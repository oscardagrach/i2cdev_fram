#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define FRAM_SIZE 0x8000

#define PRINT_DATA(a, b, c) \
if(a) { \
printf("%s\n", a); \
} \
printf("        00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"); \
printf("        - - - - - - - - - - - - - - - - - - - - - - - -\n"); \
printf("0x0000: "); \
   for(int i=0; i<c; i++) { \
    if(i && !(i%16)) \
    printf("\n0x%04hX: ", i); \
    printf("%02X ", *(b+i)); \
   } \
   printf("\n");

enum boundary {
	ADDR_CHECK = 1,
	DATA_CHECK,
	BOTH_CHECK
};

static const char *device = "/dev/i2c-1";
static int slave_addr = 0x50;

static int check_boundary(uint8_t type, uint16_t addr, uint16_t len)
{
	switch(type)
	{
		case 1:
			if (addr > 0x8000)
			{
				printf("[-] Address out of bounds\n");
				return 1;
			}
			break;
		case 2:
			if (addr+len > 0x8000)
			{
				printf("[-] Data out of bounds\n");
				return 1;
			}
			break;
		case 3:
			if (addr > 0x8000)
			{
				printf("[-] Address out of bounds\n");
				return 1;
			}
			if (addr+len > 0x8000)
			{
				printf("[-] Data out of bounds\n");
				return 1;
			}
			break;
		default:
			return 1;
	}
	return 0;
}

static int erase(int fd)
{
	uint8_t buf[8192] = {0};
	uint16_t addr = 0;

	for (int i=0; i<4; i++) {
		if (write(fd, buf, 8192) != 8192) {
			printf("Failed to erase chip\n");
			return -1;
		}
		addr += 8190;
		buf[0] = addr >> 8;
		buf[1] = addr;
		if (i==3) {
			write(fd, buf, 10);
		}
	}
	return 0;
}

static int read_image(int fd, char *file)
{
	FILE *outf = NULL;
	uint8_t addr[2] = {0};
	uint8_t *data = NULL;

	data = (uint8_t *)malloc(sizeof(uint8_t)*FRAM_SIZE);
	if (!data) {
		printf("Failed to allocate buffer\n");
		return -1;
	}

	/* set FRAM address */
	if (write(fd, addr, 2) != 2) {
		printf("Failed to set FRAM address\n");
		return -1;
	}

	for (int i=0; i<4; i++) {
		read(fd, data+(i*8192), 8192);
	}

	outf = fopen(file, "wb");
	if (!outf) {
		printf("Error opening file for write\n");
		return -1;
	}

	if (!fwrite(data, 1, FRAM_SIZE, outf)) {
		printf("Failed to write file %s\n", file);
		fclose(outf);
		return -1;
	}

	fsync(fileno(outf));
	fclose(outf);
	printf("Read image to %s\n", file);
	return 0;
}	

static int write_image(int fd, char *file)
{
	FILE *inf = NULL;
	uint8_t *data = NULL;
	uint16_t addr, size, result = 0;
	uint32_t count = 0;

	/* erase the chip prior to writing an image */
	printf("Erasing chip...\n");
	erase(fd);

	inf = fopen(file, "rb");
	if (!inf) {
		printf("Error opening file %s\n", file);
		return 1;
	}

	/* measure the image file size */
	fseek(inf, 0, SEEK_END);
	size = ftell(inf);
	rewind(inf);

	if (check_boundary(DATA_CHECK, 0x0, size)) {
		fclose(inf);
		return -1;
	}

	/* size+2 for address bytes */
	data = (uint8_t *)malloc(sizeof(uint8_t)*(size+2));
	if (!data) {
		printf("Failed to allocate buffer\n");
		fclose(inf);
		return -1;
	}

	/* starting reading past the address bytes */
	result = fread((data+2), 1, size, inf);
	if (result != size) {
		printf("Failed to read file %s\n", file);
		fclose(inf);
		return -1;
	}

	fclose(inf);

	printf("Writing %d bytes\n", size);

	count = size;

	/* ensure FRAM address is set to 0x0 */
	addr = 0;
	addr += addr >> 8;
	addr += addr;

	if (count <= 8190) {
		if (write(fd, data, size+2) != size+2) {
			printf("Failed to write image\n");
			return 1;
		}
	}

	/* This is ugly and weird because I have to work around the */
	/* i2c-dev kernel driver limitation of 8192 byte writes, of */
	/* which two bytes are dedicated to setting the FRAM address */
	/* It works fine and allows the largest chunks to be written */
	else {
		do {
			if (count >= 8190) {
				if (write(fd, data+addr, 8192) != 8192 ) {
					printf("Failed to write image\n");
					return -1;
				}
				addr += 8188;
				count -= 8190;
				data[addr] = addr >> 8;
				data[addr+1] = addr;
			}
			else {
				count += 8;
				data[addr] = addr >> 8;
				data[addr+1] = addr;
				if (write(fd, data+addr, count+2) != count+2) {
					printf("Failed to write image\n");
					return 1;
				}
				count -= count;
			}
		} while (count != 0);
	}

	printf("Done\n");
	return 0;
}

static int dump(int fd)
{
	uint32_t rounds = 0;
	uint8_t addr[2] = {0};
	uint8_t buf[FRAM_SIZE] = {0};

	/* set FRAM address to 0x0 */
	write(fd, addr, 2);

	/* i2c-dev kernel driver 8192 byte limitation */
	rounds = FRAM_SIZE/8192;
	for (int i=0; i<rounds; i++) {
		if (read(fd, buf+(i*8192), 8192) != 8192) {
			printf("Failed to dump chip\n");
			return -1;
		}
	}

	PRINT_DATA("Dumping...", buf, sizeof(buf));
	return 0;
}

static int read_byte(int fd, uint16_t addr)
{
	uint8_t buf[3] = {0};

	if ((check_boundary(ADDR_CHECK, addr, 0x0)) > 0) {
		return -1;
	}

	/* set FRAM address to read */
	buf[0] = addr >> 8;
	buf[1] = addr;

	if (write(fd, buf, 2) < 0) {
		printf("Failed to set FRAM address\n");
		return -1;
	}

	if (read(fd, &buf[2], 1) < 0) {
		printf("Failed to read byte\n");
		return -1;
	}

	printf("Read 0x%hhX: %02hX\n", addr, buf[2]);
	return 0;
}

static int write_byte(int fd, uint16_t addr, uint8_t data)
{
	uint8_t buf[3] = {0};

	if ((check_boundary(ADDR_CHECK, addr, 0x0)) > 0) {
		return -1;
	}

	/* set FRAM address/data to write */
	buf[0] = addr >> 8;
	buf[1] = addr;
	buf[2] = data;

	if (write(fd, buf, 3) < 0) {
		printf("Failed to write byte\n");
		return -1;
	}

	/* verify written byte */
	if (write(fd, buf, 2) < 0) {
		printf("Failed to set verify address\n");
		return -1;
	}

	buf[2] = 0;

	if (read(fd, &buf[2], 1) < 0) {
		printf("Failed to read written byte\n");
		return -1;
	}

	if (buf[2] != data) {
		printf("Failed to verify write\n");
		return -1;
	}

	printf("Wrote %02hhX to 0x%hX\n", data, addr);
	return 0;
}

int main(int argc, char *argv[])
{
	int fd = 0;
	uint8_t data = 0;
	uint16_t addr = 0;
	char file[40] = {0};

	/* initialize i2c bus/device */
	if ((fd = open(device, O_RDWR)) < 0) {
		printf("Failed to open I2C bus\n");
		return -1;
	}

	if (ioctl(fd, I2C_SLAVE, slave_addr) < 0) {
		close(fd);
		printf("Failed to access I2C bus\n");
		return -1;
	}

	if (argc < 2) {
		printf("I2C FRAM Utility\n");
		printf("By oscardagrach\n\n");
		printf("read [addr]\n");
		printf("write [addr] [data]\n");
		printf("read_image [file]\n");
		printf("write_image [file]\n");
		printf("erase\n");
		return 1;
	}

	if (strcmp("read", argv[1]) == 0) {
		if (argc != 3) {
			printf("read [addr]\n");
			return 1;
		}
		sscanf(argv[2], "%hx", &addr);
		read_byte(fd, addr);
	}

	else if (strcmp("write", argv[1]) == 0) {
		if (argc != 4) {
			printf("write [addr] [data]\n");
			return 1;
		}
		sscanf(argv[2], "%hx", &addr);
		sscanf(argv[3], "%hhx", &data);
		write_byte(fd, addr, data);
	}

	else if (strcmp("erase", argv[1]) == 0) {
		if (argc != 2) {
			printf("erase\n");
			return 1;
		}
		erase(fd);
	}

	else if (strcmp("dump", argv[1]) == 0) {
		if (argc != 2) {
			printf("dump\n");
			return 1;
		}
		dump(fd);
	}

	else if (strcmp("write_image", argv[1]) == 0) {
		if (argc != 3) {
			printf("write_image [file]\n");
			return 1;
		}
		sscanf(argv[2], "%s", file);
		write_image(fd, file);
	}

	else if (strcmp("read_image", argv[1]) == 0) {
		if (argc != 3) {
			printf("read_image [file]\n");
			return 1;
		}
		sscanf(argv[2], "%s", file);
		read_image(fd, file);
	}

	else {
		printf("Unrecognized command\n");
		close(fd);
		return 1;
	}

	close(fd);
	return 0;
}
