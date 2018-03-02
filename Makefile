CC := gcc
CFLAGS := -O2 -g -Wall
INCLUDES = -I ./

all:
	$(CC) $(CFLAGS) $(INCLUDES) fram.c -o fram

clean:
	rm fram

