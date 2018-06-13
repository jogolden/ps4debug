LIBPS4	:=	ps4-payload-sdk/libPS4

CC	:= gcc
AR	:= ar
CFLAGS	:= -I$(LIBPS4)/include -I. -Os -std=gnu11 -ffunction-sections -fdata-sections -fno-builtin -nostartfiles -nostdlib -Wall -masm=intel -march=btver2 -mtune=btver2 -m64 -mabi=sysv -mcmodel=small -fpie
CFILES	:= $(wildcard *.c)
SFILES	:= $(wildcard *.s)
OBJS	:= $(patsubst %.c, %.o, $(CFILES)) $(patsubst %.s, %.o, $(SFILES))

TARGET = $(shell basename $(CURDIR)).a

$(TARGET): $(OBJS)
	$(AR) rcs $@ $(OBJS)

%.o: %.c
	$(CC) -c -o $@ $< -L$(LIBPS4) -L. $(CFLAGS)

%.o: %.s
	$(CC) -c -o $@ $< -L$(LIBPS4) -L. $(CFLAGS)

.PHONY: clean

clean:
	rm -rf $(TARGET) $(ODIR)
