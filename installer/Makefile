KSDK	:= ../ps4-ksdk/

CC		:=	gcc
AS		:=	gcc
OBJCOPY	:=	objcopy
ODIR	:=	build
SDIR	:=	source
IDIRS	:=	-I$(KSDK)/include -I. -Iinclude
LDIRS	:=	-L$(KSDK) -L. -Llib
MAPFILE := $(shell basename $(CURDIR)).map
CFLAGS	:=	$(IDIRS) -Os -std=gnu11 -ffunction-sections -fdata-sections -fno-builtin -nostartfiles -nostdlib -Wall -masm=intel -march=btver2 -mtune=btver2 -m64 -mabi=sysv -mcmodel=small -fpie
SFLAGS	:=	-nostartfiles -nostdlib -march=btver2 -mtune=btver2
LFLAGS	:=	$(LDIRS) -Xlinker -T linker.x -Wl,--build-id=none -Wl,--gc-sections
CFILES	:=	$(wildcard $(SDIR)/*.c)
SFILES	:=	$(wildcard $(SDIR)/*.s)
OBJS	:=	$(patsubst $(SDIR)/%.c, $(ODIR)/%.o, $(CFILES)) $(patsubst $(SDIR)/%.s, $(ODIR)/%.o, $(SFILES))

LIBS	:= -lKSDK

TARGET = installer.bin

$(TARGET): $(ODIR) $(OBJS)
	$(CC) crt0.s $(ODIR)/*.o -o temp.t $(CFLAGS) $(LFLAGS) $(LIBS)
	$(OBJCOPY) -O binary temp.t $(TARGET)
	rm -f temp.t

$(ODIR)/%.o: $(SDIR)/%.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR)/%.o: $(SDIR)/%.s
	$(AS) -c -o $@ $< $(SFLAGS)

$(ODIR):
	@mkdir $@

.PHONY: clean

clean:
	rm -f $(TARGET) $(ODIR)/*.o
