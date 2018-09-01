KSDK := ../ps4-ksdk/

LFILE = ./kdebugger.x

CC		:=	gcc
AS		:=	gcc
OBJCOPY	:=	objcopy
ODIR	:=	build
SDIR	:=	source
IDIRS	:=	-I$(KSDK)/include -I. -Iinclude
LDIRS	:=	-L$(KSDK) -L. -Llib
CFLAGS	:=	$(IDIRS) -O3 -std=gnu11 -fno-builtin -fno-exceptions -fno-asynchronous-unwind-tables -nostartfiles -nostdlib -Wall -masm=intel -march=btver2 -mtune=btver2 -m64 -mabi=sysv -mcmodel=small -fPIE
SFLAGS	:=	-nostartfiles -nostdlib -masm=intel -march=btver2 -mtune=btver2 -m64 -mabi=sysv -mcmodel=small
LFLAGS	:=	$(LDIRS) -Xlinker -T $(LFILE) -Wl,--build-id=none -pie
CFILES	:=	$(wildcard $(SDIR)/*.c)
SFILES	:=	$(wildcard $(SDIR)/*.s)
OBJS	:=	$(patsubst $(SDIR)/%.c, $(ODIR)/%.o, $(CFILES)) $(patsubst $(SDIR)/%.s, $(ODIR)/%.o, $(SFILES))

LIBS	:= -lKSDK

TARGET = kdebugger.elf

$(TARGET): $(ODIR) $(OBJS)
	$(CC) crt0.s $(ODIR)/*.o -o $(TARGET) $(CFLAGS) $(LFLAGS) $(LIBS)
	elfedit --output-type=DYN $(TARGET)
	strip $(TARGET)

$(ODIR)/%.o: $(SDIR)/%.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR)/%.o: $(SDIR)/%.s
	$(AS) -c -o $@ $< $(SFLAGS)

$(ODIR):
	@mkdir $@

.PHONY: clean

clean:
	rm -f $(TARGET) $(ODIR)/*.o