CC	:= gcc
AR	:= ar
ODIR	:= build
SDIR	:= source
IDIRS	:= -I. -Iinclude
LDIRS	:= -L. -Llib
CFLAGS	:= $(IDIRS) -Os -std=gnu11 -ffunction-sections -fdata-sections -fno-builtin -nostartfiles -nostdlib -Wall -masm=intel -march=btver2 -mtune=btver2 -m64 -mabi=sysv -mcmodel=small -fpie
LFLAGS	:= $(LDIRS)
CFILES	:= $(wildcard $(SDIR)/*.c)
SFILES	:= $(wildcard $(SDIR)/*.s)
OBJS	:= $(patsubst $(SDIR)/%.c, build/%.o, $(CFILES)) $(patsubst $(SDIR)/%.s, build/%.o, $(SFILES))

TARGET = libKSDK.a

$(TARGET): $(ODIR) $(OBJS)
	$(AR) rcs $@ $(OBJS)

$(ODIR)/%.o: $(SDIR)/%.c
	$(CC) -c -o $@ $< $(CFLAGS) $(LFLAGS)

$(ODIR)/%.o: $(SDIR)/%.s
	$(CC) -c -o $@ $< $(CFLAGS) $(LFLAGS)

$(ODIR):
	@mkdir $@

.PHONY: clean

clean:
	rm -rf $(TARGET) $(ODIR)
