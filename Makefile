# make ps4debug

TARGET = ps4debug.bin

all: clean $(TARGET)

$(TARGET):
	cd debugger && $(MAKE) -s
	cd kdebugger && $(MAKE) -s
	cd installer && $(MAKE) -s
	cp installer/installer.bin $(TARGET)
	
.PHONY: clean
clean:
	rm -f $(TARGET)
	cd installer && $(MAKE) -s clean
	cd kdebugger && $(MAKE) -s clean
	cd debugger && $(MAKE) -s clean
