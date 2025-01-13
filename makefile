LDLIBS += -lpcap

all: airodump-hw

airodump: airodump-hw.c

clean:
	rm -f airodump-hw *.o