LDLIBS += -lpcap -lncurses

all: airodump-hw

airodump: airodump-hw.cpp

clean:
	rm -f airodump-hw *.o
