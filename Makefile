CC = gcc
CFLAGS = -O3 -Wall -Wformat

OBJS = main.o pcap.o ja3.o util.o md5.o
HEADERS = ja3_from_pcap.h

ja3_from_pcap: $(OBJS)
	$(CC) -o $@ $(OBJS) -lpcap -lssl -lcrypto

%.o : %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY : clean
clean:
	rm -f $(OBJS) ja3_from_pcap

all: ja3_from_pcap
