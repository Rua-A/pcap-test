#Makefile
all: capture

capture.o: capture.h capture.cpp
	gcc -c -o capture.o capture.cpp

main.o: capture.h main.cpp
	gcc -c -o main.o main.cpp

capture: capture.o main.o
	gcc -o capture capture.o main.o -l pcap

clean:
	rm -f capture
	rm -f *.o
