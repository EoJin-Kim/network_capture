#Makefile
all: net_cap

net_cap.o: net_cap.h net_cap.cpp
	gcc -c -o net_cap.o net_cap.cpp

main.o: net_cap.h main.cpp
	gcc -c -o main.o main.cpp

net_cap: net_cap.o main.o
	gcc -o net_cap net_cap.o main.o -l pcap





clean:
	rm -f net_cap
	rm -f *.o