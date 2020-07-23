#Makefile
all: net_test

net_test: net_cap.o main.o
	g++ -o net_test net_cap.o main.o -lpcap

main.o: net_cap.h main.cpp
	gcc -c -o main.o main.cpp

net_cap.o: net_cap.h net_cap.cpp
	gcc -c -o net_cap.o net_cap.cpp

clean:
	rm -f net_test
	rm -f *.o
