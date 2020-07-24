
#include <stdio.h>
#include "net_cap.h"

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    char packet_data[70];
    int payload_count=0;
    if (argc != 2) {
        usage();
        return -1;
    }
    net_cap(argv[1]);
    
}
