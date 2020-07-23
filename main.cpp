#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include<arpa/inet.h>
#include "net_cap.h"
#define PROMISCUOUS 1
#define NONPROMISCUOUS 0



void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    // dev : 랜 카드, 1000 : timeout(ms), 에러 메시지 저장 변수
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, PROMISCUOUS, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }
    

    pcap_loop(handle, -1,callback,NULL);

}
