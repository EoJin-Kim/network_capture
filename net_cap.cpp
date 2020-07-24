#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>


int net_cap(char *interface) {

    char errbuf[PCAP_ERRBUF_SIZE];
    int payload_count=0;

    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", interface, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        printf("%u bytes captured\n", header->caplen);

        // Mac 주소
        printf("Destination Mac : %02x:%02x:%02x:%02x:%02x:%02x\n", packet[0x0],packet[0x1],packet[0x2],packet[0x3],packet[0x4],packet[0x5]);
        printf("Sourct Mac : %02x:%02x:%02x:%02x:%02x:%02x\n",packet[0x6],packet[0x7],packet[0x8],packet[0x9],packet[0xa],packet[0xb]);
        printf("\n");

        // IP 주소
        printf("Source IP : %d.%d.%d.%d\n",packet[0x1a],packet[0x1b],packet[0x1c],packet[0x1d]);
        printf("Destiantion IP : %d.%d.%d.%d\n",packet[0x1e],packet[0x1f],packet[0x20],packet[0x21]);
        printf("\n");

        // Port 주소
        uint8_t s_port[] = { packet[34], packet[35]};
        uint16_t* src_port = reinterpret_cast<uint16_t*>(s_port);
        uint16_t source_port = ntohs(*src_port);

        uint8_t d_port[] = { packet[36], packet[37]};
        uint16_t* dest_port = reinterpret_cast<uint16_t*>(d_port);

        uint16_t destination_port = ntohs(*dest_port);
        printf("Source Port : %d\n",source_port);
        printf("Destination Port : %d\n",destination_port);
        printf("\n");

        // 페이로드 16바이트
        printf("payload\n");
        while(payload_count<16)
        {
            printf("%02x ",packet[44+payload_count]);
            payload_count+=1;
        }
        payload_count=0;
        printf("\n---------------------------------\n");        

    }
    pcap_close(handle);
    return 0;
}


    // ############################################## //
    // ##################구글 참조################### //
    // ############################################## //
    // https://www.joinc.co.kr/w/Site/Network_Programing/AdvancedComm/pcap_intro#AEN14

    // /usr/include/pcap/pcap.h 들어가면 함수 및 구조체 확인 가능 #centos7 기준

    // pcap_loop() 함수 사용하면 패킷 지정한 회수만큼 탐지 가능

    // 이더넷 헤더(14 바이트)를 가져온다. 
    // ep = (struct ether_header *)packet;
    // 이더넷 DST_MAC, SRC_MAC
    //printf(" Ethernet 헤더\n");
    //printf("Destination MAC     : %x\n", ep->ether_dhost);
    //printf("Source MAC  : %x\n", ep->ether_shost);
    // 프로토콜 타입을 알아낸다. 
    // ether_type = ntohs(ep->ether_type);

    // 이더넷 헤더 크기만큼 packet주소 더하기.
    //packet += sizeof(struct ether_header);

    // IP 헤더(20 바이트) 가져온다.
    // iph = (struct ip *)packet;
    //printf("IP 패킷\n");
    //printf("Version     : %d\n", iph->ip_v);
    //printf("Header Len  : %d\n", iph->ip_hl);
    //printf("Ident       : %d\n", ntohs(iph->ip_id));
    //printf("TTL         : %d\n", iph->ip_ttl); 
    //printf("Src Address : %s\n", inet_ntoa(iph->ip_src));
    //printf("Dst Address : %s\n", inet_ntoa(iph->ip_dst));

    // IP 헤더의 Length 필드 X 4해서 packet 오프셋 이동 후 TCP 헤더 주소구한다.
    // tcph = (struct tcphdr *)(packet + iph->ip_hl * 4);
    //printf("Src Port : %d\n" , ntohs(tcph->source));
    //printf("Dst Port : %d\n" , ntohs(tcph->dest));