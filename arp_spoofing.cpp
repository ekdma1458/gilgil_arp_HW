#include "arp_spoofing.h"
//3,232,235,520
u_int32_t splitIP(char* ip){
    u_int32_t split_ip = 0;
    u_int8_t i = 24;
    char* ptr = nullptr;
    ptr = strtok(ip,".");
    split_ip = atoi(ptr) << i;
    while(ptr != nullptr){
        i = i - 8;
        ptr = strtok(nullptr,".");
        split_ip = split_ip | (atoi(ptr) << i);
        if(i == 0) break;
    };
    return split_ip;
}/*
void makeArpPacket(u_char* packet, u_char* mac, u_int32_t sendIp, u_int32_t targetIp){

    packet[0] = 0xff;
    packet[1] = 0xff;
    packet[2] = 0xff;
    packet[3] = 0xff;
    packet[4] = 0xff;
    packet[5] = 0xff;

    packet[6]  = mac[0];
    packet[7]  = mac[1];
    packet[8]  = mac[2];
    packet[9]  = mac[3];
    packet[10] = mac[4];
    packet[11] = mac[5];
    packet[12] = 0x08;
    packet[13] = 0x06;

    packet[14] = 0x01;
    packet[15] = 0x08;
    packet[16] = 0x00;
    packet[17] = 0x06;
    packet[18] = 0x04;
    packet[19] = 0x01;

    packet[20] = (sendIp & 0xff000000) >> 24;
    packet[21] = (sendIp & 0x00ff0000) >> 16;
    packet[22] = (sendIp & 0x0000ff00) >> 8;
    packet[23] = (sendIp & 0x000000ff);

    packet[24] = 0x00;
    packet[25] = 0x00;
    packet[26] = 0x00;
    packet[27] = 0x00;
    packet[28] = 0x00;
    packet[29] = 0x00;

    packet[30] = (targetIp & 0xff000000) >> 24;
    packet[31] = (targetIp & 0x00ff0000) >> 16;
    packet[32] = (targetIp & 0x0000ff00) >> 8;
    packet[33] = (targetIp & 0x000000ff);

}*/
void packetInsert(u_char* packet, je_arp_header** arp_header){
    *arp_header = reinterpret_cast<je_arp_header*>(packet);
    (*arp_header)->eth_hdr.ether_type =  ntohs((*arp_header)->eth_hdr.ether_type);
    (*arp_header)->arp_hdr.ar_hrd = ntohs((*arp_header)->arp_hdr.ar_hrd);
    (*arp_header)->arp_hdr.ar_pro = ntohs((*arp_header)->arp_hdr.ar_pro);
    (*arp_header)->arp_hdr.ar_op = ntohs((*arp_header)->arp_hdr.ar_op);
    (*arp_header)->sender_ip_addr.s_addr = ntohl((*arp_header)->sender_ip_addr.s_addr);
    (*arp_header)->target_ip_addr.s_addr = ntohl((*arp_header)->target_ip_addr.s_addr);
}
void printfJeArpInfo(je_arp_header* arp_header){
    printf("D_Mac  ");
    for (int i = 0; i < 5; i++) {
        printf("%02x:", arp_header->eth_hdr.ether_dhost[i]);
        if(i==4){
            printf("%02x\r\n", arp_header->eth_hdr.ether_dhost[i+1]);
            break;
        }
    }
    printf("S_Mac  ");
    for (int i = 0; i < 5; i++) {
        printf("%02x:", arp_header->eth_hdr.ether_shost[i]);
        if(i==4){
            printf("%02x\r\n", arp_header->eth_hdr.ether_shost[i+1]);
            break;
        }
    }
    printf("ETH_TYPE %x\r\n", arp_header->eth_hdr.ether_type);
    printf("HW_TYPE %x\r\n", arp_header->arp_hdr.ar_hrd);
    printf("PRO_TYPE %x\r\n", arp_header->arp_hdr.ar_pro);
    printf("HW_SIZE %x\r\n", arp_header->arp_hdr.ar_hln);
    printf("PRO_SIZE %x\r\n", arp_header->arp_hdr.ar_pln);
    printf("PRO_TYPE %x\r\n", arp_header->arp_hdr.ar_op);

    printf("Send_Mac  ");
    for (int i = 0; i < 5; i++) {
        printf("%02x:", arp_header->sender_mac[i]);
        if(i==4){
            printf("%02x\r\n", arp_header->sender_mac[i+1]);
            break;
        }
    }
    printf("Sender : %d.%d.%d.%d \r\n", (arp_header->sender_ip_addr.s_addr & 0xff000000) >> 24  , (arp_header->sender_ip_addr.s_addr & 0x00ff0000) >> 16 , (arp_header->sender_ip_addr.s_addr & 0x0000ff00) >> 8 , arp_header->sender_ip_addr.s_addr & 0x000000ff);
    printf("target_Mac  ");
    for (int i = 0; i < 5; i++) {
        printf("%02x:", arp_header->target_mac[i]);
        if(i==4){
            printf("%02x\r\n", arp_header->target_mac[i+1]);
            break;
        }
    }
    printf("Target : %d.%d.%d.%d\r\n", (arp_header->target_ip_addr.s_addr & 0xff000000) >> 24  , (arp_header->target_ip_addr.s_addr & 0x00ff0000) >> 16 , (arp_header->target_ip_addr.s_addr & 0x0000ff00) >> 8 , arp_header->target_ip_addr.s_addr & 0x000000ff);

}
void printfPacket(const u_char* packet, u_int lenght ){
    for (int i = 0 ; i < lenght; i++) {
        printf("%02x ",packet[i]);
        if( (i + 1) % 16 == 0){
            printf("\r\n");
        }
    }
    printf("\r\n");
}
