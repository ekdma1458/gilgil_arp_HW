#pragma once

#include <libnet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <string.h>
#include <pthread.h>

#pragma pack(1)
struct je_arp_header{
    struct libnet_ethernet_hdr eth_hdr;
    struct libnet_arp_hdr arp_hdr;
    uint8_t sender_mac[ETHER_ADDR_LEN];
    struct in_addr sender_ip_addr;
    uint8_t target_mac[ETHER_ADDR_LEN];
    struct in_addr target_ip_addr;
};

u_int32_t splitIP(char* ip);
void setSplitIP(char* ip, u_char* packet);
void makeArpPacket(u_char* packet, u_char* mac, u_int32_t sendIp, u_int32_t targetIp);
void printfPacket(const u_char* packet, u_int lenght);
void packetInsert(u_char* packet, je_arp_header** arp_header);
void printfJeArpInfo(je_arp_header* arp_header);
