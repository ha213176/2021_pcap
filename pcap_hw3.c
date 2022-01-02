#include<stdio.h>
#include<string.h>
#include<pcap/pcap.h>
#include<stdlib.h>
#include<unistd.h>
#include<time.h>
#include"hdr.h"

eth_hdr *ethernet = NULL;
ip_hdr *ip = NULL;
ipv6_hdr *ipv6 = NULL;
tcp_hdr *tcp = NULL;
udp_hdr *udp = NULL;

int main(int argc, char **argv){
    if(argc != 2){
        printf("Error argument: ./pcap_hw3 [file].pcap\n");
        exit(1);
    }
    char *dev, errbuf[PCAP_ERRBUF_SIZE];

    char *fname = argv[1];


    pcap_t *handle = pcap_open_offline(fname, errbuf);
    if(!handle){
        fprintf(stderr,"pcap_open_offline(): %s\n", errbuf);
        exit(1);
    }
    
    printf("Open: %s\n", fname);

    const u_char *packet = NULL;
    struct pcap_pkthdr header;
    struct tm *timeinfo;
    char buf[128] ={0};
    time_t t;
    u_int eth_len=sizeof(eth_hdr);
    u_int ip_len=sizeof(ip_hdr);
    

    while(1){
        packet = pcap_next(handle, &header);
        if(packet == NULL) break;
        // time
        t = header.ts.tv_sec;
        timeinfo = localtime(&t);
        strftime(buf,128, "%Y-%m-%d %H:%M:%S", timeinfo);
        printf("%s\t", buf);

        ethernet = (eth_hdr *)packet;
        printf("src_mac: %02x-%02x-%02x-%02x-%02x-%02x ", 
        ethernet->src_mac[0],ethernet->src_mac[1],ethernet->src_mac[2],
        ethernet->src_mac[3],ethernet->src_mac[4],ethernet->src_mac[5]);

        printf("dst_mac: %02x-%02x-%02x-%02x-%02x-%02x ", 
        ethernet->dst_mac[0],ethernet->dst_mac[1],ethernet->dst_mac[2],
        ethernet->dst_mac[3],ethernet->dst_mac[4],ethernet->dst_mac[5]);

        printf("eth_type: 0x%04x\t", ntohs(ethernet->eth_type));

        if(ntohs(ethernet->eth_type) == 0x800){
            ip = (ip_hdr*)(packet+eth_len);
            printf("Sip: %d.%d.%d.%d ", ip->sourceIP[0],ip->sourceIP[1],ip->sourceIP[2],ip->sourceIP[3]);
            printf("Dip: %d.%d.%d.%d\t", ip->destIP[0],ip->destIP[1],ip->destIP[2],ip->destIP[3]);
        
            if(ip->protocal == 6){
                tcp = (tcp_hdr*)(packet+eth_len+ip_len);
                printf("Sport:%u ", ntohs(tcp->src_port));
                printf("Dport:%u\t", ntohs(tcp->dest_port));
            }
            else if(ip->protocal == 17){
                udp = (udp_hdr *)(packet+eth_len+ip_len);
                printf("Sport:%u ", ntohs(udp->src_port));
                printf("Dport:%u\t", ntohs(udp->dest_port));
            }
        
        }
        else if(ntohs(ethernet->eth_type) == 0x86dd){
            ipv6 = (ipv6_hdr*)(packet+eth_len);
            printf("Sip: ");
            for(int i = 0; i < 7; i++){
                printf("%.2x%.2x:",ipv6->sip[i*2],ipv6->sip[i*2+1]);
            }
            printf("%.2x%.2x ",ipv6->sip[14], ipv6->sip[15]);
            printf("Dip: ");
            for(int i = 0; i < 7; i++){
                printf("%.2x%.2x:",ipv6->dip[i*2],ipv6->dip[i*2+1]);
            }
            printf("%.2x%.2x ",ipv6->dip[14], ipv6->dip[15]);
        }
        printf("\n\n");
    }
    pcap_close(handle);
    return 0;
}