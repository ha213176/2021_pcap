typedef struct eth_hdr{
    u_char dst_mac[6];
    u_char src_mac[6];
    u_short eth_type;
}eth_hdr;

typedef struct ip_hdr{
    int version:4;
    int header_len:4;
    u_char tos:8;
    int total_len:16;
    int ident:16;
    int flags:16;
    u_char ttl:8;
    u_char protocal:8;
    int checksum:16;
    u_char sourceIP[4];
    u_char destIP[4];
} ip_hdr;

typedef struct ipv6{
    int version_and_other:32;
    int pld_len:16;
    int n_hdr:8;
    int hop_limit:8;
    u_char sip[16];
    u_char dip[16];
}ipv6_hdr;

typedef struct tcp_hdr{
    u_short src_port;
    u_short dest_port;
    u_int seq;
    u_int ack;
    u_char head_len;
    u_char flags;
    u_short wind_size;
    u_short checksum;
    u_short urg_ptr;
}tcp_hdr;

typedef struct udp_hdr{
    u_short src_port;
    u_short dest_port;
    u_short tot_len;
    u_short checksum;
}udp_hdr;
