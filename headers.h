#pragma pack(2)

struct fs_ethhdr
{
  unsigned char dst[6];
  unsigned char src[6];
  unsigned short int type:16;
};

struct fs_ipv4hdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int header_length:4;
    unsigned int version:4;
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int header_length:4;
#endif
    unsigned char dscp:8;
    unsigned short int length:16;
    unsigned short int id:16;
    unsigned short int offset:16;
    unsigned char ttl:8;
    unsigned char protocol:8;
    unsigned short checksum:16;
    unsigned long int src:32;
    unsigned long int dst:32;
};

struct fs_tcphdr
{
    unsigned short int src:16;
    unsigned short int dst:16;
    unsigned long int seq_num:32;
    unsigned long int ack_num:32;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned short int reserved:4;
    unsigned short int offset:4;  
    unsigned short int flag_fin:1;
    unsigned short int flag_syn:1;
    unsigned short int flag_rst:1;
    unsigned short int flag_psh:1;
    unsigned short int flag_ack:1;
    unsigned short int flag_urg:1;
    unsigned short int flag_ece:1;
    unsigned short int flag_cwr:1;
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned short int offset:4;
    unsigned short int reserved:4;
    unsigned short int flag_cwr:1;
    unsigned short int flag_ece:1;
    unsigned short int flag_urg:1;
    unsigned short int flag_ack:1;
    unsigned short int flag_psh:1;
    unsigned short int flag_rst:1;
    unsigned short int flag_syn:1;
    unsigned short int flag_fin:1;
#endif
    unsigned short int window:16;
    unsigned short int checksum:16;
    unsigned short int urg_ptr:16;
};

struct fs_pseudov4hdr
{
  unsigned long int src:32;
  unsigned long int dst:32;
  unsigned char reserved:8;
  unsigned char protocol:8;
  unsigned short int length:16;
};
