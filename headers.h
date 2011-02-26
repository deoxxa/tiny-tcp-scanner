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
		unsigned char dscp;
		unsigned short int length;
		unsigned short int id;
		unsigned short int offset;
		unsigned char ttl;
		unsigned char protocol;
		unsigned short checksum;
		unsigned long int src;
		unsigned long int dst;
};

struct fs_tcphdr
{
		unsigned short int src;
		unsigned short int dst;
		unsigned long int seq_num;
		unsigned long int ack_num;
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
		unsigned short int window;
		unsigned short int checksum;
		unsigned short int urg_ptr;
};

struct fs_pseudov4hdr
{
	unsigned long int src;
	unsigned long int dst;
	unsigned char reserved;
	unsigned char protocol;
	unsigned short int length;
};
