#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

#include <pcap.h>

#include "headers.h"

void print_packet(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
  struct fs_ethhdr*  eth;
  struct fs_ipv4hdr* ip;
  struct fs_tcphdr*  tcp;

  eth = (struct fs_ethhdr* )(packet);
  ip  = (struct fs_ipv4hdr*)(packet + 14);
  tcp = (struct fs_tcphdr* )(packet + 14 + sizeof(struct fs_ipv4hdr));

  unsigned long  int ip_src  = htonl(ip->src);
  unsigned short int tcp_src = htons(tcp->src);

  printf("%lu.%lu.%lu.%lu:%d\n", ((ip_src & 0xFF000000) >> 24), ((ip_src & 0x00FF0000) >> 16), ((ip_src & 0x0000FF00) >> 8), ((ip_src & 0x000000FF) >> 0), tcp_src);
}

int main(int argc, char** argv)
{ 
  if (argc < 3)
  {
    fprintf(stderr, "Usage: %s interface ip\n", argv[0]);
    exit(0);
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  char* dev = argv[1];
  char* ip = argv[2];

  bpf_u_int32 maskp;
  bpf_u_int32 netp;
  if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1)
  {
    fprintf(stderr, "Error (pcap_lookup): %s\n", errbuf);
    exit(-1);
  }

  pcap_t* descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
  if (descr == NULL)
  {
    fprintf(stderr, "Error (pcap_open_live): %s\n", errbuf);
    exit(-2);
  }

  char filter[1024];
  sprintf(filter, "dst host %s", ip);

  struct bpf_program fp;
  if (pcap_compile(descr, &fp, filter, 0, netp) == -1)
  {
    fprintf(stderr, "Error: (pcap_compile): %s\n", pcap_geterr(descr));
    exit(-3);
  }

  if (pcap_setfilter(descr, &fp) == -1)
  {
    fprintf(stderr, "Error: (pcap_setfilter): %s\n", pcap_geterr(descr));
    exit(-4);
  }

  u_char* args = NULL;
  pcap_loop(descr, atoi(argv[1]), &print_packet, args);

  return 0;
}
