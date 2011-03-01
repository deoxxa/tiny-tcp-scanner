#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <unistd.h>

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
  char        errbuf[PCAP_ERRBUF_SIZE];
  char*       interface_dev = NULL;
  bpf_u_int32 interface_mask;
  bpf_u_int32 interface_net;
  char*       filter_str = NULL;

  int c;
  while ((c = getopt(argc, argv, "i:f:h")) != -1)
  {
    switch (c)
    {
    case 'h':
      fprintf(stderr, "Usage: %s [-i interface] [-f filter string]\n", argv[0]);
      exit(0);
    case 'i':
      interface_dev = optarg;
      break;
    case 'f':
      filter_str = optarg;
      break;
    }
  }

  fprintf(stderr, "[+] packets-recv startup:\n");

  if (interface_dev == NULL)
  {
    fprintf(stderr, "[!] Source interface not specified, trying to autodetect...\n");
    interface_dev = pcap_lookupdev(errbuf);
    if (interface_dev == NULL)
    {
      fprintf(stderr, "[-] Couldn't get an interface: %s\n", errbuf);
      exit(-1);
    }
    fprintf(stderr, "[+] Using %s\n", interface_dev);
  }

  if (pcap_lookupnet(interface_dev, &interface_net, &interface_mask, errbuf) == -1)
  {
    fprintf(stderr, "[-] Couldn't get network details: %s\n", errbuf);
    exit(-1);
  }

  pcap_t* pcaph = pcap_open_live(interface_dev, BUFSIZ, 1, -1, errbuf);
  if (pcaph == NULL)
  {
    fprintf(stderr, "[-] Couldn't open interface: %s\n", errbuf);
    exit(-2);
  }

  if (filter_str != NULL)
  {
    struct bpf_program fp;
    if (pcap_compile(pcaph, &fp, filter_str, 0, interface_net) == -1)
    {
      fprintf(stderr, "[-] Couldn't compile filter string: %s\n", pcap_geterr(pcaph));
      exit(-3);
    }

    if (pcap_setfilter(pcaph, &fp) == -1)
    {
      fprintf(stderr, "[-] Couldn't apply filter: %s\n", pcap_geterr(pcaph));
      exit(-4);
    }
  }
  else
  {
    filter_str = "none";
  }

  fprintf(stderr, "[+] Device: %s\n", interface_dev);
  fprintf(stderr, "[+] Filter: %s\n", filter_str);

  pcap_loop(pcaph, 0, &print_packet, (u_char*)NULL);

  return 0;
}
