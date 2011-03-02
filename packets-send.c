#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <math.h>

#include <pcap.h>

#include "headers.h"

#ifdef _DEBUG
void dump(unsigned char* data, int len)
{
  int i;
  for (i=0;i<len;i++)
  {
    if ((i % 16) == 0) { fprintf(stderr, "    0x%04x:  ", i); }
    fprintf(stderr, "%02x", *data++);
    if (((i+1) % 2) == 0) { fprintf(stderr, " "); }
    if (((i+1) % 16) == 0) { fprintf(stderr, "\n"); }
  }

  fprintf(stderr, "\n");
}
#endif

char* fs_inet_ntop(unsigned long int ip, char* ip_str)
{
  ip = ntohl(ip);
  sprintf(ip_str, "%lu.%lu.%lu.%lu", ((ip & 0xFF000000) >> 24), ((ip & 0x00FF0000) >> 16), ((ip & 0x0000FF00) >> 8), ((ip & 0x000000FF) >> 0));
  return ip_str;
}

unsigned short checksum(unsigned short* ptr, int len)
{
  register int sum = 0;

  for (;len>1;len-=2)
    sum += *ptr++;

  if (len == 1)
    sum += *(unsigned char*)ptr;

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  return (unsigned short)(~sum);
}

int sendpacket(unsigned char* buf, int s, unsigned long int src_ip, unsigned int src_port, unsigned long int dst_ip, int dst_port)
{
  memset(buf, 0, sizeof(struct fs_ipv4hdr)+sizeof(struct fs_tcphdr));

  struct fs_ipv4hdr* ip  = (struct fs_ipv4hdr*) buf;
  struct fs_tcphdr* tcp = (struct fs_tcphdr*) (buf + sizeof(struct fs_ipv4hdr));
  struct fs_pseudov4hdr* pseudo = (struct fs_pseudov4hdr*) (buf + sizeof(struct fs_ipv4hdr) - sizeof(struct fs_pseudov4hdr));
  struct sockaddr_in sin, din;

  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = src_ip;
  sin.sin_port = htons(src_port);

  din.sin_family = AF_INET;
  din.sin_addr.s_addr = dst_ip;
  din.sin_port = htons(dst_port);

  pseudo->src = src_ip;
  pseudo->dst = dst_ip;
  pseudo->protocol = 6;
  pseudo->length = htons(sizeof(struct fs_tcphdr));

  tcp->src = htons(src_port);
  tcp->dst = htons(dst_port);
  tcp->seq_num = 1;
  tcp->ack_num = 0;
  tcp->offset = 5;
  tcp->flag_syn = 1;
  tcp->checksum = checksum((unsigned short int*)pseudo, sizeof(struct fs_pseudov4hdr)+sizeof(struct fs_tcphdr));

  ip->version = 4;
  ip->header_length = 5;
  ip->dscp = 0;
  ip->length = sizeof(struct fs_ipv4hdr) + sizeof(struct fs_tcphdr);
  ip->id = 0;
  ip->offset = 0;
  ip->ttl = 64;
  ip->protocol = 6;
  ip->src = src_ip;
  ip->dst = dst_ip;
  ip->checksum = checksum((unsigned short int*)ip, (sizeof(struct fs_ipv4hdr) + sizeof(struct fs_tcphdr)));

#ifdef _DEBUG
  fprintf(stderr, "[+] Packet:\n");
  dump(buf, sizeof(struct fs_ipv4hdr)+sizeof(struct fs_tcphdr));

  fprintf(stderr, "[+] IP sum: 0x%04x\n", ip->checksum);
  fprintf(stderr, "[+] IP Portion:\n");
  dump(buf, sizeof(struct fs_ipv4hdr));

  fprintf(stderr, "[+] TCP sum: 0x%04x\n", tcp->checksum);
  fprintf(stderr, "[+] TCP Portion:\n");
  dump((buf+sizeof(struct fs_ipv4hdr)), sizeof(struct fs_tcphdr));
#endif

  if (sendto(s, buf, ip->length, 0, (struct sockaddr*)&din, sizeof(struct sockaddr_in)) < 0)
  {
    char ip_str[INET_ADDRSTRLEN];
    fprintf(stderr, "[-] Could not send packet to %d: [%d] %s\n", s, errno, strerror(errno));
    fprintf(stderr, "  |- Arguments were: %d, %p, %d, 0, %p, %d\n", s, buf, ip->length, &din, sizeof(struct sockaddr_in));
    fprintf(stderr, "  `- Remote address was: %s:%d\n", fs_inet_ntop(dst_ip, ip_str), dst_port);
    return -1;
  }

  return 0;
}

int make_raw_socket(char* src_interface)
{
  int s = 0;
  int y = 1;

  if ((s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
  {
    fprintf(stderr, "[-] Could not create socket descriptor: [%d] %s\n", errno, strerror(errno));
    return -1;
  }
  else
  {
    fprintf(stderr, "[+] Socket descriptor created: %d\n", s);
  }

  if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &y, sizeof(y)) < 0)
  {
    fprintf(stderr, "[-] Could not set socket option IPPROTO_IP/IP_HDRINCL: [%d] %s\n", errno, strerror(errno));
    return -2;
  }
  else
  {
    fprintf(stderr, "[+] Socket option IPPROTO_IP/IP_HDRINCL set successfully\n");
  }

  if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, src_interface, strlen(src_interface)) < 0)
  {
    fprintf(stderr, "[-] Could not set socket option SOL_SOCKET/SO_BINDTODEVICE: [%d] %s\n", errno, strerror(errno));
    return -3;
  }
  else
  {
    fprintf(stderr, "[+] Socket option SOL_SOCKET/SO_BINDTODEVICE set successfully\n");
  }

  return s;
}

void send_packets(char* src_interface, unsigned long int src_ip, unsigned int src_port, float tpps, short int pnum, short int* pptr)
{
  // init memory used for packet construction
  unsigned char buf [sizeof(struct fs_ipv4hdr) + sizeof(struct fs_tcphdr)];

  // initialise socket
  int sd = make_raw_socket(src_interface);

  // work out how long the initial sleep time is to be (this will be adjusted later)
  struct timespec sleep_req;
  struct timespec sleep_rem;
  sleep_req.tv_sec = floor(1.0f/tpps);
  sleep_req.tv_nsec = (((1.0f/tpps) - floor(1.0f/tpps))*1000000000);
  sleep_rem.tv_sec = 0;
  sleep_rem.tv_nsec = 0;

  int p=0,packets=0,packets_last=0;
  float opps=0,cpps=0,rpps=0;
  time_t time_last = time(NULL);

  fprintf(stderr, "[+] Sending packets...\n");

  char              ip_char[17];
  unsigned long int ip_int;
  while (fgets(ip_char, 17, stdin))
  {
    ip_int = inet_addr(ip_char);

    if ((htonl(ip_int) & 0x000000FF) == 0 || ((htonl(ip_int) & 0xFF000000) >> 24) == 0)
      continue;

    // cycle through ports
    for (p=0;p<pnum;++p)
    {
      sendpacket(buf, sd, src_ip, src_port, ip_int, pptr[p]);
      // send packet
      if (!sd)
      {
        // try to close the socket if necessary
        if (sd > 0)
          close(sd);
        // recreate the socket
        sd = make_raw_socket(src_interface);
        // go back one port
        if (p > 0)
          --p;
      }
      else
      {
        // record the packet being sent
        packets++;
        // sleep for the required amount of time
        nanosleep(&sleep_req, &sleep_rem);
      }
    }

    if (time_last < time(NULL))
    {
      opps = rpps?rpps:tpps;
      cpps = packets - packets_last;

      if (cpps>tpps)
        rpps = opps - (abs(opps-cpps)/10);
      else if(cpps<tpps)
        rpps = opps + (abs(opps-cpps)/10);
      else
        rpps = opps;

      fprintf(stderr, "[+] Packets sent: %d to %d hosts\n", packets, pnum?(packets/pnum):0);
      fprintf(stderr, "[+] Current real PPS is %f, adjusting new PPS to %f from %f to meet target PPS of %f\n", cpps, rpps, opps, tpps);

      sleep_req.tv_sec = floor(1.0f/rpps);
      sleep_req.tv_nsec = (((1.0f/rpps) - floor(1.0f/rpps))*1000000000);

      packets_last = packets;
      time_last = time(NULL);
    }
  }

  close(sd);
}

int main(int argc, char** argv)
{
  srand(time(NULL));

  if (getuid() != 0)
  {
    fprintf(stderr, "Sorry, I only run as root!\n");
    exit(-1);
  }

  char* src_interface = NULL;
  char* src_ip_str;
  unsigned long int src_ip = 0;
  unsigned short int src_port = 0;
  float tpps = 1000;
  short int pnum = 0;
  short int* pptr = NULL;

  // Some variables that are used to hold various things
  int i = 0;
  char errbuf[PCAP_ERRBUF_SIZE];

  int c;
  while ((c = getopt(argc, argv, "i:s:p:r:h")) != -1)
  {
    switch (c)
    {
    case 'h':
      fprintf(stderr, "Usage: %s [-i interface] [-s source ip] [-p source port] [-r packets/second] [-h] port_1 [port_2 [...]]\n", argv[0]);
      exit(0);
    case 'i':
      src_interface = optarg;
      break;
    case 's':
      src_ip_str = optarg;
      src_ip = inet_addr(optarg);
      break;
    case 'p':
      src_port = atoi(optarg);
      break;
    case 'r':
      tpps = atof(optarg);
      break;
    }
  }

  if (optind < argc)
  {
    pnum = argc-optind;
    pptr = malloc(sizeof(int)*pnum);
    for (i=optind;i<argc;++i)
      pptr[i-optind] = atoi(argv[i]);
  }

  fprintf(stderr, "[+] packets-send startup:\n");

  if (src_interface == NULL)
  {
    fprintf(stderr, "[!] Source interface not specified, trying to autodetect...\n");
    src_interface = pcap_lookupdev(errbuf);
    if (src_interface == NULL)
    {
      fprintf(stderr, "[-] Couldn't get an interface: %s\n", errbuf);
      exit(-1);
    }
    fprintf(stderr, "[+] Using %s\n", src_interface);
  }

  if (src_ip == 0)
  {
    src_ip_str = malloc(sizeof(char)*INET_ADDRSTRLEN);
    fprintf(stderr, "[!] Source IP not specified, trying to autodetect...\n");
    bpf_u_int32 tmp_net=0, tmp_mask=0;
    if (pcap_lookupnet(src_interface, &tmp_net, &tmp_mask, errbuf) < 0)
    {
      fprintf(stderr, "[-] Couldn't get address: %s\n", errbuf);
      exit(-1);
    }
    src_ip = tmp_net;
    fprintf(stderr, "[+] Using %s\n", fs_inet_ntop(src_ip, src_ip_str));
  }

  if (src_port == 0)
  {
    fprintf(stderr, "[!] Source port not specified, choosing one at random...\n");
    src_port = (random()%(65536-1024))+1024;
    fprintf(stderr, "[+] Using %u\n", src_port);
  }

  if (src_ip < 0 || src_ip >= 4294967295)
  {
    fprintf(stderr, "[-] Source IP is invalid!\n");
    return -2;
  }

  if (src_port < 0 || src_port >= 65536)
  {
    fprintf(stderr, "[-] Source port is invalid!\n");
    return -3;
  }

  if (tpps < 0)
  {
    fprintf(stderr, "[-] Packets per second value is invalid!\n");
    return -4;
  }

  fprintf(stderr, "[+] Source interface: %s\n", src_interface);
  fprintf(stderr, "[+] Source IP: %s\n", fs_inet_ntop(src_ip, src_ip_str));
  fprintf(stderr, "[+] Source Port: %u\n", src_port);
  fprintf(stderr, "[+] Packets per second: %f\n", tpps);
  fprintf(stderr, "[+] Number of ports to scan: %d\n", pnum);
  fprintf(stderr, "[+] Ports:");
  for (i=0;i<pnum;++i)
    fprintf(stderr, " %d", pptr[i]);
  fprintf(stderr, "\n");

  send_packets(src_interface, src_ip, src_port, tpps, pnum, pptr);

  free(pptr);

  exit(0);
}
