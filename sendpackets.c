#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <math.h>
#include <pthread.h>

#include "headers.h"

void lfsr_step(unsigned long int* lfsr) { *lfsr = (*lfsr >> 1) ^ (unsigned long int)(0 - (*lfsr & 1u) & 0xd0000001u); }

void dump(unsigned char* data, int len)
{
	int i;
	for (i=0;i<len;i++)
	{
		if ((i % 16) == 0) { printf("		 0x%04x:	", i); }
		printf("%02x", *data++);
		if (((i+1) % 2) == 0) { printf(" "); }
		if (((i+1) % 16) == 0) { printf("\n"); }
	}

	printf("\n");
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

int sendpacket(unsigned char* buf, int s, unsigned long int src_ip, int src_port, unsigned long int dst_ip, int dst_port)
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
	printf("[+] Packet:\n");
	dump(buf, sizeof(struct fs_ipv4hdr)+sizeof(struct fs_tcphdr));

	printf("[+] IP sum: 0x%04x\n", ip->checksum);
	printf("[+] IP Portion:\n");
	dump(buf, sizeof(struct fs_ipv4hdr));

	printf("[+] TCP sum: 0x%04x\n", tcp->checksum);
	printf("[+] TCP Portion:\n");
	dump((buf+sizeof(struct fs_ipv4hdr)), sizeof(struct fs_tcphdr));
#endif

	if (sendto(s, buf, ip->length, 0, (struct sockaddr*)&din, sizeof(struct sockaddr_in)) < 0)
	{
		fprintf(stderr, "[-] Could not send packet to %d: [%d] %s\n", s, errno, strerror(errno));
		fprintf(stderr, "		 Arguments were: %d, %p, %d, 0, %p, %d\n", s, buf, ip->length, &din, sizeof(struct sockaddr_in));
		fprintf(stderr, "		 Remote address was: %lu.%lu.%lu.%lu:%d\n", ((dst_ip & 0xFF000000) >> 24), ((dst_ip & 0x00FF0000) >> 16), ((dst_ip & 0x0000FF00) >> 8), ((dst_ip & 0x000000FF) >> 0), dst_port);
		return -1;
	}

	return 0;
}

int make_raw_socket()
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
		printf("[+] Socket descriptor created: %d\n", s);
	}

	if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &y, sizeof(y)) < 0)
	{
		fprintf(stderr, "[-] Could not set socket option IPPROTO_IP/IP_HDRINCL: [%d] %s\n", errno, strerror(errno));
		return -2;
	}
	else
	{
		printf("[+] Socket option IPPROTO_IP/IP_HDRINCL set successfully\n");
	}

	return s;
}

void send_packets(unsigned long int src_ip, int src_port, float tpps, short int pnum, short int* pptr)
{
	// init memory used for packet construction
	unsigned char buf [sizeof(struct fs_ipv4hdr) + sizeof(struct fs_tcphdr)];

	// create placeholder for socket
	int sd = 0;

	// init the lfsr
	unsigned long lfsr = 1;

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

	printf("[+] Sending packets...\n");
	do
	{
		// increment the lfsr
		lfsr_step(&lfsr);

		if ((lfsr & 0x000000FF) == 0)
			continue;

		// cycle through ports
		for (p=0;p<pnum;++p)
		{
			// send packet
			if ((sd <= 0) || (sendpacket(buf, sd, src_ip, src_port, lfsr, pptr[p]) != 0))
			{
				// try to close the socket if necessary
				if (sd > 0)
					close(sd);
				// recreate the socket
				sd = make_raw_socket();
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
			else
				rpps = opps + (abs(opps-cpps)/10);

			printf("[+] Packets sent: %d\n", packets);
			printf("[+] Current real PPS is %f, adjusting new PPS to %f from %f to meet target PPS of %f\n", cpps, rpps, opps, tpps);

			sleep_req.tv_sec = floor(1.0f/rpps);
			sleep_req.tv_nsec = (((1.0f/rpps) - floor(1.0f/rpps))*1000000000);

			packets_last = packets;
			time_last = time(NULL);
		}
	} while (lfsr != 1u);

	close(sd);
}

int main(int argc, char** argv)
{
	if (argc < 5)
	{
		if (argc > 0)
			fprintf(stderr, "Usage: %s src_ip src_port packets_per_second port_1 [port_2 [port_3 [...]]]\n", argv[0]);
		// in case we have no argv[0] (it can happen...)
		else
			fprintf(stderr, "Usage: ./sendpackets src_ip src_port packets_per_second port_1 [port_2 [port_3 [...]]]\n");

		return -1;
	}

	unsigned long int src_ip = inet_addr(argv[1]);
	short int src_port = atoi(argv[2]);
	float tpps = atof(argv[3]);
	short int pnum = argc-4;
	short int* pptr = malloc(sizeof(short int)*pnum);
	int i;
	for (i=0;i<pnum;++i)
		pptr[i] = atoi(argv[4+i]);

	if (src_ip <= 0 || src_ip >= 4294967295)
	{
		fprintf(stderr, "[-] Source IP is invalid!\n");
		return -2;
	}

	if (src_port <= 0 || src_port >= 65536)
	{
		fprintf(stderr, "[-] Source port is invalid!\n");
		return -3;
	}

	if (tpps <= 0)
	{
		fprintf(stderr, "[-] Packets per second value is invalid!\n");
		return -4;
	}

	printf("[+] Source IP: %s\n", argv[1]);
	printf("[+] Source Port: %u\n", src_port);
	printf("[+] Packets per second: %f\n", tpps);
	printf("[+] Number of ports to scan: %d\n", pnum);
	printf("[+] Ports:");
	for (i=0;i<pnum;++i)
		printf(" %d", pptr[i]);
	printf("\n");

	send_packets(src_ip, src_port, tpps, pnum, pptr);

	while (1)
		sleep(1);

	free(pptr);
}
