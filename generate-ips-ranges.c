#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <math.h>

int process_range(char* range, unsigned long int* ip_from, unsigned long int* ip_to)
{
  if (range[0] == '#')
    return 0;

  char* tmp = range;
  for (;*tmp;++tmp)
    if (*tmp == '\n')
      *tmp = 0;

  fprintf(stderr, "[+] Processing range: %s\n", range);

  char* pos;
  char ip_str[16], cidr_str[3];
  int cidr = 0;
  memset(ip_str, 0, 16);
  memset(cidr_str, 0, 3);
  if (pos = strchr(range, '/'))
  {
    strncpy(ip_str, range, pos-range);
    strncpy(cidr_str, pos+1, strlen(pos+1));
    cidr = atoi(cidr_str);
    *ip_from = ntohl(inet_addr(ip_str));
    *ip_to = ntohl(inet_addr(ip_str))+pow(2, 32-cidr)-2;
  }

  return 0;
}

int main(int argc, char** argv)
{
  int c;
  while ((c = getopt(argc, argv, "h")) != -1)
  {
    switch (c)
    {
    case 'h':
      fprintf(stderr, "Usage: %s [file]\n", argv[0]);
      exit(0);
    }
  }

  fprintf(stderr, "[+] generate-ips-ranges startup:\n");
  fprintf(stderr, "[+] File to read ranges from: %s\n", (argc>1)?argv[1]:"-");

  FILE* fh_in;

  if (argc <= 1)
    fh_in = stdin;
  else
    fh_in = fopen(argv[1], "r");

  if (!fh_in)
  {
    fprintf(stderr, "[-] Could not open %s for reading\n", argv[1]);
    exit(-1);
  }

  char range[128];
  unsigned long int ip_from=0,ip_to=0;
  while(fgets(range, 34, fh_in))
  {
    if (process_range(range, &ip_from, &ip_to) == 0)
      do {
        printf("%lu.%lu.%lu.%lu\n", ((ip_from & 0xFF000000) >> 24), ((ip_from & 0x00FF0000) >> 16), ((ip_from & 0x0000FF00) >> 8), ((ip_from & 0x000000FF) >> 0));
      } while (ip_from++ < ip_to);
  }

  return 0;
}
