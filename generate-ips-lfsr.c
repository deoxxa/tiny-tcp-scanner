#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void lfsr_step(unsigned long int* lfsr) { *lfsr = (*lfsr >> 1) ^ (unsigned long int)(0 - (*lfsr & 1u) & 0xd0000001u); }

int main(int argc, char** argv)
{
  unsigned long int n = 0xFFFFFFFF;

  int c;
  while ((c = getopt(argc, argv, "n:h")) != -1)
  {
    switch (c)
    {
    case 'h':
      fprintf(stderr, "Usage: %s [-n number of ips]\n", argv[0]);
      exit(0);
    case 'n':
      n = atoi(optarg);
      break;
    }
  }

  fprintf(stderr, "[+] generate-ips-lfsr startup:\n");
  fprintf(stderr, "[+] Total IPs to generate: %lu\n", n);

  unsigned long lfsr = 1;

  for (;n>0;--n)
  {
    printf("%lu.%lu.%lu.%lu\n", ((lfsr & 0xFF000000) >> 24), ((lfsr & 0x00FF0000) >> 16), ((lfsr & 0x0000FF00) >> 8), ((lfsr & 0x000000FF) >> 0));
    lfsr_step(&lfsr);
  }

  return 0;
}
