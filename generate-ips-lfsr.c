#include <stdio.h>
#include <stdlib.h>

void lfsr_step(unsigned long int* lfsr) { *lfsr = (*lfsr >> 1) ^ (unsigned long int)(0 - (*lfsr & 1u) & 0xd0000001u); }

int main(int argc, char** argv)
{
  unsigned long int c = 0xFFFFFFFF;

  if (argc >= 2)
    c = atoi(argv[1]);

  fprintf(stderr, "[+] generate-ips-lfsr startup:\n");
  fprintf(stderr, "[+] Total IPs to generate: %lu\n", c);

  unsigned long lfsr = 1;

  for (;c>0;--c)
  {
    printf("%lu.%lu.%lu.%lu\n", ((lfsr & 0xFF000000) >> 24), ((lfsr & 0x00FF0000) >> 16), ((lfsr & 0x0000FF00) >> 8), ((lfsr & 0x000000FF) >> 0));
    lfsr_step(&lfsr);
  }

  return 0;
}
