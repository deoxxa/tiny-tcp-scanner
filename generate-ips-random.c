#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

int main(int argc, char** argv)
{
  unsigned long int n = 0xFFFFFFFF;
  int s = time(NULL);

  int c;
  while ((c = getopt(argc, argv, "n:s:h")) != -1)
  {
    switch (c)
    {
    case 'h':
      fprintf(stderr, "Usage: %s [-n number of ips] [-s seed]\n", argv[0]);
      exit(0);
    case 'n':
      n = atoi(optarg);
      break;
    case 's':
      s = atoi(optarg);
      break;
    }
  }

  fprintf(stderr, "[+] generate-ips-random startup:\n");
  fprintf(stderr, "[+] Total IPs to generate: %lu\n", n);
  fprintf(stderr, "[+] Seed: %d\n", s);

  srand(s);

  for (;n>0;--n)
    printf("%lu.%lu.%lu.%lu\n", random() % 256, random() % 256, random() % 256, random() % 256);

  return 0;
}
