#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char** argv)
{
  unsigned long int c = 0xFFFFFFFF;
  int s = time(NULL);

  if (argc >= 3)
    s = atoi(argv[2]);

  if (argc >= 2)
    c = atoi(argv[1]);

  fprintf(stderr, "[+] generate-ips-random startup:\n");
  fprintf(stderr, "[+] Total IPs to generate: %lu\n", c);
  fprintf(stderr, "[+] Seed: %d\n", s);

  srand(s);

  for (;c>0;--c)
    printf("%lu.%lu.%lu.%lu\n", random() % 256, random() % 256, random() % 256, random() % 256);

  return 0;
}
