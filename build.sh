#!/bin/sh

clang -o sendpackets sendpackets.c -lm
clang -o recvpackets recvpackets.c -lpcap
clang -o generate-ips-random generate-ips-random.c
clang -o generate-ips-lfsr generate-ips-lfsr.c
