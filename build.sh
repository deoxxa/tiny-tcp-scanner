#!/bin/sh

clang -o packets-send packets-send.c -lm
clang -o packets-recv packets-recv.c -lpcap
clang -o generate-ips-random generate-ips-random.c
clang -o generate-ips-lfsr generate-ips-lfsr.c
