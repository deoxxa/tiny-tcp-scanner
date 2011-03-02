#!/bin/sh

cc -o packets-send packets-send.c -lpcap -lm
cc -o packets-recv packets-recv.c -lpcap
cc -o generate-ips-random generate-ips-random.c
cc -o generate-ips-lfsr generate-ips-lfsr.c
