#!/bin/sh

clang -o sendpackets sendpackets.c -lm
clang -o recvpackets recvpackets.c -lpcap
