/*
    This file is part of ICMPTXE

    itunnel - an ICMP tunnel by edi / teso
    VTun - Virtual Tunnel over TCP/IP network.

    Copyright (C) 1998-2000  Maxim Krasnyansky <max_mk@yahoo.com>
    Copyright (C) 2006       Thomer M. Gil <thomer@thomer.com>
    Copyright (C) 2008       John Plaxco <john@johnplaxco.com>
    Copyright (C) 2020
 
    Original author unknown, but modified by Thomer M. Gil who found the original
    code through
      http://www.linuxexposed.com/Articles/Hacking/Case-of-a-wireless-hack.html
      (a page written by Siim Põder).

    Code updated by John Plaxco, cleaned up and added polling support to survive stateful firewalls.
 
    The (old) icmptx website is at http://thomer.com/icmptx/
    The current icmptx website is hosted at github, http://github.com/jakkarth/icmptx
*/

#include "tun_dev.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int run_icmp_tunnel(int verbose, uint16_t id, uint64_t key, const char *target_server);

#define USAGE "Usage: %s [-v] [-i ID] [-k KEY] [-c SERVER] [-s]\n" \
"\t-v - Verbose Mode (printslot of debug output to stdout)\n" \
"\t-i ID - optional 16-bit Identification Number (0..65535) to be used to mark packets (must be same on client and server)\n" \
"\t-k KEY - optional up to 64-bit Encryption Key Gamming Value (must be same on client and server)\n" \
"\t-s - Server Mode (default)\n" \
"\t-c - Client Mode with connection to specified SERVER\n" \

int main(int argc, char **argv) {
  int i;
  uint16_t id = 0xa110;
  uint64_t key = 0x1234567887654321;
  const char *target_server = NULL;
  int verbose = 0;

  for (i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "-v") == 0) {
      verbose = 1;

    } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
      id = (uint16_t)atoi(argv[++i]);

    } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
      const uint64_t kg = (uint64_t)atoi(argv[++i]);
      if (kg <= 0xff) {
        key^= (kg) | (kg << 8) | (kg << 16) | (kg << 24) | (kg << 32) | (kg << 40) | (kg << 48) | (kg << 56);
      } else if (kg <= 0xffff) {
        key^= (kg) | (kg << 16) | (kg << 32) | (kg << 48);
      } else if (kg <= 0xffffffff) {
        key^= (kg) | (kg << 32);
      } else {
        key^= (kg);
      }

    } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
      target_server = argv[++i];

    } else if (strcmp(argv[i], "-s") == 0) {
      target_server = NULL;

    } else {
      fprintf(stderr, USAGE, argv[0]);
      return 1;
    }
  }

  run_icmp_tunnel(verbose, id, key, target_server);

  return 0;
}
