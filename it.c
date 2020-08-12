/*
    This file is part of ICMPTXE

    Original code copyright date unknown, edi/teso.
    Copyright (C) 2006       Thomer M. Gil <thomer@thomer.com>
    Copyright (C) 2008       John Plaxco <john@johnplaxco.com>
    Copyright (C) 2020

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this ICMPTX.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "tun_dev.h"

#define MAXPACKET 0xffff

unsigned short in_cksum(unsigned short *, int);

static void icmptx_encrypt(unsigned char *b, unsigned int l, uint64_t key)
{
  unsigned int i;
  for (i = 0; i < l; ++i) {
    uint64_t new_key = (key >> 8) | ((key & 0xff) << 56);
    uint64_t nkg = (b[i] ^ i) & 0xff;
    new_key^= nkg; new_key^= nkg << 8;
    new_key^= nkg << 16; new_key^= nkg << 24;
    new_key^= nkg << 32; new_key^= nkg << 40;
    new_key^= nkg << 48; new_key^= nkg << 56;
    b[i]^= (unsigned char)(key&0xff);
    key = new_key;
  }
}

static void icmptx_decrypt(unsigned char *b, unsigned int l, uint64_t key)
{
  unsigned int i;
  uint64_t nkg;
  for (i = 0; i < l; ++i) {
    b[i]^= (unsigned char)(key&0xff);
    key = (key >> 8) | ((key & 0xff) << 56);
    nkg = (b[i] ^ i) & 0xff;
    key^= nkg; key^= nkg << 8;
    key^= nkg << 16; key^= nkg << 24;
    key^= nkg << 32; key^= nkg << 40;
    key^= nkg << 48; key^= nkg << 56;
  }
}

/* int sock - ICMP socket used to communicate
   int tun_fd - Input/output file descriptor
   int proxy - 0 means send echo requests, 1 means send echo replies
   server_addr - For the client, points to the server address. For the server, NULL.
   id - tunnel id field
   key - tunnel encryption key
*/

struct txehdr {
/* unique random value */
  uint16_t salt;
/* server-unique id (passed in command line) */
  uint16_t id;
};

struct txeclient {
  uint32_t ip;
  uint16_t id;
  uint16_t seq;
};

static void send2client(int sock, struct txeclient *client, unsigned char *buf, int len)
{
  struct icmphdr *icmp = (struct icmphdr*)buf;
  struct sockaddr_in clnt_sin = {AF_INET, 0};
  clnt_sin.sin_addr.s_addr = client->ip;

  icmp->type = 0; /*echo response*/
  icmp->code = 0;
  icmp->un.echo.id = client->id;
  icmp->un.echo.sequence = client->seq;
  icmp->checksum = 0;
  icmp->checksum = in_cksum((unsigned short *)buf, len);
  sendto(sock, (char*)buf, len, 0, (struct sockaddr*)&clnt_sin, sizeof(clnt_sin));
}

static void send2server(int sock, struct sockaddr_in *server_addr, unsigned char *buf, int len)
{
  struct icmphdr *icmp = (struct icmphdr*)buf;

  icmp->type = 8; /*echo request*/
  icmp->code = 0;
  icmp->un.echo.id = 1;
  icmp->un.echo.sequence = 0;
  icmp->checksum = 0;
  icmp->checksum = in_cksum((unsigned short *)buf, len);
  sendto(sock, (char*)buf, len, 0, (struct sockaddr*)server_addr, sizeof(*server_addr));
}

int icmp_tunnel(int verbose, int sock, int tun_fd, struct sockaddr_in *server_addr, uint16_t id, uint64_t key)
{
  int rv;
  uint16_t peer_id;
  fd_set fs;
  struct iphdr *ip;
  struct icmphdr *icmp;
  struct txehdr *txe;
  struct timeval tv;
  const int buflen = sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct txehdr) + MAXPACKET + 64;
  const int poll_dummy_len = (rand() % sizeof(struct iphdr)) & (~3);
  unsigned char *buf = (unsigned char *)malloc(buflen);
  struct txeclient clients[0x100] = {0}; /* index is least octet of in-tunnel peer IP */

  if (buf == NULL) {
    fprintf(stderr, "Error allocating buffer");
    return -1;
  }

  if ((id & 0xff) == (id >> 8)) {
    /* hi&lo octets of id must be different */
    id^= 1;
  }

  if (server_addr == NULL) {
    peer_id = id;
    id = ((id & 0xff) << 8) | ((id & 0xff00) >> 8);
  } else {
    peer_id = ((id & 0xff) << 8) | ((id & 0xff00) >> 8);
  }

  /* here's the infinite loop that shovels bufs back and forth while the tunnel's up */
  while (1) {
    FD_ZERO (&fs);
    FD_SET (tun_fd, &fs);
    FD_SET (sock, &fs);

    /* block until data's available in one direction or the other, or it's time to poll */
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    rv = select ((tun_fd > sock) ? tun_fd + 1 : sock + 1, &fs, NULL, NULL, &tv);

    /* data available on tunnel device, need to transmit over icmp or timeout */
    if (FD_ISSET(tun_fd, &fs) || (rv == 0 && server_addr != NULL)) {
      int client_index = -1;
      if (FD_ISSET(tun_fd, &fs)) {
        ip = (struct iphdr *)&buf[sizeof(struct icmphdr) + sizeof(struct txehdr)];
        rv = tun_read(tun_fd, (char *)ip, MAXPACKET);
        if (!rv) {/*eof*/
          perror("tunnel eof");
          break;

        }
        if (rv < 0) {
          perror("tunnel read");
          return -1;
        }

        if (!server_addr) {
          client_index = ((ip->daddr >> 24) & 0xff);
        }

      } else {
        /*
         * If we didn't send or receive anything, the select timed out
         * so lets send an echo request dummy poll to the server (helps
         * with stateful firewalls). In such case payload size is less
         * than sizeof IP header to allow receiver to-prefilter them out
         */
        int i;
        rv = poll_dummy_len;
        for (i = 0; i < rv; ++i) {
          buf[sizeof(struct icmphdr) + sizeof(struct txehdr) + i] = rand() & 0xff;
        }
      }
      txe = (struct txehdr *)&buf[sizeof(struct icmphdr)];
      txe->salt = rand() & 0xffff;
      txe->id = id;

      icmptx_encrypt(&buf[sizeof(struct icmphdr)], rv + sizeof(struct txehdr), key);

      if (server_addr) {
        send2server(sock, server_addr, buf, sizeof(struct icmphdr) + sizeof(struct txehdr) + rv);
        if (verbose) printf("server <- %d\n", rv);

      } else if (client_index == -1 || clients[client_index].ip == 0) {
        int i;
        if (verbose) printf("client[?] <- %d\n", rv);
        for (i = 0; i <= 0xff; ++i) if (clients[i].ip != 0) {
          send2client(sock, &clients[i], buf, sizeof(struct icmphdr) + sizeof(struct txehdr) + rv);
        }

      } else {
        if (verbose) printf("client[%d] <- %d\n", client_index, rv);
        send2client(sock, &clients[client_index], buf, sizeof(struct icmphdr) + sizeof(struct txehdr) + rv);
      }
    }

    /* data available on socket from icmp, need to pass along to tunnel device */
    if (FD_ISSET(sock, &fs)) {
      const int txeofs = sizeof(struct iphdr) + sizeof(struct icmphdr);
      struct sockaddr_in from;
      socklen_t fromlen = sizeof(struct sockaddr_in);
      rv = recvfrom(sock, buf, buflen, 0, (struct sockaddr*)&from, &fromlen);

      if (rv >= txeofs + sizeof(struct txehdr)) {
        icmptx_decrypt(&buf[txeofs], rv - txeofs, key);
        txe = (struct txehdr *)&buf[txeofs];
        if (txe->id == peer_id) {
            const int payload_len = rv - (txeofs + sizeof(struct txehdr));
            /* dont write to tunnel dummy polls, only real IP packets */
            if (payload_len >= sizeof(struct iphdr)) {
                ip = (struct iphdr *)&buf[txeofs + sizeof(struct txehdr)];
                if (!server_addr) {
                  int client_index = (ip->saddr >> 24) & 0xff;
                  icmp = (struct icmphdr*)(buf + sizeof(struct iphdr));
                  if (verbose) {
                    printf("client[%d] -> %d\n", client_index, payload_len);
                  }
                  clients[client_index].ip = from.sin_addr.s_addr;
                  clients[client_index].id = icmp->un.echo.id;
                  clients[client_index].seq = icmp->un.echo.sequence;

                } else if (verbose) {
                  printf("server -> %d\n", payload_len);
                }
                tun_write(tun_fd, (char *)ip, payload_len);
            }
            else if (verbose) {
                printf("dummy: %d\n", payload_len);
            }
        }
        else if (verbose) {
          printf("bad id=0x%x rv=%d\n", txe->id, rv);
        }
      }
      else if (verbose) {
        printf("too short rv=%d\n", rv);
      }
    }
  }  /* end of while(1) */

  return 0;
}

/*
 * this is the function that starts it all rolling (or not)
 * id - the id value for the icmp stream (must match on both ends), to distinguish it from any other incoming ICMP packets
 * key - encryption key (must match on both ends)
 * target_server - target server host if running in client mode, otherwise NULL if running in server mode
 */
int run_icmp_tunnel(int verbose, uint16_t id, uint64_t key, const char *target_server)
{
  struct sockaddr_in server_addr;
  struct in_addr inp;
  int sock_fd, tun_fd;

  if (target_server == NULL) {
    ;
  } else if (!inet_aton(target_server, &inp)) {
    struct hostent* he = gethostbyname (target_server);
    if (!he) {
      herror ("gethostbyname");
      return -1;
    }
    memcpy (&server_addr.sin_addr.s_addr, he->h_addr_list[0], he->h_length);

  } else {
    server_addr.sin_addr.s_addr = inp.s_addr;

  }
  server_addr.sin_family = AF_INET;

  if ( (sock_fd = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
    perror ("socket");
    return -1;
  }

  if ((tun_fd = tun_open()) < 1) {
    fprintf(stderr, "Could not create tunnel device. Fatal.\n");
    close(sock_fd);
    return -2;
  }

  srand(getpid());

  icmp_tunnel(verbose, sock_fd, tun_fd, target_server ? &server_addr : NULL, id, key);

  tun_close(tun_fd);
  close(sock_fd);

  return 0;
}

/*
 * calculate the icmp checksum for the packet, including data
 */
unsigned short in_cksum (unsigned short *addr, int len) {
  int nleft = len;
  unsigned short *w = addr;
  int sum = 0;
  unsigned short answer = 0;
  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }
  if (nleft == 1) {
    *(unsigned char *) (&answer) = *(unsigned char *) w;
    sum += answer;
  }
  sum = (sum >> 16) + (sum & 0xffff);   /* add hi 16 to low 16 */
  sum += (sum >> 16);           /* add carry */
  answer = ~(sum & 0xffff);                /* truncate to 16 bits */
  return (answer);
}
