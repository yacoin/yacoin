/*
 * Get External IP address by STUN protocol
 *
 * Based on project Minimalistic STUN client "ministun"
 * https://code.google.com/p/ministun/
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *
 * STUN is described in RFC3489 and it is based on the exchange
 * of UDP packets between a client and one or more servers to
 * determine the externally visible address (and port) of the client
 * once it has gone through the NAT boxes that connect it to the
 * outside.
 * The simplest request packet is just the header defined in
 * struct stun_header, and from the response we may just look at
 * one attribute, STUN_MAPPED_ADDRESS, that we find in the response.
 * By doing more transactions with different server addresses we
 * may determine more about the behaviour of the NAT boxes, of
 * course - the details are in the RFC.
 *
 * All STUN packets start with a simple header made of a type,
 * length (excluding the header) and a 16-byte random transaction id.
 * Following the header we may have zero or more attributes, each
 * structured as a type, length and a value (whose format depends
 * on the type, but often contains addresses).
 * Of course all fields are in network format.
 */
#ifdef _MSC_VER
    #include "msvc_warnings.push.h"
#endif

#define __STDC_LIMIT_MACROS

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif
#ifndef WIN32
#include <unistd.h>
#endif
#include <time.h>
#include <errno.h>

#include "ministun.h"

#ifndef BITCOIN_SYNC_H
 #include "sync.h"
#endif
//extern CCriticalSection cs_net;

extern int GetRandInt(int nMax);
extern uint64_t GetRand(uint64_t nMax);

/*---------------------------------------------------------------------*/

struct StunSrv {
    char     name[30];
    uint16_t port;
};

/*---------------------------------------------------------------------*/
static const int StunSrvListQty = 37; // Must be PRIME!!!!!

static struct StunSrv StunSrvList[37] = {
    {"s1.taraba.net", 3478},
    {"s2.taraba.net", 3478},
    {"stun.12connect.com", 3478},
    {"stun.1und1.de", 3478},
    {"stun.2talk.co.nz", 3478},
    {"stun.alltel.com.au", 3478},
    {"stun.altar.com.pl", 3478},
    {"stun.barracuda.com", 3478},
    {"stun.drogon.net", 3478},
    {"stun.duocom.es", 3478},
    {"stun.freecall.com", 3478},
    {"stun.freeswitch.org", 3478},
    {"stun.gmx.de", 3478},
    {"stun.gmx.net", 3478},
    {"stun.hosteurope.de", 3478},
    {"stun.intervoip.com", 3478},
    {"stun.kanet.ru", 3478},
    {"stun.kiwilink.co.nz", 3478},
    {"stun.kundenserver.de", 3478},
    {"stun.l.google.com", 19302},
    {"stun.linphone.org", 3478},
    {"stun.liveo.fr", 3478},
    {"stun.magnet.ie", 3478},
    {"stun.mit.de", 3478},
    {"stun.nas.net", 3478},
    {"stun.nottingham.ac.uk", 3478},
    {"stun.phone.com", 3478},
    {"stun.services.mozilla.com", 3478},
    {"stun.stunprotocol.org", 3478},
    {"stun.voip.blackberry.com", 3478},
    {"stun.whoi.edu", 3478},
    {"stun1.l.google.com", 19302},
    {"stun2.l.google.com", 19302},
    {"stun3.l.google.com", 19302},
    {"stun4.l.google.com", 19302},
    {"stunserver.org", 3478},
    {"stun.antisip.com", 3478}
};


/* wrapper to send an STUN message */
static int stun_send(int s, struct sockaddr_in *dst, struct stun_header *resp)
{
    return sendto(s, (const char *)resp, ntohs(resp->msglen) + sizeof(*resp), 0,
                  (struct sockaddr *)dst, sizeof(*dst));
}

/* helper function to generate a random request id */
static uint64_t randfiller = GetRand(UINT64_MAX);
static void stun_req_id(struct stun_header *req)
{
    const uint64_t *S_block = (const uint64_t *)StunSrvList;
    req->id.id[0] = GetRandInt(INT32_MAX);
    req->id.id[1] = GetRandInt(INT32_MAX);
    req->id.id[2] = GetRandInt(INT32_MAX);
    req->id.id[3] = GetRandInt(INT32_MAX);

    req->id.id[0] |= 0x55555555;
    req->id.id[1] &= 0x55555555;
    req->id.id[2] |= 0x55555555;
    req->id.id[3] &= 0x55555555;
    register char x = 20;
    do {
        uint32_t s_elm = S_block[(uint8_t)randfiller];
        randfiller ^= (randfiller << 5) | (randfiller >> (64 - 5));
        randfiller += s_elm ^ x;
        req->id.id[x & 3] ^= randfiller + (randfiller >> 13);
    } while(--x);
}

/* callback type to be invoked on stun responses. */
typedef int (stun_cb_f)(struct stun_attr *attr, void *arg);

/* handle an incoming STUN message.
 *
 * Do some basic sanity checks on packet size and content,
 * try to extract a bit of information, and possibly reply.
 * At the moment this only processes BIND requests, and returns
 * the externally visible address of the request.
 * If a callback is specified, invoke it with the attribute.
 */
static int stun_handle_packet(int s, struct sockaddr_in *src,
                              unsigned char *data, size_t len, stun_cb_f *stun_cb, void *arg)
{
    struct stun_header *hdr = (struct stun_header *)data;
    struct stun_attr *attr;
    int ret = len;
    unsigned int x;

    /* On entry, 'len' is the length of the udp payload. After the
   * initial checks it becomes the size of unprocessed options,
   * while 'data' is advanced accordingly.
   */
    if (len < sizeof(struct stun_header))
        return -20;

    len -= sizeof(struct stun_header);
    data += sizeof(struct stun_header);
    x = ntohs(hdr->msglen); /* len as advertised in the message */
    if(x < len)
        len = x;

    while (len) {
        if (len < sizeof(struct stun_attr)) {
            ret = -21;
            break;
        }
        attr = (struct stun_attr *)data;
        /* compute total attribute length */
        x = ntohs(attr->len) + sizeof(struct stun_attr);
        if (x > len) {
            ret = -22;
            break;
        }
        stun_cb(attr, arg);
        //if (stun_process_attr(&st, attr)) {
        //  ret = -23;
        //  break;
        // }
        /* Clear attribute id: in case previous entry was a string,
     * this will act as the terminator for the string.
     */
        attr->attr = 0;
        data += x;
        len -= x;
    } // while
    /* Null terminate any string.
   * XXX NOTE, we write past the size of the buffer passed by the
   * caller, so this is potentially dangerous. The only thing that
   * saves us is that usually we read the incoming message in a
   * much larger buffer
   */
    *data = '\0';

    /* Now prepare to generate a reply, which at the moment is done
   * only for properly formed (len == 0) STUN_BINDREQ messages.
   */

    return ret;
}

/* Extract the STUN_MAPPED_ADDRESS from the stun response.
 * This is used as a callback for stun_handle_response
 * when called from stun_request.
 */
static int stun_get_mapped(struct stun_attr *attr, void *arg)
{
    struct stun_addr *addr = (struct stun_addr *)(attr + 1);
    struct sockaddr_in *sa = (struct sockaddr_in *)arg;

    if (ntohs(attr->attr) != STUN_MAPPED_ADDRESS || ntohs(attr->len) != 8)
        return 1; /* not us. */
    sa->sin_port = addr->port;
    sa->sin_addr.s_addr = addr->addr;
    return 0;
}

/*---------------------------------------------------------------------*/

static int StunRequest2(int sock, struct sockaddr_in *server, struct sockaddr_in *mapped) {

    struct stun_header *req;
    unsigned char reqdata[1024];

    req = (struct stun_header *)reqdata;
    stun_req_id(req);
    int reqlen = 0;
    req->msgtype = 0;
    req->msglen = 0;
    req->msglen = htons(reqlen);
    req->msgtype = htons(STUN_BINDREQ);

    unsigned char reply_buf[1024];
    fd_set rfds;
    struct timeval to = { STUN_TIMEOUT, 0 };
    struct sockaddr_in src;
#ifdef WIN32
    int srclen;
#else
    socklen_t srclen;
#endif

    int res = stun_send(sock, server, req);
    if(res < 0)
        return -10;
    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);
    res = select(sock + 1, &rfds, NULL, NULL, &to);
    if (res <= 0)  /* timeout or error */
        return -11;
    memset(&src, 0, sizeof(src));
    srclen = sizeof(src);
    /* XXX pass -1 in the size, because stun_handle_packet might
   * write past the end of the buffer.
   */
    res = recvfrom(sock, (char *)reply_buf, sizeof(reply_buf) - 1,
                   0, (struct sockaddr *)&src, &srclen);
    if (res <= 0)
        return -12;
    memset(mapped, 0, sizeof(struct sockaddr_in));
    return stun_handle_packet(sock, &src, reply_buf, res, stun_get_mapped, mapped);
} // StunRequest2

/*---------------------------------------------------------------------*/
static int StunRequest(const char *host, uint16_t port, struct sockaddr_in *mapped) 
{
//    LOCK(cs_net);
    {

    struct hostent *hostinfo = gethostbyname(host);
    if(hostinfo == NULL)
        return -1;

    struct sockaddr_in server, client;
    memset(&server, 0, sizeof(server));
    memset(&client, 0, sizeof(client));
    server.sin_family = client.sin_family = AF_INET;

    server.sin_addr = *(struct in_addr*) hostinfo->h_addr;
    server.sin_port = htons(port);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0)
        return -2;

    client.sin_addr.s_addr = htonl(INADDR_ANY);

    int rc = -3;
    if(bind(sock, (struct sockaddr*)&client, sizeof(client)) >= 0)
        rc = StunRequest2(sock, &server, mapped);
#ifndef WIN32
    close(sock);
#else
    (void)closesocket(sock);
#endif
    return rc;
    }
} // StunRequest

/*---------------------------------------------------------------------*/
// Input: two random values (pos, step) for generate unique way over server
// list
// Output: populate struct struct mapped
// Retval:

int GetExternalIPbySTUN(uint64_t rnd, struct sockaddr_in *mapped, const char **srv) {
    randfiller    = rnd;
    uint16_t pos  = rnd;
    uint16_t step;
    do {
        rnd = (rnd >> 8) | 0xff00000000000000LL;
        step = rnd % StunSrvListQty;
    } while(step == 0);

    uint16_t attempt;
    for(attempt = 1; attempt < StunSrvListQty * 2; attempt++) {
        pos = (pos + step) % StunSrvListQty;
        int rc = StunRequest(*srv = StunSrvList[pos].name, StunSrvList[pos].port, mapped);
        if(rc >= 0)
            return attempt;
        // fprintf(stderr, "Lookup: %s:%u\t%s\t%d\n", StunSrvList[pos].name,
        // StunSrvList[pos].port, inet_ntoa(mapped->sin_addr), rc);
    }
    return -1;
}
#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
