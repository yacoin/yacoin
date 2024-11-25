// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef _BITCOIN_COMPAT_H
#define _BITCOIN_COMPAT_H 1

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#ifdef WIN32
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0501
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifdef FD_SETSIZE
#undef FD_SETSIZE // prevent redefinition compiler warning
#endif
#define FD_SETSIZE 1024 // max number of fds in fd_set

#include <winsock2.h>     // Must be included before mswsock.h and windows.h

#include <mswsock.h>
#include <windows.h>
#include <ws2tcpip.h>
#else
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <limits.h>
#include <netdb.h>
#include <unistd.h>
#endif

#ifndef WIN32
typedef unsigned int SOCKET;
#include "errno.h"
#define WSAGetLastError()   errno
#define WSAEINVAL           EINVAL
#define WSAEALREADY         EALREADY
#define WSAEWOULDBLOCK      EWOULDBLOCK
#define WSAEMSGSIZE         EMSGSIZE
#define WSAEINTR            EINTR
#define WSAEINPROGRESS      EINPROGRESS
#define WSAEADDRINUSE       EADDRINUSE
#define WSAENOTSOCK         EBADF
#define INVALID_SOCKET      (SOCKET)(~0)
#define SOCKET_ERROR        -1
#endif

#ifdef WIN32
#define MSG_NOSIGNAL        0
#define MSG_DONTWAIT        0

#ifndef S_IRUSR
#define S_IRUSR             0400
#define S_IWUSR             0200
#endif
#else
#define MAX_PATH            1024
#endif

#if HAVE_DECL_STRNLEN == 0
size_t strnlen( const char *start, size_t max_len);
#endif // HAVE_DECL_STRNLEN

bool static inline IsSelectableSocket(const SOCKET& s) {
#ifdef WIN32
    return true;
#else
    return (s < FD_SETSIZE);
#endif
}

extern bool 
    fDebug;

inline int myclosesocket(SOCKET& hSocket)
{
#ifdef WIN32
    static ::uint32_t 
        nHowManyValidCloses = 0,
        nHowManyCloses = 0;

    ++nHowManyCloses;
#endif
    if (hSocket == INVALID_SOCKET)
        return WSAENOTSOCK;
#ifdef WIN32
    ++nHowManyValidCloses;
    int ret = closesocket(hSocket);
#else
    int ret = close(hSocket);
#endif
    hSocket = INVALID_SOCKET;
    return ret;
}
#define closesocket(s)      myclosesocket(s)


#endif
