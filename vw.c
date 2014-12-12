/*-
 * Copyright (c) 2012 Weongyo Jeong <weongyo@gmail.com>
 * Copyright (c) 2006 Verdens Gang AS
 * Copyright (c) 2006-2011 Varnish Software AS
 * All rights reserved.
 *
 * Author: Poul-Henning Kamp <phk@phk.freebsd.dk>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#define _GNU_SOURCE
#include <sys/param.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include "vqueue.h"

/*--------------------------------------------------------------------*/

#define	likely(x)	__builtin_expect(!!(x), 1)
#define	unlikely(x)	__builtin_expect(!!(x), 0)

/* Assert zero return value */
#define AZ(foo)		do { assert((foo) == 0); } while (0)
#define AN(foo)		do { assert((foo) != 0); } while (0)
#define XXXAZ(foo)	do { assert((foo) == 0); } while (0)
#define XXXAN(foo)	do { assert((foo) != 0); } while (0)

/* lightweight addrinfo */
struct vss_addr {
	int			 va_family;
	int			 va_socktype;
	int			 va_protocol;
	socklen_t		 va_addrlen;
	struct sockaddr_storage	 va_addr;
};

struct sess {
	unsigned		magic;
#define	SESS_MAGIC		0x2c2f9c5a
	int			fd;
	int			no;
	struct sesshead		*sh;
	VTAILQ_ENTRY(sess)	list;
};
VTAILQ_HEAD(sesshead, sess);

/*
 * Take a string provided by the user and break it up into address and
 * port parts.  Examples of acceptable input include:
 *
 * "localhost" - "localhost:80"
 * "127.0.0.1" - "127.0.0.1:80"
 * "0.0.0.0" - "0.0.0.0:80"
 * "[::1]" - "[::1]:80"
 * "[::]" - "[::]:80"
 *
 * See also RFC5952
 */

int
VSS_parse(const char *str, char **addr, char **port)
{
	const char *p;

	*addr = *port = NULL;

	if (str[0] == '[') {
		/* IPv6 address of the form [::1]:80 */
		if ((p = strchr(str, ']')) == NULL ||
		    p == str + 1 ||
		    (p[1] != '\0' && p[1] != ':'))
			return (-1);
		*addr = strdup(str + 1);
		XXXAN(*addr);
		(*addr)[p - (str + 1)] = '\0';
		if (p[1] == ':') {
			*port = strdup(p + 2);
			XXXAN(*port);
		}
	} else {
		/* IPv4 address of the form 127.0.0.1:80, or non-numeric */
		p = strchr(str, ' ');
		if (p == NULL)
			p = strchr(str, ':');
		if (p == NULL) {
			*addr = strdup(str);
			XXXAN(*addr);
		} else {
			if (p > str) {
				*addr = strdup(str);
				XXXAN(*addr);
				(*addr)[p - str] = '\0';
			}
			*port = strdup(p + 1);
			XXXAN(*port);
		}
	}
	return (0);
}

/*
 * For a given host and port, return a list of struct vss_addr, which
 * contains all the information necessary to open and bind a socket.  One
 * vss_addr is returned for each distinct address returned by
 * getaddrinfo().
 *
 * The value pointed to by the tap parameter receives a pointer to an
 * array of pointers to struct vss_addr.  The caller is responsible for
 * freeing each individual struct vss_addr as well as the array.
 *
 * The return value is the number of addresses resoved, or zero.
 *
 * If the addr argument contains a port specification, that takes
 * precedence over the port argument.
 *
 * XXX: We need a function to free the allocated addresses.
 */
int
VSS_resolve(const char *addr, const char *port, struct vss_addr ***vap)
{
	struct addrinfo hints, *res0, *res;
	struct vss_addr **va;
	int i, ret;
	long int ptst;
	char *adp, *hop;

	*vap = NULL;
	memset(&hints, 0, sizeof hints);
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	ret = VSS_parse(addr, &hop, &adp);
	if (ret)
		return (0);

	if (adp == NULL)
		ret = getaddrinfo(addr, port, &hints, &res0);
	else {
		ptst = strtol(adp,NULL,10);
		if (ptst < 0 || ptst > 65535)
			return(0);
		ret = getaddrinfo(hop, adp, &hints, &res0);
	}

	free(hop);
	free(adp);

	if (ret != 0)
		return (0);

	XXXAN(res0);
	for (res = res0, i = 0; res != NULL; res = res->ai_next, ++i)
		/* nothing */ ;
	if (i == 0) {
		freeaddrinfo(res0);
		return (0);
	}
	va = calloc(i, sizeof *va);
	XXXAN(va);
	*vap = va;
	for (res = res0, i = 0; res != NULL; res = res->ai_next, ++i) {
		va[i] = calloc(1, sizeof(**va));
		XXXAN(va[i]);
		va[i]->va_family = res->ai_family;
		va[i]->va_socktype = res->ai_socktype;
		va[i]->va_protocol = res->ai_protocol;
		va[i]->va_addrlen = res->ai_addrlen;
		assert(va[i]->va_addrlen <= sizeof va[i]->va_addr);
		memcpy(&va[i]->va_addr, res->ai_addr, va[i]->va_addrlen);
	}
	freeaddrinfo(res0);
	return (i);
}

/*
 * Given a struct vss_addr, open a socket of the appropriate type, and bind
 * it to the requested address.
 *
 * If the address is an IPv6 address, the IPV6_V6ONLY option is set to
 * avoid conflicts between INADDR_ANY and IN6ADDR_ANY.
 */

int
VSS_bind(const struct vss_addr *va)
{
	int sd, val;

	sd = socket(va->va_family, va->va_socktype, va->va_protocol);
	if (sd < 0) {
		perror("socket()");
		return (-1);
	}
	val = 1;
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof val) != 0) {
		perror("setsockopt(SO_REUSEADDR, 1)");
		(void)close(sd);
		return (-1);
	}
#ifdef IPV6_V6ONLY
	/* forcibly use separate sockets for IPv4 and IPv6 */
	val = 1;
	if (va->va_family == AF_INET6 &&
	    setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof val) != 0) {
		perror("setsockopt(IPV6_V6ONLY, 1)");
		(void)close(sd);
		return (-1);
	}
#endif
	if (bind(sd, (const void*)&va->va_addr, va->va_addrlen) != 0) {
		perror("bind()");
		(void)close(sd);
		return (-1);
	}
	return (sd);
}

static const struct linger linger = { 0, 0 };
static int	lfd = -1;

int nwrk;
int nsp[16];

static void
showMe(int no)
{
	int i;

	printf("%p %d [", (void *)pthread_self(), no);
	for (i = 0; i < nwrk; i++)
		printf("%d ", nsp[i]);
	printf("]\n");
}

static int
toMe(int no)
{
	int i, m, j = -1, jv = 1024;

	for (i = 0; i < nwrk - 1; i++) {
		m = MIN(nsp[i], nsp[i + 1]);
		if (m < jv) {
			if (m == nsp[i]) {
				j = i;
				jv = nsp[i];
			} else {
				j = i + 1;
				jv = nsp[i + 1];
			}
		}
	}
	assert(j != -1);
	if (j == no)
		return (1);
	return (0);
}

static void
http_read_cb(struct bufferevent *bev, void *ctx)
{
    /* struct evbuffer *input = bufferevent_get_input(bev); */
    struct evbuffer *output = bufferevent_get_output(bev);
	const char msg[] = "HTTP/1.1 200 OK\r\n"
		"Date: Thu, 25 Oct 2012 18:28:34 GMT\r\n"
		"Content-Length: 1\r\n"
		"\r\n"
		"A";

    evbuffer_add_printf(output, "%s", msg);
}

static void
http_event_cb(struct bufferevent *bev, short events, void *ctx)
{
    if (events & BEV_EVENT_ERROR)
        perror("Error from bufferevent");
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        bufferevent_free(bev);
    }
}

static void
accept_conn_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *address, int socklen, void *ctx)
{
    struct event_base *base = evconnlistener_get_base(listener);
    struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);

    bufferevent_setcb(bev, http_read_cb, NULL, http_event_cb, NULL);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
}

static void
accept_error_cb(struct evconnlistener *listener, void *ctx)
{
    struct event_base *base = evconnlistener_get_base(listener);
    int err = EVUTIL_SOCKET_ERROR();
    fprintf(stderr, "Got an error %d (%s) on the listener. "
            "Shutting down.\n", err, evutil_socket_error_to_string(err));

    event_base_loopexit(base, NULL);
}

static void *
WRK_thread(void *arg)
{
    struct event_base *base;
    struct evconnlistener *listener;
    struct sockaddr_in sin;

	struct sesshead sh;
	struct sess *sp;
	struct sockaddr_storage addr_s;
	struct sockaddr *addr;
	socklen_t l;
	int efd, i, n, r;
	struct sched_param p;
	int no, need_accept;
#ifdef LINUX
    cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(nwrk++, &cpuset);
	AZ(pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset));

	no = sched_getcpu();
	printf("NWRK %d CPU %d\n", nwrk, no);

	p.sched_priority = sched_get_priority_max(SCHED_RR);
	AZ(sched_setscheduler(0, SCHED_RR, &p));
#endif

    base = event_base_new();
	assert(base != 0);

    listener = evconnlistener_new(base, accept_conn_cb, NULL, LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, 0, lfd);
    assert(listener != 0);

    evconnlistener_set_error_cb(listener, accept_error_cb);

    event_base_dispatch(base);
}

int
VTCP_nonblocking(int sock)
{
	int i, j;

	i = 1;
	j = ioctl(sock, FIONBIO, &i);
	return (j);
}

int
main(void)
{
	struct vss_addr **ta;
	pthread_t tp;
	int n;

	n = VSS_resolve("127.0.0.1:8085", "http", &ta);
	assert(n >= 0);
	lfd = VSS_bind(ta[0]);
	assert(lfd >= 0);
	AZ(listen(lfd, 64 * 1024));
	AZ(setsockopt(lfd, SOL_SOCKET, SO_LINGER, &linger, sizeof linger));
	AZ(VTCP_nonblocking(lfd));

	AZ(pthread_create(&tp, NULL, WRK_thread, NULL));
	AZ(pthread_create(&tp, NULL, WRK_thread, NULL));
	/* AZ(pthread_create(&tp, NULL, WRK_thread, NULL));
	AZ(pthread_create(&tp, NULL, WRK_thread, NULL));
    */

	while (1) {
		sleep(10000);
	}
}
