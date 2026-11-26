/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef CONTAINERS_H
#define CONTAINERS_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#if defined(__linux__)
#include "../kernel-src/uapi/wolfguard.h"
#elif defined(__OpenBSD__)
#include <net/if_wg.h>
#endif

#ifndef WG_CURVE_ID
    /* exact duplicate of settings in kernel-src/uapi/wolfguard.h */
    #define WG_CURVE_ID ECC_SECP256R1
    #ifdef WG_USE_PUBLIC_KEY_COMPRESSION
        #define WG_PUBLIC_KEY_LEN 33 /* Size of compressed SECP256R1 public key */
        #define WG_PUBLIC_KEY_COMPRESSED 1
        #define WG_HANDSHAKE_NAME "Noise_IKpsk2_SECP256R1_C_AesGcm_SHA256"
    #else
        #define WG_PUBLIC_KEY_LEN 65 /* Size of uncompressed SECP256R1 public key */
        #define WG_PUBLIC_KEY_COMPRESSED 0
        #define WG_HANDSHAKE_NAME "Noise_IKpsk2_SECP256R1_AesGcm_SHA256"
    #endif
    #define WG_PRIVATE_KEY_LEN 32 /* Size of SECP256R1 private key */
    #define WG_SYMMETRIC_KEY_LEN 32 /* AES_256_KEY_SIZE */
#endif

#define WG_KEY_LEN_MAX ((WG_PUBLIC_KEY_LEN > WG_PRIVATE_KEY_LEN) ?     \
                        ((WG_PUBLIC_KEY_LEN > WG_SYMMETRIC_KEY_LEN) ?  \
                         WG_PUBLIC_KEY_LEN :                           \
                         WG_SYMMETRIC_KEY_LEN) :                       \
                        ((WG_PRIVATE_KEY_LEN > WG_SYMMETRIC_KEY_LEN) ? \
                         WG_PRIVATE_KEY_LEN :                          \
                         WG_SYMMETRIC_KEY_LEN))

/* Cross platform __kernel_timespec */
struct timespec64 {
	int64_t tv_sec;
	int64_t tv_nsec;
};

/* One entry of a device's accept set: the set of suites it will answer an
 * inbound handshake for. A list rather than a fixed array because the set is
 * declarative in a config file, the way AllowedIPs is, and the kernel bounds it
 * rather than this tool.
 */
struct wgsuite {
	char name[WG_SUITE_NAME_MAX];
	struct wgsuite *next_suite;
};

struct wgallowedip {
	uint16_t family;
	union {
		struct in_addr ip4;
		struct in6_addr ip6;
	};
	uint8_t cidr;
	struct wgallowedip *next_allowedip;
};

enum {
	WGPEER_REMOVE_ME = 1U << 0,
	WGPEER_REPLACE_ALLOWEDIPS = 1U << 1,
	WGPEER_HAS_PUBLIC_KEY = 1U << 2,
	WGPEER_HAS_PRESHARED_KEY = 1U << 3,
	WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL = 1U << 4,
	WGPEER_HAS_SUITE = 1U << 5
};

struct wgpeer {
	uint32_t flags;

	uint8_t public_key[WG_PUBLIC_KEY_LEN];
	uint8_t preshared_key[WG_SYMMETRIC_KEY_LEN];

	union {
		struct sockaddr addr;
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	} endpoint;

	struct timespec64 last_handshake_time;
	uint64_t rx_bytes, tx_bytes;
	uint16_t persistent_keepalive_interval;

	/* The suite this peer initiates with. Empty means it follows the
	 * device's local suite, which is what an unpinned peer does; during a
	 * migration the two are allowed to differ, and a peer part-way through
	 * may still initiate with the old suite.
	 */
	char suite[WG_SUITE_NAME_MAX];

	struct wgallowedip *first_allowedip, *last_allowedip;
	struct wgpeer *next_peer;
};

enum {
	WGDEVICE_REPLACE_PEERS = 1U << 0,
	WGDEVICE_HAS_PRIVATE_KEY = 1U << 1,
	WGDEVICE_HAS_PUBLIC_KEY = 1U << 2,
	WGDEVICE_HAS_LISTEN_PORT = 1U << 3,
	WGDEVICE_HAS_FWMARK = 1U << 4,
	WGDEVICE_HAS_LOCAL_SUITE = 1U << 5,
	/* Replace the accept set rather than add to it, which is what a config
	 * file means: setconf states the whole configuration, so a suite absent
	 * from the file must stop being served. `wg set` adds instead, so that
	 * accept-suite can bring a second suite up mid-migration without
	 * tearing down the one carrying traffic.
	 */
	WGDEVICE_REPLACE_ACCEPT_SUITES = 1U << 6
};

struct wgdevice {
	char name[IFNAMSIZ];
	uint32_t ifindex;

	uint32_t flags;

	uint8_t public_key[WG_PUBLIC_KEY_LEN];
	uint8_t private_key[WG_PRIVATE_KEY_LEN];

	uint32_t fwmark;
	uint16_t listen_port;

	/* The suite this device initiates with, and the default for a peer that
	 * is not pinned to one.
	 */
	char local_suite[WG_SUITE_NAME_MAX];
	struct wgsuite *first_suite, *last_suite;
	/* Names given to `unaccept-suite`, which are NOT sent as-is: the kernel
	 * has no remove-one operation, so set_main reads the current accept set,
	 * subtracts these, and sends the remainder with the replace flag. Empty
	 * for every other caller.
	 */
	struct wgsuite *first_unaccept_suite, *last_unaccept_suite;

	struct wgpeer *first_peer, *last_peer;
};

#define for_each_wgpeer(__dev, __peer) for ((__peer) = (__dev)->first_peer; (__peer); (__peer) = (__peer)->next_peer)
#define for_each_wgallowedip(__peer, __allowedip) for ((__allowedip) = (__peer)->first_allowedip; (__allowedip); (__allowedip) = (__allowedip)->next_allowedip)

static inline void memzero_explicit(void *p, size_t len) {
    static void *(* const volatile memset_func)(void *, int, size_t) = memset;
    (void)memset_func(p, 0, len);
}

/* Append a name to the accept set. The caller has already decided the name is
 * acceptable; this only bounds it and links it, so the one copy of the list
 * manipulation serves both the parser and set_main.
 */
static inline bool wgdevice_add_accept_suite(struct wgdevice *dev, const char *name)
{
	struct wgsuite *suite = calloc(1, sizeof(*suite));

	if (!suite) {
		perror("calloc");
		return false;
	}
	if (strlen(name) >= sizeof(suite->name)) {
		free(suite);
		return false;
	}
	strcpy(suite->name, name);
	if (!dev->first_suite)
		dev->first_suite = dev->last_suite = suite;
	else {
		dev->last_suite->next_suite = suite;
		dev->last_suite = suite;
	}
	return true;
}

static inline void free_wgdevice(struct wgdevice *dev)
{
	if (!dev)
		return;
	for (struct wgpeer *peer = dev->first_peer, *np = peer ? peer->next_peer : NULL; peer; peer = np, np = peer ? peer->next_peer : NULL) {
		for (struct wgallowedip *allowedip = peer->first_allowedip, *na = allowedip ? allowedip->next_allowedip : NULL; allowedip; allowedip = na, na = allowedip ? allowedip->next_allowedip : NULL)
			free(allowedip);
		memzero_explicit(peer->preshared_key, sizeof peer->preshared_key);
		free(peer);
	}
	for (struct wgsuite *suite = dev->first_suite, *ns = suite ? suite->next_suite : NULL; suite; suite = ns, ns = suite ? suite->next_suite : NULL)
		free(suite);
	for (struct wgsuite *suite = dev->first_unaccept_suite, *ns = suite ? suite->next_suite : NULL; suite; suite = ns, ns = suite ? suite->next_suite : NULL)
		free(suite);
	memzero_explicit(dev->private_key, sizeof dev->private_key);
	free(dev);
}

#endif
