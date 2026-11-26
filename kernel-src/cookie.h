/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * Portions Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 */

#ifndef _WG_COOKIE_H
#define _WG_COOKIE_H

#include "messages.h"
#include "wire.h"
#include <linux/rwsem.h>

struct wg_peer;

/* The mac1 and cookie keys are HASH DIGESTS of the device's public key, so
 * their length is the suite's hash length: 32 under SHA-256 and 48 under
 * SHA-384. A device serving both therefore needs one set per suite, indexed by
 * the suite's slot in the device's accept set (wg_suite_slot). Holding a
 * single set is what would break the moment a second hash is accepted, and is
 * the substance of WOLFGUARD-AGILITY-6ytx.27.
 */
struct cookie_checker_keys {
	u8 cookie_encryption_key[WG_MAX_HASH_LEN];
	u8 message_mac1_key[WG_MAX_HASH_LEN];
};

struct cookie_checker {
	/* Device-wide random, read at the suite's hash length. */
	u8 secret[WG_MAX_HASH_LEN];
	struct cookie_checker_keys per_suite[WG_MAX_SUITES];
	u64 secret_birthdate;
	struct rw_semaphore secret_lock;
	struct wg_device *device;
};

/* Per peer, and every field here is hash-length dependent: the cookie value,
 * the mac1 we last sent, and the two keys derived from the peer's public key.
 * All sized by the maximum and used to the suite's hash length.
 */
struct cookie {
	u64 birthdate;
	bool is_valid;
	u8 cookie[WG_MAX_HASH_LEN];
	bool have_sent_mac1;
	u8 last_mac1_sent[WG_MAX_HASH_LEN];
	/* One set per suite, for the same reason the device has one set per
	 * suite: these are digests of the PEER's public key under a suite's
	 * hash, so they differ per suite. A peer's suite is not known when the
	 * peer is created, only once a handshake resolves one, so deriving a
	 * single set at creation time leaves it stale the moment a handshake
	 * arrives under a different suite.
	 */
	struct cookie_checker_keys per_suite[WG_MAX_SUITES];
	struct rw_semaphore lock;
};

enum cookie_mac_state {
	INVALID_MAC,
	VALID_MAC_BUT_NO_COOKIE,
	VALID_MAC_WITH_COOKIE_BUT_RATELIMITED,
	VALID_MAC_WITH_COOKIE
};

int __must_check wg_cookie_checker_init(struct cookie_checker *checker,
			    struct wg_device *wg);
int __must_check wg_cookie_checker_precompute_device_keys(struct cookie_checker *checker);
int __must_check wg_cookie_checker_precompute_peer_keys(struct wg_peer *peer);
void wg_cookie_init(struct cookie *cookie);

enum cookie_mac_state __must_check wg_cookie_validate_packet(struct cookie_checker *checker,
						struct sk_buff *skb,
						bool check_cookie);
int __must_check wg_cookie_add_mac_to_packet(void *message, size_t len,
				 struct wg_peer *peer);

int __must_check wg_cookie_message_create(u8 *dst, size_t dst_len,
			      struct sk_buff *skb, __le32 index,
			      struct cookie_checker *checker);
int __must_check wg_cookie_message_consume(const struct wg_cookie_view *src,
			       const struct wg_wire_layout *l,
			       struct wg_device *wg);

#endif /* _WG_COOKIE_H */
