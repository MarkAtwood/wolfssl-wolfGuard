/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * Portions Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 *
 * Handshake message layout, computed from the suite in force rather than fixed
 * at compile time.
 *
 * The packed message_handshake_* structs this replaces made every field offset
 * a compile-time constant, which is correct for exactly one suite. Two things
 * move the handshake messages around: the public key encoding, which sets the
 * ephemeral field and the plaintext of encrypted_static, and the hash, which
 * sets the MAC length and the cookie. message_data does not move under either,
 * so it keeps its struct.
 *
 * Unlike the Go wire package this mirrors, nothing here copies. Go parses into
 * a struct of its own; a kernel module cannot, because Kbuild sets
 * -Wframe-larger-than=2048 and a parsed initiation is 246 bytes today and
 * around 1100 under a post-quantum suite, which with the rest of a frame gets
 * uncomfortable. So a view is a set of pointers into the caller's buffer, and
 * both parsing and building go through the same view.
 *
 * Scalars are read and written with the unaligned helpers. The packed structs
 * got away without them by construction; a pointer into skb->data has no such
 * guarantee, and the integer fields sit at offset 4 and 8 of a UDP payload
 * whose alignment is not ours to assume.
 */

#ifndef _WG_WIRE_H
#define _WG_WIRE_H

#include <linux/kernel.h>
#include <linux/types.h>
/* The unaligned helpers moved from asm/ to linux/ during the 6.12 cycle, and
 * this tree builds against kernels on both sides of that. __has_include rather
 * than a version test, matching wolfcrypt_glue.h, because a vendor kernel's
 * version number says little about which headers it carries.
 */
#if defined(__has_include)
#if __has_include(<linux/unaligned.h>)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif
#else
#include <asm/unaligned.h>
#endif

#include "messages.h"

/* The lengths a suite contributes to the wire format. Everything else about a
 * message is fixed: the 4-byte header, the index fields, and the timestamp
 * plaintext.
 */
struct wg_wire_layout {
	u16 public_key_len;   /* ephemeral, and the plaintext of encrypted_static */
	u16 private_key_len;  /* not wire-facing; sizes handshake state */
	u16 hash_len;         /* transcript hash and chaining key; not wire-facing */
	/* The hash ALGORITHM, as a wolfCrypt enum wc_HashType. Strictly this is
	 * not a length and so not a wire layout, but the layout is what gets
	 * threaded to every site that needs it, and splitting the two would
	 * mean passing both everywhere for no gain. The same value serves
	 * hashing and HMAC, since wc_hmac_oneshot takes a wc_HashType.
	 */
	int hash_type;
	u16 authtag_len;      /* AEAD tag on each encrypted field */
	u16 mac_len;          /* mac1 and mac2, each */
	u16 cookie_len;       /* the cookie value inside a cookie reply */
	u16 cookie_nonce_len; /* the cookie reply's nonce */
};

/* The maxima over every suite this module knows, used to SIZE state that is
 * not wire-facing. Handshake state is sized by these and used to the suite's
 * length, so one struct serves every suite and nothing is reallocated per
 * handshake.
 *
 * The distinction that keeps this honest: sizeof on one of those arrays is its
 * CAPACITY and stays correct for zeroing and for bounds. A length handed to a
 * crypto call is a SEMANTIC length and must come from the suite, because after
 * max-sizing the two are no longer the same number. WOLFGUARD-AGILITY-6ytx.25
 * is exactly that substitution.
 */
#define WG_MAX_PUBLIC_KEY_LEN NOISE_PUBLIC_KEY_LEN
#define WG_MAX_PRIVATE_KEY_LEN NOISE_PRIVATE_KEY_LEN
/* 48, a SHA-384 digest, not NOISE_HASH_LEN. Every buffer holding a transcript
 * hash, chaining key, or a key derived from one is sized by this and used to
 * the suite's hash_len. Raising it is what lets a SHA-384 suite coexist with
 * the SHA-256 one in the same build.
 */
#define WG_MAX_HASH_LEN 48

/* The layout of the single suite compiled into this module. Per-suite tables
 * are WOLFGUARD-AGILITY-6ytx.26 and .27; this bead lands the mechanism and
 * wires it to the one suite, so that routing by length has something to route
 * to.
 */
extern const struct wg_wire_layout wg_wire_compiled_layout;

/* Field widths that no suite changes. */
enum wg_wire_fixed {
	WG_WIRE_HEADER_LEN = 4,
	WG_WIRE_INDEX_LEN = 4,
	WG_WIRE_TIMESTAMP_LEN = NOISE_TIMESTAMP_LEN,
};

static inline size_t wg_wire_encrypted(const struct wg_wire_layout *l,
				       size_t plain_len)
{
	return plain_len + l->authtag_len;
}

static inline size_t wg_wire_initiation_size(const struct wg_wire_layout *l)
{
	return WG_WIRE_HEADER_LEN + WG_WIRE_INDEX_LEN +
	       l->public_key_len +
	       wg_wire_encrypted(l, l->public_key_len) +
	       wg_wire_encrypted(l, WG_WIRE_TIMESTAMP_LEN) +
	       2 * (size_t)l->mac_len;
}

static inline size_t wg_wire_response_size(const struct wg_wire_layout *l)
{
	return WG_WIRE_HEADER_LEN + 2 * (size_t)WG_WIRE_INDEX_LEN +
	       l->public_key_len +
	       wg_wire_encrypted(l, 0) +
	       2 * (size_t)l->mac_len;
}

static inline size_t wg_wire_cookie_size(const struct wg_wire_layout *l)
{
	return WG_WIRE_HEADER_LEN + WG_WIRE_INDEX_LEN +
	       l->cookie_nonce_len +
	       wg_wire_encrypted(l, l->cookie_len);
}

/* The MACs are the last two fields of both handshake messages, so their
 * offsets come from the message length. cookie.c works in these terms because
 * it does not care which of the two message types it is covering.
 */
static inline size_t wg_wire_mac1_offset(const struct wg_wire_layout *l,
					 size_t msg_len)
{
	return msg_len - 2 * (size_t)l->mac_len;
}

static inline size_t wg_wire_mac2_offset(const struct wg_wire_layout *l,
					 size_t msg_len)
{
	return msg_len - (size_t)l->mac_len;
}

/* The largest handshake message any supported suite can frame, for stack
 * buffers on the send path. Derived from the compiled layout for now; when a
 * second suite arrives this becomes a max over the table, and the build will
 * fail loudly here rather than overflow a buffer, because the buffers are
 * sized by this and checked against the runtime length.
 */
#define WG_WIRE_MAX_PUBLIC_KEY_LEN WG_PUBLIC_KEY_LEN
/* 48, not NOISE_HASH_LEN: the MACs are hash-length, so a SHA-384 suite makes
 * them 48 and the maximum handshake 282 bytes. Left at 32 this evaluates to
 * 250, which is SHORTER than a 278-byte SHA-384 initiation, and the send path
 * would refuse to frame one.
 */
#define WG_WIRE_MAX_MAC_LEN WG_MAX_HASH_LEN
#define WG_WIRE_MAX_HANDSHAKE_LEN                                            \
	(WG_WIRE_HEADER_LEN + 2 * WG_WIRE_INDEX_LEN +                        \
	 WG_WIRE_MAX_PUBLIC_KEY_LEN +                                        \
	 (WG_WIRE_MAX_PUBLIC_KEY_LEN + NOISE_AUTHTAG_LEN) +                  \
	 (NOISE_TIMESTAMP_LEN + NOISE_AUTHTAG_LEN) +                         \
	 2 * WG_WIRE_MAX_MAC_LEN)

/* Views. Each field points into the caller's buffer; none of this owns
 * anything, and a view is only valid while that buffer is.
 */
struct wg_initiation_view {
	u8 *sender_index;
	u8 *unencrypted_ephemeral;
	u8 *encrypted_static;
	u8 *encrypted_timestamp;
	u8 *mac1;
	u8 *mac2;
};

struct wg_response_view {
	u8 *sender_index;
	u8 *receiver_index;
	u8 *unencrypted_ephemeral;
	u8 *encrypted_nothing;
	u8 *mac1;
	u8 *mac2;
};

struct wg_cookie_view {
	u8 *receiver_index;
	u8 *nonce;
	u8 *encrypted_cookie;
};

/* Scalar access. The buffer's alignment is not ours to assume. */
static inline __le32 wg_wire_get_index(const u8 *p)
{
	return get_unaligned((const __le32 *)p);
}

static inline void wg_wire_set_index(u8 *p, __le32 v)
{
	put_unaligned(v, (__le32 *)p);
}

/* Point a view at a buffer. The length is checked against the layout, so a
 * caller that has already routed by length gets a second, cheap confirmation
 * that it routed to the right place.
 */
bool wg_wire_view_initiation(struct wg_initiation_view *v,
			     const struct wg_wire_layout *l,
			     u8 *data, size_t len);
bool wg_wire_view_response(struct wg_response_view *v,
			   const struct wg_wire_layout *l,
			   u8 *data, size_t len);
bool wg_wire_view_cookie(struct wg_cookie_view *v,
			 const struct wg_wire_layout *l,
			 u8 *data, size_t len);

/* Write a message header. Build paths call this first, then fill the view. */
void wg_wire_put_header(u8 *data, enum message_type type);

/* A suite, as far as the wire is concerned: an identifier and the lengths it
 * contributes. The per-suite transcript tables, which is the rest of what a
 * suite means, are 6ytx.26 and .27. The layout is a pointer rather than a
 * value so there is exactly one definition of each suite's lengths.
 */
struct wg_suite {
	u8 id;
	const char *name;
	const struct wg_wire_layout *layout;
};

enum wg_suite_ids {
	WG_SUITE_NONE = 0,
	WG_SUITE_LEGACY = 1,
	WG_SUITE_SHA384 = 2,
};

extern const struct wg_suite wg_suite_legacy;
extern const struct wg_suite wg_suite_sha384;

/* Every suite this module knows how to speak, as opposed to the per-device
 * accept set below, which is the subset a given device will answer for.
 * wg_noise_init precomputes a transcript starting state for each of these.
 */
extern const struct wg_suite *const wg_known_suites[];
extern const unsigned int wg_known_suites_n;

/* Small enough that the index is a linear scan. There is no point in a hash
 * table for a handful of entries, and the scan runs once per handshake packet,
 * not per data packet.
 */
enum { WG_MAX_SUITES = 4 };

/* The per-device accept set, indexed by nothing: a scan is the index. An
 * inbound handshake is routed to a suite by its length, so this is what
 * decides which suites a device will answer for.
 */
struct wg_suite_index {
	u8 n;
	const struct wg_suite *suites[WG_MAX_SUITES];
};

void wg_suite_index_init(struct wg_suite_index *ix);

/* Add a suite to a device's accept set.
 *
 * Returns -EEXIST when the suite's initiation or response length already
 * belongs to another suite in the set. Routing is BY LENGTH, so two suites
 * that frame the same initiation size are not distinguishable, and accepting
 * both would mean parsing a packet under whichever happened to be registered
 * first while its MACs were computed under the other. Refusing loudly here is
 * the whole reason this returns an error.
 *
 * Cookie reply lengths are deliberately NOT part of that test; see the comment
 * on wg_suite_for_length.
 */
int wg_suite_index_add(struct wg_suite_index *ix, const struct wg_suite *s);

/* Resolve an inbound handshake to a suite by its type and length, or NULL.
 *
 * Initiation and response are unambiguous, because wg_suite_index_add refuses
 * a set in which they collide.
 *
 * A cookie reply is different and this returns the FIRST match for it. A
 * cookie reply carries no public key, so two suites differing only in key
 * encoding frame identical cookie replies, which is exactly what 6ytx.22
 * proposes to serve from one build. That is fine here because the only thing
 * this resolution is used for on the cookie path is the pull length, which is
 * equal by construction in that case. The suite a cookie reply actually
 * belongs to comes from its receiver_index, which identifies the handshake and
 * therefore the suite it was begun under. 6ytx.22 has to wire that up; with
 * one suite there is nothing to get wrong.
 */
const struct wg_suite *wg_suite_for_length(const struct wg_suite_index *ix,
					   enum message_type type, size_t len);

const struct wg_suite *wg_suite_by_id(const struct wg_suite_index *ix, u8 id);

/* The suite's slot in this index, or -1. Per-suite state that a device holds,
 * such as the cookie keys, is indexed by this rather than by suite id, so the
 * arrays stay WG_MAX_SUITES wide instead of as wide as the id space.
 */
int wg_suite_slot(const struct wg_suite_index *ix, u8 id);

#ifdef DEBUG
bool wg_wire_selftest(void);
#endif

#endif /* _WG_WIRE_H */
