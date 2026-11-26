// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * Portions Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 */

#include "wire.h"
#include "wire_name.h"

#include <linux/string.h>

#include <linux/build_bug.h>

/* The sizes this layout must produce, asserted at build time.
 *
 * The oracle is not this file: 246, 157 and 72 are what the Go and Rust
 * implementations frame for this suite, confirmed by the interop matrix in
 * WOLFGUARD-AGILITY's kernel-rig, where a wrong size shows up as a failed
 * handshake against them rather than as a warning here. Asserting them keeps a
 * later edit to the layout arithmetic from quietly changing the wire and
 * sending someone back to the rig to find out why.
 *
 * Written out longhand rather than calling the size functions, because those
 * take a pointer to a const struct and so are not constant expressions.
 */
#define WG_WIRE_ASSERT_INITIATION                                            \
	(WG_WIRE_HEADER_LEN + WG_WIRE_INDEX_LEN + NOISE_PUBLIC_KEY_LEN +     \
	 (NOISE_PUBLIC_KEY_LEN + NOISE_AUTHTAG_LEN) +                        \
	 (NOISE_TIMESTAMP_LEN + NOISE_AUTHTAG_LEN) + 2 * COOKIE_LEN)
#define WG_WIRE_ASSERT_RESPONSE                                              \
	(WG_WIRE_HEADER_LEN + 2 * WG_WIRE_INDEX_LEN + NOISE_PUBLIC_KEY_LEN + \
	 NOISE_AUTHTAG_LEN + 2 * COOKIE_LEN)
#define WG_WIRE_ASSERT_COOKIE                                                \
	(WG_WIRE_HEADER_LEN + WG_WIRE_INDEX_LEN + COOKIE_NONCE_LEN +         \
	 (COOKIE_LEN + NOISE_AUTHTAG_LEN))

static_assert(WG_WIRE_ASSERT_INITIATION == 246,
	      "initiation size changed; Go and Rust frame 246 for this suite");
static_assert(WG_WIRE_ASSERT_RESPONSE == 157,
	      "response size changed; Go and Rust frame 157 for this suite");
static_assert(WG_WIRE_ASSERT_COOKIE == 72,
	      "cookie reply size changed; Go and Rust frame 72 for this suite");

/* And the max used for send-side stack buffers has to actually cover them. */
static_assert(WG_WIRE_MAX_HANDSHAKE_LEN >= WG_WIRE_ASSERT_INITIATION,
	      "max handshake buffer is smaller than an initiation");
static_assert(WG_WIRE_MAX_HANDSHAKE_LEN >= WG_WIRE_ASSERT_RESPONSE,
	      "max handshake buffer is smaller than a response");
static_assert(WG_WIRE_MAX_HANDSHAKE_LEN >= WG_WIRE_ASSERT_COOKIE,
	      "max handshake buffer is smaller than a cookie reply");

/* The suite this module is built for. NOISE_PUBLIC_KEY_LEN is an uncompressed
 * SECP256R1 point, COOKIE_LEN and the MAC length are a SHA-256 digest, and the
 * AEAD is AES-GCM, so:
 *
 *   initiation  4 + 4 + 65 + (65+16) + (12+16) + 32 + 32 = 246
 *   response    4 + 4 + 4  + 65 + 16 + 32 + 32           = 157
 *   cookie      4 + 4 + 16 + (32+16)                     =  72
 *
 * Those three numbers are what the Go and Rust implementations frame for the
 * same suite, and the interop matrix checks it.
 */
const struct wg_wire_layout wg_wire_compiled_layout = {
	.public_key_len = NOISE_PUBLIC_KEY_LEN,
	.private_key_len = NOISE_PRIVATE_KEY_LEN,
	.hash_len = NOISE_HASH_LEN,
	.hash_type = WC_SHA256,
	.authtag_len = NOISE_AUTHTAG_LEN,
	.mac_len = COOKIE_LEN,
	.cookie_len = COOKIE_LEN,
	.cookie_nonce_len = COOKIE_NONCE_LEN,
};

void wg_wire_put_header(u8 *data, enum message_type type)
{
	/* Little endian encoding of the type gives the 1-byte type plus three
	 * reserved zero bytes that the format calls for, which is why the
	 * header is a __le32 and not four separate fields.
	 */
	wg_wire_set_index(data, cpu_to_le32(type));
}

bool wg_wire_view_initiation(struct wg_initiation_view *v,
			     const struct wg_wire_layout *l,
			     u8 *data, size_t len)
{
	size_t off = WG_WIRE_HEADER_LEN;

	if (unlikely(len != wg_wire_initiation_size(l)))
		return false;

	v->sender_index = data + off;
	off += WG_WIRE_INDEX_LEN;
	v->unencrypted_ephemeral = data + off;
	off += l->public_key_len;
	v->encrypted_static = data + off;
	off += wg_wire_encrypted(l, l->public_key_len);
	v->encrypted_timestamp = data + off;
	off += wg_wire_encrypted(l, WG_WIRE_TIMESTAMP_LEN);
	v->mac1 = data + off;
	off += l->mac_len;
	v->mac2 = data + off;
	off += l->mac_len;

	/* The walk and the size function have to agree, or one of them is
	 * wrong and every peer on the other side of this suite sees garbage.
	 */
	WARN_ON_ONCE(off != len);
	return true;
}

bool wg_wire_view_response(struct wg_response_view *v,
			   const struct wg_wire_layout *l,
			   u8 *data, size_t len)
{
	size_t off = WG_WIRE_HEADER_LEN;

	if (unlikely(len != wg_wire_response_size(l)))
		return false;

	v->sender_index = data + off;
	off += WG_WIRE_INDEX_LEN;
	v->receiver_index = data + off;
	off += WG_WIRE_INDEX_LEN;
	v->unencrypted_ephemeral = data + off;
	off += l->public_key_len;
	v->encrypted_nothing = data + off;
	off += wg_wire_encrypted(l, 0);
	v->mac1 = data + off;
	off += l->mac_len;
	v->mac2 = data + off;
	off += l->mac_len;

	WARN_ON_ONCE(off != len);
	return true;
}

bool wg_wire_view_cookie(struct wg_cookie_view *v,
			 const struct wg_wire_layout *l,
			 u8 *data, size_t len)
{
	size_t off = WG_WIRE_HEADER_LEN;

	if (unlikely(len != wg_wire_cookie_size(l)))
		return false;

	v->receiver_index = data + off;
	off += WG_WIRE_INDEX_LEN;
	v->nonce = data + off;
	off += l->cookie_nonce_len;
	v->encrypted_cookie = data + off;
	off += wg_wire_encrypted(l, l->cookie_len);

	WARN_ON_ONCE(off != len);
	return true;
}

const struct wg_suite wg_suite_legacy = {
	.id = WG_SUITE_LEGACY,
	.name = "Noise_IKpsk2_SECP256R1_AesGcm_SHA256",
	.layout = &wg_wire_compiled_layout,
};

/* SHA-384 with the same P-256 key encoding and AES-GCM. Only the hash changes,
 * which moves the MACs and the cookie:
 *
 *   initiation  4 + 4 + 65 + (65+16) + (12+16) + 48 + 48 = 278
 *   response    4 + 4 + 4  + 65 + 16 + 48 + 48           = 189
 *   cookie      4 + 4 + 16 + (48+16)                     =  88
 *
 * 278 and 189 are what the Go and Rust implementations frame for this suite,
 * so the interop matrix checks them against two independent implementations.
 * They differ from the legacy 246 and 157, which is what lets both be served
 * from one build: wg_suite_index_add refuses suites whose handshake lengths
 * collide, since routing has only the length to go on.
 */
static const struct wg_wire_layout sha384_layout = {
	.public_key_len = NOISE_PUBLIC_KEY_LEN,
	.private_key_len = NOISE_PRIVATE_KEY_LEN,
	.hash_len = WC_SHA384_DIGEST_SIZE,
	.hash_type = WC_SHA384,
	.authtag_len = NOISE_AUTHTAG_LEN,
	.mac_len = WC_SHA384_DIGEST_SIZE,
	.cookie_len = WC_SHA384_DIGEST_SIZE,
	.cookie_nonce_len = COOKIE_NONCE_LEN,
};

const struct wg_suite wg_suite_sha384 = {
	.id = WG_SUITE_SHA384,
	.name = ":P-256:HKDF-SHA-384:AEAD_AES_256_GCM",
	.layout = &sha384_layout,
};

const struct wg_suite *const wg_known_suites[] = {
	&wg_suite_legacy,
	&wg_suite_sha384,
};
const unsigned int wg_known_suites_n = ARRAY_SIZE(wg_known_suites);

void wg_suite_index_init(struct wg_suite_index *ix)
{
	memset(ix, 0, sizeof(*ix));
}

int wg_suite_index_add(struct wg_suite_index *ix, const struct wg_suite *s)
{
	size_t init_len = wg_wire_initiation_size(s->layout);
	size_t resp_len = wg_wire_response_size(s->layout);
	u8 i;

	if (unlikely(ix->n >= WG_MAX_SUITES))
		return -ENOSPC;

	/* Anything without a dynamic name is resolved by length, so admitting an
	 * arbitrary one would rebuild the routing table this design removes. The
	 * set is the two deployed construction strings and is closed.
	 */
	if (!wg_wire_name_is_dynamic(s->name) && !wg_suite_is_frozen_nameless(s)) {
		pr_err("wolfguard: refusing suite %s: it carries no leading colon and is not one of the two frozen constructions, so nothing on the wire would identify it\n",
		       s->name);
		return -EINVAL;
	}

	for (i = 0; i < ix->n; ++i) {
		const struct wg_suite *other = ix->suites[i];

		if (unlikely(other->id == s->id))
			return -EEXIST;

		/* Two nameless suites of equal initiation length cannot be told
		 * apart, because length is all the nameless path has.
		 */
		if (unlikely(!wg_wire_name_is_dynamic(s->name) &&
			     !wg_wire_name_is_dynamic(other->name) &&
			     wg_wire_initiation_size(other->layout) == init_len)) {
			pr_err("wolfguard: refusing suite %s: it and %s are both nameless and both frame a %zu byte initiation\n",
			       s->name, other->name, init_len);
			return -EEXIST;
		}

		/* Presence of a name is decided by total length, so a named
		 * suite that happens to arrive at a nameless suite's initiation
		 * size would be read as nameless and fail to authenticate.
		 */
		if (unlikely(wg_wire_name_is_dynamic(s->name) &&
			     !wg_wire_name_is_dynamic(other->name) &&
			     wg_wire_initiation_size(other->layout) ==
				     wg_wire_framed_initiation_size(s))) {
			pr_err("wolfguard: refusing suite %s: framed with its name it is %zu bytes, the length of nameless %s\n",
			       s->name, wg_wire_framed_initiation_size(s), other->name);
			return -EEXIST;
		}
		if (unlikely(!wg_wire_name_is_dynamic(s->name) &&
			     wg_wire_name_is_dynamic(other->name) &&
			     wg_wire_framed_initiation_size(other) == init_len)) {
			pr_err("wolfguard: refusing suite %s: nameless it is %zu bytes, the length %s arrives at framed with its name\n",
			       s->name, init_len, other->name);
			return -EEXIST;
		}
	}

	(void)resp_len;

	ix->suites[ix->n++] = s;
	return 0;
}

const struct wg_suite *wg_suite_by_name(const char *name)
{
	unsigned int i;

	for (i = 0; i < wg_known_suites_n; ++i)
		if (!strcmp(wg_known_suites[i]->name, name))
			return wg_known_suites[i];
	return NULL;
}

int wg_suite_slot(const struct wg_suite_index *ix, u8 id)
{
	u8 i;

	for (i = 0; i < ix->n; ++i)
		if (ix->suites[i]->id == id)
			return (int)i;
	return -1;
}

/* The two construction strings that may travel with no name. Both are
 * deployed, neither can ever change, and that is what makes this list closed
 * rather than merely short: every suite added from here on carries a name, so
 * the nameless path's length comparison cannot grow.
 */
static const char *const frozen_nameless_names[] = {
	"Noise_IKpsk2_SECP256R1_AesGcm_SHA256",  /* wolfGuard FIPS */
	"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s", /* stock WireGuard */
};

bool wg_suite_is_frozen_nameless(const struct wg_suite *s)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(frozen_nameless_names); ++i) {
		if (!strcmp(s->name, frozen_nameless_names[i]))
			return true;
	}
	return false;
}

size_t wg_wire_framed_initiation_size(const struct wg_suite *s)
{
	size_t n = wg_wire_initiation_size(s->layout);

	if (!wg_wire_name_is_dynamic(s->name))
		return n;
	return n + strlen(s->name) + 1;
}

bool wg_wire_split_name_tail(const u8 *data, size_t len, size_t *body_len,
			     u8 *name_out, size_t *name_len)
{
	size_t n;

	if (unlikely(!len))
		return false;

	n = data[len - 1];
	if (unlikely(n < WG_NAME_MIN_LEN || n > WG_NAME_MAX_LEN || len < n + 2))
		return false;
	if (unlikely(!wg_wire_name_valid(data + len - 1 - n, n)))
		return false;

	memcpy(name_out, data + len - 1 - n, n);
	*name_len = n;
	*body_len = len - 1 - n;
	return true;
}

size_t wg_wire_append_name_tail(u8 *data, size_t len, size_t cap,
				const char *name)
{
	size_t n = strlen(name);

	if (unlikely(n < WG_NAME_MIN_LEN || n > WG_NAME_MAX_LEN))
		return 0;
	if (unlikely(len + n + 1 > cap))
		return 0;

	memcpy(data + len, name, n);
	data[len + n] = (u8)n;
	return len + n + 1;
}

const struct wg_suite *wg_suite_by_wire_name(const struct wg_suite_index *ix,
					     const u8 *name, size_t len)
{
	u8 i;

	for (i = 0; i < ix->n; ++i) {
		const struct wg_suite *s = ix->suites[i];

		if (!wg_wire_name_is_dynamic(s->name))
			continue;
		if (strlen(s->name) == len && !memcmp(s->name, name, len))
			return s;
	}
	return NULL;
}

const struct wg_suite *wg_suite_nameless_for_length(const struct wg_suite_index *ix,
						    size_t len)
{
	u8 i;

	for (i = 0; i < ix->n; ++i) {
		const struct wg_suite *s = ix->suites[i];

		if (wg_wire_name_is_dynamic(s->name))
			continue;
		if (wg_wire_initiation_size(s->layout) == len)
			return s;
	}
	return NULL;
}

bool wg_suite_index_admits_handshake(const struct wg_suite_index *ix,
				     enum message_type type, size_t len)
{
	u8 i;

	for (i = 0; i < ix->n; ++i) {
		const struct wg_suite *s = ix->suites[i];

		switch (type) {
		case MESSAGE_HANDSHAKE_INITIATION:
			if (wg_wire_framed_initiation_size(s) == len)
				return true;
			break;
		case MESSAGE_HANDSHAKE_RESPONSE:
			if (wg_wire_response_size(s->layout) == len)
				return true;
			break;
		case MESSAGE_HANDSHAKE_COOKIE:
			if (wg_wire_cookie_size(s->layout) == len)
				return true;
			break;
		default:
			return false;
		}
	}
	return false;
}

bool wg_wire_receiver_index(enum message_type type, const u8 *data, size_t len,
			    __le32 *out)
{
	size_t off;

	switch (type) {
	case MESSAGE_HANDSHAKE_RESPONSE:
		/* type, sender, then receiver. */
		off = WG_WIRE_HEADER_LEN + WG_WIRE_INDEX_LEN;
		break;
	case MESSAGE_HANDSHAKE_COOKIE:
		/* type, then receiver. */
		off = WG_WIRE_HEADER_LEN;
		break;
	default:
		return false;
	}

	if (unlikely(len < off + WG_WIRE_INDEX_LEN))
		return false;
	*out = wg_wire_get_index(data + off);
	return true;
}

const struct wg_suite *wg_suite_by_id(const struct wg_suite_index *ix, u8 id)
{
	u8 i;

	for (i = 0; i < ix->n; ++i)
		if (ix->suites[i]->id == id)
			return ix->suites[i];
	return NULL;
}

#include "selftest/wire.c"
