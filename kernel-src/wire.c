// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * Portions Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 */

#include "wire.h"

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

#include "selftest/wire.c"
