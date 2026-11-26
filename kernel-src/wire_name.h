/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2026 wolfSSL Inc. All Rights Reserved.
 */

#ifndef _WG_WIRE_NAME_H
#define _WG_WIRE_NAME_H

#include <linux/types.h>

/* The handshake name carried with an initiation.
 *
 * A dynamic name leads with a colon and names three primitives, for example
 * ":P-256:HKDF-SHA-384:AEAD_AES_256_GCM". The string is at once the identifier,
 * the description and the domain separator: it is hashed into the initial
 * chaining key, so altering it in flight makes every derived key wrong and the
 * handshake fails. Nothing is registered or allocated to add a primitive.
 *
 * The two frozen construction strings carry no leading colon and travel with no
 * name at all, which is what keeps a deployed peer byte-identical.
 *
 * This is the kernel half of handshakename/ in the Go tree and must accept
 * exactly what that package accepts. The grammar is deliberately hostile
 * because a name is read before anything in the packet is authenticated: mac1
 * is keyed on the responder's static public key, which is not secret from
 * anyone intending to talk to it.
 */

/* WG_NAME_LEAD is the first byte of every dynamic name. */
#define WG_NAME_LEAD ':'

/* WG_NAME_MAX_LEN caps the encoded length. Names from the public registries run
 * to roughly forty bytes; the cap leaves room for a hybrid key exchange such as
 * "X25519+ML-KEM-768" without inviting a peer to spend the receiver's budget on
 * an unauthenticated path. Must equal handshakename.MaxLen.
 */
#define WG_NAME_MAX_LEN 96

/* WG_NAME_MIN_LEN is the shortest syntactically possible name, a lead and three
 * single-character fields: ":a:b:c". Must equal handshakename.MinLen.
 */
#define WG_NAME_MIN_LEN 6

/* WG_NAME_FIELDS is how many primitives a name carries: key exchange, KDF,
 * AEAD.
 */
#define WG_NAME_FIELDS 3

/* wg_wire_name_valid checks a dynamic name against the grammar.
 *
 * Validating is not authorising: a syntactically valid name may still be one
 * this device does not serve, which the caller decides by looking it up in the
 * accept set.
 */
bool wg_wire_name_valid(const u8 *name, size_t len);

/* wg_wire_name_is_dynamic reports whether a construction string announces
 * itself on the wire, which is to say whether it leads with a colon.
 */
static inline bool wg_wire_name_is_dynamic(const char *name)
{
	return name && name[0] == WG_NAME_LEAD;
}

#endif /* _WG_WIRE_NAME_H */
