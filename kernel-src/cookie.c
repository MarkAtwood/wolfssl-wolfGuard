// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * Portions Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 */

#include "cookie.h"
#include "wire.h"
#include "queueing.h"
#include "peer.h"
#include "device.h"
#include "messages.h"
#include "ratelimiter.h"
#include "timers.h"

#include <net/ipv6.h>

int wg_cookie_checker_init(struct cookie_checker *checker,
			    struct wg_device *wg)
{
	int ret = wc_get_random_bytes(checker->secret, WG_MAX_HASH_LEN);
	if (ret)
		return ret;
	init_rwsem(&checker->secret_lock);
	checker->secret_birthdate = ktime_get_coarse_boottime_ns();
	checker->device = wg;
	return 0;
}

enum { COOKIE_KEY_LABEL_LEN = 8 };
/* __nonstring attributes added by 71e5da46e7. */
#ifndef __nonstring
	#define __nonstring
#endif
static const u8 mac1_key_label[COOKIE_KEY_LABEL_LEN] __nonstring = "mac1----";
static const u8 cookie_key_label[COOKIE_KEY_LABEL_LEN] __nonstring = "cookie--";

/* The derived key IS a digest of the label and the public key, so its length
 * is the suite's hash length and the algorithm is the suite's.
 */
static int precompute_key(const struct wg_wire_layout *l, u8 *key,
			   const u8 *pubkey,
			   const u8 label[COOKIE_KEY_LABEL_LEN])
{
	return wc_hash_oneshot2(l->hash_type, key, label, COOKIE_KEY_LABEL_LEN,
				pubkey, l->public_key_len);
}

/* Must hold peer->handshake.static_identity->lock */
/* One set of keys per suite the device accepts. They are digests of the
 * device's own public key under that suite's hash, so two suites with
 * different hashes have different keys and a single set cannot serve both.
 */
int __must_check wg_cookie_checker_precompute_device_keys(struct cookie_checker *checker)
{
	const struct wg_suite_index *ix = &checker->device->suites;
	u8 i;

	if (unlikely(!checker->device->static_identity.has_identity)) {
		memset(checker->per_suite, 0, sizeof(checker->per_suite));
		return 0;
	}

	for (i = 0; i < ix->n; ++i) {
		const struct wg_wire_layout *l = ix->suites[i]->layout;
		int ret;

		ret = precompute_key(l, checker->per_suite[i].cookie_encryption_key,
			       checker->device->static_identity.static_public,
			       cookie_key_label);
		if (ret)
			return ret;
		ret = precompute_key(l, checker->per_suite[i].message_mac1_key,
			       checker->device->static_identity.static_public,
			       mac1_key_label);
		if (ret)
			return ret;
	}
	return 0;
}

/* A peer is addressed under exactly one suite, the one its handshake records,
 * so one set of keys per peer is right. 6ytx.28 is what lets that suite be
 * configured per peer rather than being the device's.
 */
int __must_check wg_cookie_checker_precompute_peer_keys(struct wg_peer *peer)
{
	const struct wg_suite_index *ix = &peer->device->suites;
	u8 i;

	for (i = 0; i < ix->n; ++i) {
		const struct wg_wire_layout *l = ix->suites[i]->layout;
		int ret;

		ret = precompute_key(l, peer->latest_cookie.per_suite[i].cookie_encryption_key,
			       peer->handshake.remote_static, cookie_key_label);
		if (ret)
			return ret;
		ret = precompute_key(l, peer->latest_cookie.per_suite[i].message_mac1_key,
			       peer->handshake.remote_static, mac1_key_label);
		if (ret)
			return ret;
	}
	return 0;
}

void wg_cookie_init(struct cookie *cookie)
{
	memset(cookie, 0, sizeof(*cookie));
	init_rwsem(&cookie->lock);
}

/* Each MAC covers the message up to its own offset, so the covered length IS
 * that offset. Both MACs are the last two fields of either handshake message,
 * which is why this works from the total length and does not need to know
 * which of the two it is looking at.
 *
 * The layout is a parameter because the covered length depends on the MAC
 * length, which the suite sets. An inbound packet's layout comes from the
 * suite its length routed to; an outbound one's comes from the suite being
 * sent under.
 */
static int __must_check compute_mac1(const struct wg_wire_layout *l,
			 u8 *mac1, const void *message, size_t len,
			 const u8 *key)
{
	len = wg_wire_mac1_offset(l, len);
	return wc_hmac_oneshot(l->hash_type, mac1, l->mac_len, message, len, key,
			       l->hash_len);
}

static int __must_check compute_mac2(const struct wg_wire_layout *l,
			 u8 *mac2, const void *message, size_t len,
			 const u8 *cookie)
{
	len = wg_wire_mac2_offset(l, len);
	return wc_hmac_oneshot(l->hash_type, mac2, l->mac_len, message, len, cookie,
			       l->cookie_len);
}

static int __must_check make_cookie(const struct wg_wire_layout *l,
			u8 *cookie, struct sk_buff *skb,
			struct cookie_checker *checker)
{
	int ret;
	struct Hmac *wc_hmac; /* sizeof(struct Hmac) is 832 if SHA3 is enabled. */

	wc_hmac = (struct Hmac *)malloc(sizeof(*wc_hmac));
	if (! wc_hmac)
		return -ENOMEM;

	ret = wc_HmacInit(wc_hmac, NULL /* heap */, INVALID_DEVID);
	if (ret < 0)
		goto out_hmac_uninited;

	if ((ret == 0) && wg_birthdate_has_expired(checker->secret_birthdate,
				     COOKIE_SECRET_MAX_AGE)) {
		down_write(&checker->secret_lock);
		ret = wc_get_random_bytes(checker->secret, WG_MAX_HASH_LEN);
		if (ret == 0)
			checker->secret_birthdate = ktime_get_coarse_boottime_ns();
		up_write(&checker->secret_lock);
	}

	if (ret == 0) {
		down_read(&checker->secret_lock);

		ret = wc_HmacSetKey(wc_hmac, l->hash_type, checker->secret, l->hash_len);

		if ((ret == 0) && (skb->protocol == htons(ETH_P_IP)))
			ret = wc_HmacUpdate(wc_hmac, (u8 *)&ip_hdr(skb)->saddr,
					    (word32)sizeof(struct in_addr));
		else if ((ret == 0) && (skb->protocol == htons(ETH_P_IPV6)))
			ret = wc_HmacUpdate(wc_hmac, (u8 *)&ipv6_hdr(skb)->saddr,
					    (word32)sizeof(struct in6_addr));
	
		if (ret == 0)
			ret = wc_HmacUpdate(wc_hmac, (u8 *)&udp_hdr(skb)->source, sizeof(__be16));

		if (ret == 0)
			ret = wc_HmacFinal(wc_hmac, cookie);

		up_read(&checker->secret_lock);
	}

	wc_HmacFree(wc_hmac);

out_hmac_uninited:

	free(wc_hmac);

	return ret;
}

enum cookie_mac_state __must_check wg_cookie_validate_packet(struct cookie_checker *checker,
						struct sk_buff *skb,
						bool check_cookie)
{
	/* The suite the length gate resolved for this packet. */
	const struct wg_suite *s =
		wg_suite_by_id(&checker->device->suites, PACKET_CB(skb)->suite_id);
	const struct wg_wire_layout *l;
	const u8 *mac1, *mac2;
	enum cookie_mac_state ret;
	int slot;
	u8 computed_mac[WG_MAX_HASH_LEN];
	u8 cookie[WG_MAX_HASH_LEN];

	ret = INVALID_MAC;
	if (unlikely(!s))
		goto out;
	l = s->layout;
	mac1 = skb->data + wg_wire_mac1_offset(l, skb->len);
	mac2 = skb->data + wg_wire_mac2_offset(l, skb->len);

	slot = wg_suite_slot(&checker->device->suites, s->id);
	if (unlikely(slot < 0))
		goto out;

	if (compute_mac1(l, computed_mac, skb->data, skb->len,
			 checker->per_suite[slot].message_mac1_key) != 0)
		goto out;
	if (ConstantCompare(computed_mac, mac1, l->mac_len))
		goto out;

	ret = VALID_MAC_BUT_NO_COOKIE;

	if (!check_cookie)
		goto out;

	if (make_cookie(l, cookie, skb, checker) != 0)
		goto out;

	if (compute_mac2(l, computed_mac, skb->data, skb->len, cookie) != 0)
		goto out_with_cookie;

	if (ConstantCompare(computed_mac, mac2, l->mac_len))
		goto out_with_cookie;

	ret = VALID_MAC_WITH_COOKIE_BUT_RATELIMITED;
	if (!wg_ratelimiter_allow(skb, dev_net(checker->device->dev)))
		goto out_with_cookie;

	ret = VALID_MAC_WITH_COOKIE;

out_with_cookie:

	memzero_explicit(cookie, sizeof cookie);

out:

	memzero_explicit(computed_mac, sizeof computed_mac);

	return ret;
}

int __must_check wg_cookie_add_mac_to_packet(void *message, size_t len,
				 struct wg_peer *peer)
{
	int ret;
	/* The suite this handshake is running under, which for a response is
	 * the one the initiation arrived in. Using the compiled suite here
	 * computes a SHA-256 mac over a SHA-384 message, at the wrong offsets,
	 * and the peer silently rejects it and retries forever.
	 */
	const struct wg_suite *suite = peer->handshake.suite;
	const struct wg_wire_layout *l = suite->layout;
	const int slot = wg_suite_slot(&peer->device->suites, suite->id);
	u8 *mac1 = (u8 *)message + wg_wire_mac1_offset(l, len);
	u8 *mac2 = (u8 *)message + wg_wire_mac2_offset(l, len);

	if (unlikely(slot < 0))
		return -EINVAL;

	down_write(&peer->latest_cookie.lock);
	ret = compute_mac1(l, mac1, message, len,
		     peer->latest_cookie.per_suite[slot].message_mac1_key);
	if (ret != 0) {
		up_write(&peer->latest_cookie.lock);
		return ret;
	}
	memcpy(peer->latest_cookie.last_mac1_sent, mac1, l->mac_len);
	peer->latest_cookie.have_sent_mac1 = true;
	up_write(&peer->latest_cookie.lock);

	down_read(&peer->latest_cookie.lock);
	if (peer->latest_cookie.is_valid &&
	    !wg_birthdate_has_expired(peer->latest_cookie.birthdate,
				COOKIE_SECRET_MAX_AGE - COOKIE_SECRET_LATENCY))
		ret = compute_mac2(l, mac2, message, len,
			     peer->latest_cookie.cookie);
	else
		memset(mac2, 0, l->mac_len);

	up_read(&peer->latest_cookie.lock);
	return ret;
}

/* dst_len is the caller's buffer, which must be exactly the cookie reply size
 * for the layout. The mac1 of the packet being answered is the AEAD's
 * additional data, and it is read out of that packet, not out of dst.
 */
int __must_check wg_cookie_message_create(u8 *dst, size_t dst_len,
			      struct sk_buff *skb, __le32 index,
			      struct cookie_checker *checker)
{
	/* Two layouts could differ here in principle: the one the received
	 * packet was framed under, which fixes where its mac1 sits, and the one
	 * the reply is framed under. They are the same suite today, and a
	 * cookie reply is sent under the suite of the packet that provoked it,
	 * so one layout is correct rather than merely convenient.
	 */
	const struct wg_suite *s =
		wg_suite_by_id(&checker->device->suites, PACKET_CB(skb)->suite_id);
	const struct wg_wire_layout *l;
	const u8 *mac1;
	struct wg_cookie_view v;
	int slot;
	u8 cookie[WG_MAX_HASH_LEN];
	int ret;

	if (unlikely(!s))
		return -EINVAL;
	l = s->layout;
	slot = wg_suite_slot(&checker->device->suites, s->id);
	if (unlikely(slot < 0))
		return -EINVAL;
	mac1 = skb->data + wg_wire_mac1_offset(l, skb->len);

	if (unlikely(!wg_wire_view_cookie(&v, l, dst, dst_len)))
		return -EINVAL;

	wg_wire_put_header(dst, MESSAGE_HANDSHAKE_COOKIE);
	wg_wire_set_index(v.receiver_index, index);
	ret = wc_get_random_bytes(v.nonce, l->cookie_nonce_len);

	if (ret == 0)
		ret = make_cookie(l, cookie, skb, checker);

	if (ret == 0)
		ret = wc_AesGcm_oneshot_encrypt(v.encrypted_cookie,
					wg_wire_encrypted(l, l->cookie_len),
					checker->per_suite[slot].cookie_encryption_key,
					l->hash_len,
					cookie, l->cookie_len,
					v.nonce, l->cookie_nonce_len,
					mac1, l->mac_len, NOISE_AUTHTAG_LEN);

	memzero_explicit(cookie, sizeof cookie);

	return ret;
}

int __must_check wg_cookie_message_consume(const struct wg_cookie_view *src,
			       const struct wg_wire_layout *l,
			       struct wg_device *wg)
{
	struct wg_peer *peer = NULL;
	u8 cookie[WG_MAX_HASH_LEN];
	int ret = 0;

	if (unlikely(!wg_index_hashtable_lookup(wg->index_hashtable,
						INDEX_HASHTABLE_HANDSHAKE |
						INDEX_HASHTABLE_KEYPAIR,
						wg_wire_get_index(src->receiver_index), &peer)))
		return -ENOENT;

	down_read(&peer->latest_cookie.lock);
	if (unlikely(!peer->latest_cookie.have_sent_mac1)) {
		up_read(&peer->latest_cookie.lock);
		goto out;
	}

	ret = wc_AesGcm_oneshot_decrypt(cookie, (word32)l->cookie_len,
					peer->latest_cookie.per_suite[
						wg_suite_slot(&wg->suites,
							      peer->handshake.suite->id)
					].cookie_encryption_key, l->hash_len,
					src->encrypted_cookie,
					(word32)wg_wire_encrypted(l, l->cookie_len),
					src->nonce, (word32)l->cookie_nonce_len,
					peer->latest_cookie.last_mac1_sent, l->mac_len,
					NOISE_AUTHTAG_LEN);

	up_read(&peer->latest_cookie.lock);

	if (ret == 0) {
		down_write(&peer->latest_cookie.lock);
		memcpy(peer->latest_cookie.cookie, cookie, l->cookie_len);
		peer->latest_cookie.birthdate = ktime_get_coarse_boottime_ns();
		peer->latest_cookie.is_valid = true;
		peer->latest_cookie.have_sent_mac1 = false;
		up_write(&peer->latest_cookie.lock);
	} else {
		net_dbg_ratelimited("%s: Could not decrypt invalid cookie response: %d\n",
				    wg->dev->name, ret);
		ret = -EBADMSG;
	}

	memzero_explicit(cookie, sizeof cookie);

out:
	wg_peer_put(peer);

	return ret;
}
