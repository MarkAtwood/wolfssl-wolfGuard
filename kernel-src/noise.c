// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * Portions Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 */

#include "noise.h"
#include "wire.h"
#include "device.h"
#include "peer.h"
#include "messages.h"
#include "queueing.h"
#include "peerlookup.h"

#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/bitmap.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>

/* This implements Noise_IKpsk2:
 *
 * <- s
 * ******
 * -> e, es, s, ss, {t}
 * <- e, ee, se, psk, {}
 */

static const u8 identifier_name[] = "WolfGuard v1 info@wolfssl.com";


/* One starting transcript per suite this module knows, rather than one pair of
 * globals derived from a compiled-in name. Written once at module init and
 * read on every handshake, hence __ro_after_init.
 *
 * The identifier is still module wide. Per-device and per-peer identifiers are
 * what the Go tree gained in 6ytx.21 and are not this change.
 */
static struct {
	u8 id;
	struct noise_suite_transcript t;
} suite_transcripts[WG_MAX_SUITES] __ro_after_init;
static unsigned int n_suite_transcripts __ro_after_init;

static atomic64_t keypair_counter = ATOMIC64_INIT(0);

/* ChainKey = H(name), then Hash = H(ChainKey || identifier). wc_Sha256Final
 * resets the context, which is why one context serves both digests.
 */
static int __init precompute_transcript(const struct wg_wire_layout *l,
					const char *name,
					struct noise_suite_transcript *out)
{
	const enum wc_HashType type = (enum wc_HashType)l->hash_type;
	wc_HashAlg sha;
	int ret;

	ret = wc_HashInit(&sha, type);
	if (ret != 0) {
		pr_err("ERROR: precompute_transcript() wc_HashInit() failed with code %d.\n", ret);
		return -EINVAL;
	}

	ret = wc_HashUpdate(&sha, type, (const u8 *)name, (word32)strlen(name));
	if (ret == 0)
		ret = wc_HashFinal(&sha, type, out->chaining_key);
	if (ret == 0)
		ret = wc_HashUpdate(&sha, type, out->chaining_key, l->hash_len);
	if (ret == 0)
		ret = wc_HashUpdate(&sha, type, identifier_name, (word32)strlen(identifier_name));
	if (ret == 0)
		ret = wc_HashFinal(&sha, type, out->hash);

	(void)wc_HashFree(&sha, type);
	return ret;
}

const struct noise_suite_transcript *wg_noise_transcript_of(u8 suite_id)
{
	unsigned int i;

	for (i = 0; i < n_suite_transcripts; ++i)
		if (suite_transcripts[i].id == suite_id)
			return &suite_transcripts[i].t;
	return NULL;
}

__must_check int __init wg_noise_init(void)
{
	unsigned int i;
	int ret = 0;

	for (i = 0; i < wg_known_suites_n && i < WG_MAX_SUITES; ++i) {
		const struct wg_suite *suite = wg_known_suites[i];

		ret = precompute_transcript(suite->layout, suite->name,
					    &suite_transcripts[i].t);
		if (ret != 0)
			break;
		suite_transcripts[i].id = suite->id;
		n_suite_transcripts = i + 1;
	}

	if (ret != 0) {
		pr_err("ERROR: wg_noise_init() failed with code %d.\n", ret);
		return -EINVAL;
	}

	return 0;
}

/* Must hold peer->handshake.static_identity->lock */
void wg_noise_precompute_static_static(struct wg_peer *peer)
{
	down_write(&peer->handshake.lock);

	/* Lengths come from the suite, not from sizeof: the arrays are sized by
	 * the maxima over suites, so sizeof is their capacity and would hand
	 * these calls a longer key than the suite actually uses. The
	 * memzero_explicit below is the opposite case and correctly uses
	 * capacity, since zeroing the whole array is what is wanted.
	 */
	if (!peer->handshake.static_identity->has_identity ||
	    (wc_ecc_shared_secret_exim(peer->handshake.precomputed_static_static,
				       peer->handshake.suite->layout->private_key_len,
				       peer->handshake.static_identity->static_private,
				       peer->handshake.suite->layout->private_key_len,
				       peer->handshake.remote_static,
				       peer->handshake.suite->layout->public_key_len,
				       NOISE_CURVE_ID) != 0))
	{
		memzero_explicit(peer->handshake.precomputed_static_static,
		       sizeof(peer->handshake.precomputed_static_static));
	}

	up_write(&peer->handshake.lock);
}

void wg_noise_handshake_init(struct noise_handshake *handshake,
			     struct noise_static_identity *static_identity,
			     const u8 peer_public_key[NOISE_PUBLIC_KEY_LEN],
			     const u8 peer_preshared_key[NOISE_SYMMETRIC_KEY_LEN],
			     struct wg_peer *peer)
{
	memset(handshake, 0, sizeof(*handshake));
	init_rwsem(&handshake->lock);
	handshake->entry.type = INDEX_HASHTABLE_HANDSHAKE;
	handshake->entry.peer = peer;

	/* A new peer inherits the device's outbound suite; WGPEER_A_SUITE
	 * overrides it per peer, and consume_initiation replaces it with
	 * whatever an inbound handshake resolved to.
	 */
	handshake->suite = peer->device->local_suite ?
			   peer->device->local_suite : &wg_suite_legacy;

	memcpy(handshake->remote_static, peer_public_key,
	       handshake->suite->layout->public_key_len);

	if (peer_preshared_key)
		memcpy(handshake->preshared_key, peer_preshared_key,
		       NOISE_SYMMETRIC_KEY_LEN);
	handshake->static_identity = static_identity;
	handshake->state = HANDSHAKE_ZEROED;
	wg_noise_precompute_static_static(peer);
}

static void handshake_zero(struct noise_handshake *handshake)
{
	memzero_explicit(&handshake->ephemeral_private, NOISE_PRIVATE_KEY_LEN);
	memzero_explicit(&handshake->remote_ephemeral, NOISE_PUBLIC_KEY_LEN);
	memzero_explicit(&handshake->hash, sizeof(handshake->hash));
	memzero_explicit(&handshake->chaining_key, sizeof(handshake->chaining_key));
	handshake->remote_index = 0;
	handshake->state = HANDSHAKE_ZEROED;
}

void wg_noise_handshake_clear(struct noise_handshake *handshake)
{
	down_write(&handshake->lock);
	wg_index_hashtable_remove(
			handshake->entry.peer->device->index_hashtable,
			&handshake->entry);
	handshake_zero(handshake);
	up_write(&handshake->lock);
}

static struct noise_keypair *keypair_create(struct wg_peer *peer)
{
	struct noise_keypair *keypair = kzalloc(sizeof(*keypair), GFP_KERNEL);

	if (unlikely(!keypair))
		WC_DEBUG_PR_NULL_RET(NULL);
	spin_lock_init(&keypair->receiving_counter.lock);
	keypair->internal_id = atomic64_inc_return(&keypair_counter);
	keypair->entry.type = INDEX_HASHTABLE_KEYPAIR;
	keypair->entry.peer = peer;
	kref_init(&keypair->refcount);
	return keypair;
}

static void keypair_free_rcu(struct rcu_head *rcu)
{
	kfree_sensitive(container_of(rcu, struct noise_keypair, rcu));
}

static void keypair_free_kref(struct kref *kref)
{
	struct noise_keypair *keypair =
		container_of(kref, struct noise_keypair, refcount);

	net_dbg_ratelimited("%s: Keypair %llu destroyed for peer %llu\n",
			    keypair->entry.peer->device->dev->name,
			    keypair->internal_id,
			    keypair->entry.peer->internal_id);
	wg_index_hashtable_remove(keypair->entry.peer->device->index_hashtable,
				  &keypair->entry);
	call_rcu(&keypair->rcu, keypair_free_rcu);
}

void wg_noise_keypair_put(struct noise_keypair *keypair, bool unreference_now)
{
	if (unlikely(!keypair))
		return;
	if (unlikely(unreference_now))
		wg_index_hashtable_remove(
			keypair->entry.peer->device->index_hashtable,
			&keypair->entry);
	kref_put(&keypair->refcount, keypair_free_kref);
}

struct noise_keypair *wg_noise_keypair_get(struct noise_keypair *keypair)
{
	RCU_LOCKDEP_WARN(!rcu_read_lock_bh_held(),
		"Taking noise keypair reference without holding the RCU BH read lock");
	if (unlikely(!keypair))
		return NULL;
	if (!kref_get_unless_zero(&keypair->refcount))
		WC_DEBUG_PR_NULL_RET(NULL);
	return keypair;
}

void wg_noise_keypairs_clear(struct noise_keypairs *keypairs)
{
	struct noise_keypair *old;

	spin_lock_bh(&keypairs->keypair_update_lock);

	/* We zero the next_keypair before zeroing the others, so that
	 * wg_noise_received_with_keypair returns early before subsequent ones
	 * are zeroed.
	 */
	old = rcu_dereference_protected(keypairs->next_keypair,
		lockdep_is_held(&keypairs->keypair_update_lock));
	RCU_INIT_POINTER(keypairs->next_keypair, NULL);
	wg_noise_keypair_put(old, true);

	old = rcu_dereference_protected(keypairs->previous_keypair,
		lockdep_is_held(&keypairs->keypair_update_lock));
	RCU_INIT_POINTER(keypairs->previous_keypair, NULL);
	wg_noise_keypair_put(old, true);

	old = rcu_dereference_protected(keypairs->current_keypair,
		lockdep_is_held(&keypairs->keypair_update_lock));
	RCU_INIT_POINTER(keypairs->current_keypair, NULL);
	wg_noise_keypair_put(old, true);

	spin_unlock_bh(&keypairs->keypair_update_lock);
}

void wg_noise_expire_current_peer_keypairs(struct wg_peer *peer)
{
	struct noise_keypair *keypair;

	wg_noise_handshake_clear(&peer->handshake);
	wg_noise_reset_last_sent_handshake(&peer->last_sent_handshake);

	spin_lock_bh(&peer->keypairs.keypair_update_lock);
	keypair = rcu_dereference_protected(peer->keypairs.next_keypair,
			lockdep_is_held(&peer->keypairs.keypair_update_lock));
	if (keypair)
		keypair->sending.is_valid = false;
	keypair = rcu_dereference_protected(peer->keypairs.current_keypair,
			lockdep_is_held(&peer->keypairs.keypair_update_lock));
	if (keypair)
		keypair->sending.is_valid = false;
	spin_unlock_bh(&peer->keypairs.keypair_update_lock);
}

static void add_new_keypair(struct noise_keypairs *keypairs,
			    struct noise_keypair *new_keypair)
{
	struct noise_keypair *previous_keypair, *next_keypair, *current_keypair;

	spin_lock_bh(&keypairs->keypair_update_lock);
	previous_keypair = rcu_dereference_protected(keypairs->previous_keypair,
		lockdep_is_held(&keypairs->keypair_update_lock));
	next_keypair = rcu_dereference_protected(keypairs->next_keypair,
		lockdep_is_held(&keypairs->keypair_update_lock));
	current_keypair = rcu_dereference_protected(keypairs->current_keypair,
		lockdep_is_held(&keypairs->keypair_update_lock));
	if (new_keypair->i_am_the_initiator) {
		/* If we're the initiator, it means we've sent a handshake, and
		 * received a confirmation response, which means this new
		 * keypair can now be used.
		 */
		if (next_keypair) {
			/* If there already was a next keypair pending, we
			 * demote it to be the previous keypair, and free the
			 * existing current. Note that this means KCI can result
			 * in this transition. It would perhaps be more sound to
			 * always just get rid of the unused next keypair
			 * instead of putting it in the previous slot, but this
			 * might be a bit less robust. Something to think about
			 * for the future.
			 */
			RCU_INIT_POINTER(keypairs->next_keypair, NULL);
			rcu_assign_pointer(keypairs->previous_keypair,
					   next_keypair);
			wg_noise_keypair_put(current_keypair, true);
		} else /* If there wasn't an existing next keypair, we replace
			* the previous with the current one.
			*/
			rcu_assign_pointer(keypairs->previous_keypair,
					   current_keypair);
		/* At this point we can get rid of the old previous keypair, and
		 * set up the new keypair.
		 */
		wg_noise_keypair_put(previous_keypair, true);
		rcu_assign_pointer(keypairs->current_keypair, new_keypair);
	} else {
		/* If we're the responder, it means we can't use the new keypair
		 * until we receive confirmation via the first data packet, so
		 * we get rid of the existing previous one, the possibly
		 * existing next one, and slide in the new next one.
		 */
		rcu_assign_pointer(keypairs->next_keypair, new_keypair);
		wg_noise_keypair_put(next_keypair, true);
		RCU_INIT_POINTER(keypairs->previous_keypair, NULL);
		wg_noise_keypair_put(previous_keypair, true);
	}
	spin_unlock_bh(&keypairs->keypair_update_lock);
}

bool wg_noise_received_with_keypair(struct noise_keypairs *keypairs,
				    struct noise_keypair *received_keypair)
{
	struct noise_keypair *old_keypair;
	bool key_is_new;

	/* We first check without taking the spinlock. */
	key_is_new = received_keypair ==
		     rcu_access_pointer(keypairs->next_keypair);
	if (likely(!key_is_new))
		return false;

	spin_lock_bh(&keypairs->keypair_update_lock);
	/* After locking, we double check that things didn't change from
	 * beneath us.
	 */
	if (unlikely(received_keypair !=
		    rcu_dereference_protected(keypairs->next_keypair,
			    lockdep_is_held(&keypairs->keypair_update_lock)))) {
		spin_unlock_bh(&keypairs->keypair_update_lock);
		WC_DEBUG_PR_FALSE_RET(false);
	}

	/* When we've finally received the confirmation, we slide the next
	 * into the current, the current into the previous, and get rid of
	 * the old previous.
	 */
	old_keypair = rcu_dereference_protected(keypairs->previous_keypair,
		lockdep_is_held(&keypairs->keypair_update_lock));
	rcu_assign_pointer(keypairs->previous_keypair,
		rcu_dereference_protected(keypairs->current_keypair,
			lockdep_is_held(&keypairs->keypair_update_lock)));
	wg_noise_keypair_put(old_keypair, true);
	rcu_assign_pointer(keypairs->current_keypair, received_keypair);
	RCU_INIT_POINTER(keypairs->next_keypair, NULL);

	spin_unlock_bh(&keypairs->keypair_update_lock);
	return true;
}

/* Must hold static_identity->lock */
void wg_noise_set_static_identity_private_key(
	struct noise_static_identity *static_identity,
	const u8 private_key[NOISE_PRIVATE_KEY_LEN])
{
	if (wc_ecc_private_to_public_exim(private_key, NOISE_PRIVATE_KEY_LEN,
					  static_identity->static_public,
					  sizeof(static_identity->static_public),
					  NOISE_CURVE_ID, WG_PUBLIC_KEY_COMPRESSED)
	    == 0)
	{
		memcpy(static_identity->static_private, private_key,
		       NOISE_PRIVATE_KEY_LEN);
		static_identity->has_identity = 1;
	}
	else
		static_identity->has_identity = 0;
}

/* This is Hugo Krawczyk's HKDF:
 *  - https://eprint.iacr.org/2010/264.pdf
 *  - https://tools.ietf.org/html/rfc5869
 */
static int __must_check kdf(const struct wg_wire_layout *l,
		u8 *first_dst, u8 *second_dst, u8 *third_dst, const u8 *data,
		size_t first_len, size_t second_len, size_t third_len,
		size_t data_len, const u8 *chaining_key)
{
	/* Sized by the maximum over suites, used to this suite's hash length.
	 * The +1 is HKDF's counter byte appended after the digest.
	 */
	u8 output[WG_MAX_HASH_LEN + 1];
	u8 secret[WG_MAX_HASH_LEN];
	const size_t hlen = l->hash_len;
	struct Hmac *wc_hmac;
	int ret;

	WARN_ON(IS_ENABLED(DEBUG) &&
		(first_len > hlen ||
		 second_len > hlen ||
		 third_len > hlen ||
		 ((second_len || second_dst || third_len || third_dst) &&
		  (!first_len || !first_dst)) ||
		 ((third_len || third_dst) && (!second_len || !second_dst))));

	wc_hmac = (struct Hmac *)malloc(sizeof(*wc_hmac));
	if (! wc_hmac) {
		ret = -ENOMEM;
		WC_DEBUG_PR_CODEPOINT();
		goto out;
	}

	/* Extract entropy from data into secret */
	ret = wc_hmac_oneshot_prealloc(wc_hmac, l->hash_type, secret, hlen, data,
			      data_len, chaining_key, hlen);
	if (ret != 0)
		goto out;

	if (!first_dst || !first_len)
		goto out;

	/* Expand first key: key = secret, data = 0x1 */
	output[0] = 1;

	ret = wc_hmac_oneshot_prealloc(wc_hmac, l->hash_type, output, hlen, output,
			      1, secret, hlen);
	if (ret != 0) {
		WC_DEBUG_PR_CODEPOINT();
		goto out;
	}

	memcpy(first_dst, output, first_len);

	if (!second_dst || !second_len)
		goto out;

	/* Expand second key: key = secret, data = first-key || 0x2 */
	output[hlen] = 2;

	ret = wc_hmac_oneshot_prealloc(wc_hmac, l->hash_type, output, hlen, output,
			      hlen + 1, secret, hlen);
	if (ret != 0) {
		WC_DEBUG_PR_CODEPOINT();
		goto out;
	}

	memcpy(second_dst, output, second_len);

	if (!third_dst || !third_len)
		goto out;

	/* Expand third key: key = secret, data = second-key || 0x3 */
	output[WC_SHA256_DIGEST_SIZE] = 3;

	ret = wc_hmac_oneshot_prealloc(wc_hmac, WC_SHA256, output, sizeof(output), output,
				       WC_SHA256_DIGEST_SIZE + 1, secret, WC_SHA256_DIGEST_SIZE);

	if (ret != 0)
		goto out;

	memcpy(third_dst, output, third_len);

out:
	/* Clear sensitive data from stack */
	memzero_explicit(secret, WC_SHA256_DIGEST_SIZE);
	memzero_explicit(output, WC_SHA256_DIGEST_SIZE + 1);

	if (wc_hmac)
		free(wc_hmac);

	WC_DEBUG_PR_NEG_RET(ret);
}

static int __must_check derive_keys(const struct wg_wire_layout *l,
			struct noise_symmetric_key *first_dst,
			struct noise_symmetric_key *second_dst,
			const u8 *chaining_key)
{
	u64 birthdate = ktime_get_coarse_boottime_ns();
	int ret = kdf(l, first_dst->key, second_dst->key, NULL, NULL,
	    NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, 0,
	    chaining_key);
	if (ret)
		WC_DEBUG_PR_NEG_RET(ret);
	first_dst->birthdate = second_dst->birthdate = birthdate;
	first_dst->is_valid = second_dst->is_valid = true;
	return 0;
}

static bool __must_check mix_dh(const struct wg_wire_layout *l,
				u8 *chaining_key,
				u8 key[NOISE_SYMMETRIC_KEY_LEN],
				const u8 *private,
				const u8 *public)
{
	u8 dh_calculation[NOISE_PRIVATE_KEY_LEN];
	bool ret;

	if (wc_ecc_shared_secret_exim(dh_calculation, sizeof(dh_calculation),
				      private, NOISE_PRIVATE_KEY_LEN,
				      public, NOISE_PUBLIC_KEY_LEN,
				      NOISE_CURVE_ID) != 0)
		WC_DEBUG_PR_FALSE_RET(false);
	if (kdf(l, chaining_key, key, NULL, dh_calculation, l->hash_len,
		NOISE_SYMMETRIC_KEY_LEN, 0, l->private_key_len, chaining_key) == 0)
		ret = true;
	else
		ret = false;
	memzero_explicit(dh_calculation, NOISE_PRIVATE_KEY_LEN);
	WC_DEBUG_PR_FALSE_RET(ret);
}

static bool __must_check mix_precomputed_dh(const struct wg_wire_layout *l,
					    u8 *chaining_key,
					    u8 key[NOISE_SYMMETRIC_KEY_LEN],
					    const u8 precomputed[NOISE_PRIVATE_KEY_LEN])
{
	static const u8 zero_point[NOISE_PRIVATE_KEY_LEN];
	if (unlikely(!ConstantCompare(precomputed, zero_point, NOISE_PRIVATE_KEY_LEN)))
		WC_DEBUG_PR_FALSE_RET(false);
	if (kdf(l, chaining_key, key, NULL, precomputed, l->hash_len,
		NOISE_SYMMETRIC_KEY_LEN, 0, l->private_key_len,
		chaining_key) != 0)
	{
		WC_DEBUG_PR_FALSE_RET(false);
	}
	return true;
}

static int __must_check mix_hash(const struct wg_wire_layout *l,
				u8 *hash, const u8 *src, size_t src_len)
{
	wc_HashAlg sha;
	int ret;

	ret = wc_HashInit(&sha, (enum wc_HashType)l->hash_type);
	if (ret != 0)
	    WC_DEBUG_PR_NEG_RET(ret);

	ret = wc_HashUpdate(&sha, (enum wc_HashType)l->hash_type, hash, l->hash_len);

	if (ret == 0)
		ret = wc_HashUpdate(&sha, (enum wc_HashType)l->hash_type, src, src_len);

	if (ret == 0)
		ret = wc_HashFinal(&sha, (enum wc_HashType)l->hash_type, hash);

	(void)wc_HashFree(&sha, (enum wc_HashType)l->hash_type);

	WC_DEBUG_PR_NEG_RET(ret);
}

static int __must_check mix_psk(const struct wg_wire_layout *l,
		    u8 *chaining_key, u8 *hash,
		    u8 key[NOISE_SYMMETRIC_KEY_LEN],
		    const u8 psk[NOISE_SYMMETRIC_KEY_LEN])
{
	u8 temp_hash[WG_MAX_HASH_LEN];
	int ret;

	ret = kdf(l, chaining_key, temp_hash, key, psk, l->hash_len, l->hash_len,
		  NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, chaining_key);
	if (ret == 0)
		ret = mix_hash(l, hash, temp_hash, l->hash_len);
	memzero_explicit(temp_hash, sizeof(temp_hash));
	WC_DEBUG_PR_NEG_RET(ret);
}

/* Begin a transcript under a given suite. The starting state comes from that
 * suite's precomputed pair, so a handshake begun under one suite cannot be
 * continued under another even if the lengths happened to agree.
 */
static int __must_check handshake_init(const struct wg_suite *suite,
			   u8 *chaining_key,
			   u8 *hash,
			   const u8 *remote_static)
{
	const struct wg_wire_layout *l = suite->layout;
	const struct noise_suite_transcript *t =
		wg_noise_transcript_of(suite->id);

	if (unlikely(!t))
		return -EINVAL;

	memcpy(hash, t->hash, l->hash_len);
	memcpy(chaining_key, t->chaining_key, l->hash_len);
	WC_DEBUG_PR_NEG_RET(mix_hash(l, hash, remote_static,
				     suite->layout->public_key_len));
}

static int __must_check message_encrypt(const struct wg_wire_layout *l,
			    u8 *dst_ciphertext, size_t dst_ciphertext_space, const u8 *src_plaintext,
			    size_t src_len, u8 key[NOISE_SYMMETRIC_KEY_LEN],
			    u8 *hash)
{
	/* For Noise_IK, an all-zeros IV is used, and the key itself guarantees
	 * uniqueness of the { key, iv } tuple, via wc_ecc_make_keypair_exim(),
	 * mix_dh(l, ), mix_precomputed_dh(l, ), and mix_psk(l, ).
	 */
	int ret = wc_AesGcm_oneshot_encrypt(dst_ciphertext, dst_ciphertext_space, key, NOISE_SYMMETRIC_KEY_LEN, src_plaintext, src_len,
					    NULL /* iv */, 0,
					    hash, l->hash_len, NOISE_AUTHTAG_LEN);
	if (ret == 0)
		ret = mix_hash(l, hash, dst_ciphertext, noise_encrypted_len(src_len));

	WC_DEBUG_PR_NEG_RET(ret);
}

static bool __must_check message_decrypt(const struct wg_wire_layout *l,
			    u8 *dst_plaintext, size_t dst_plaintext_space, const u8 *src_ciphertext,
			    size_t src_len, u8 key[NOISE_SYMMETRIC_KEY_LEN],
			    u8 *hash)
{
	int ret = wc_AesGcm_oneshot_decrypt(dst_plaintext, dst_plaintext_space, key, NOISE_SYMMETRIC_KEY_LEN, src_ciphertext, src_len,
					    NULL /* iv */, 0,
					    hash, l->hash_len, NOISE_AUTHTAG_LEN);
	if (ret != 0)
		WC_DEBUG_PR_FALSE_RET(false);
	ret = mix_hash(l, hash, src_ciphertext, src_len);
	if (ret != 0)
		WC_DEBUG_PR_FALSE_RET(false);
	return true;
}

static int __must_check message_ephemeral(const struct wg_wire_layout *l,
			      u8 *ephemeral_dst,
			      const u8 *ephemeral_src,
			      u8 *chaining_key,
			      u8 *hash)
{
	int ret;
	if (ephemeral_dst != ephemeral_src)
		memcpy(ephemeral_dst, ephemeral_src, NOISE_PUBLIC_KEY_LEN);
	ret = mix_hash(l, hash, ephemeral_src, NOISE_PUBLIC_KEY_LEN);
	if (ret)
		WC_DEBUG_PR_NEG_RET(ret);
	ret = kdf(l, chaining_key, NULL, NULL, ephemeral_src, l->hash_len, 0, 0,
	    l->public_key_len, chaining_key);
	WC_DEBUG_PR_NEG_RET(ret);
}

static void tai64n_now(u8 output[NOISE_TIMESTAMP_LEN])
{
	struct timespec64 now;

	ktime_get_real_ts64(&now);

	/* In order to prevent some sort of infoleak from precise timers, we
	 * round down the nanoseconds part to the closest rounded-down power of
	 * two to the maximum initiations per second allowed anyway by the
	 * implementation.
	 */
	now.tv_nsec = ALIGN_DOWN(now.tv_nsec,
		rounddown_pow_of_two(NSEC_PER_SEC / INITIATIONS_PER_SECOND));

	/* https://cr.yp.to/libtai/tai64.html */
	*(__be64 *)output = cpu_to_be64(0x400000000000000aULL + now.tv_sec);
	*(__be32 *)(output + sizeof(__be64)) = cpu_to_be32(now.tv_nsec);
}

bool
wg_noise_handshake_create_initiation(u8 *dst, size_t dst_len,
				     struct noise_handshake *handshake)
{
	/* The suite this peer is addressed under, set from configuration
	 * (6ytx.28) and defaulting to the device's local_suite at peer
	 * creation. This is what makes a device able to INITIATE under
	 * something other than the suite it was built with.
	 */
	const struct wg_suite *suite = handshake->suite;
	const struct wg_wire_layout *l = suite->layout;
	struct wg_initiation_view v;
	u8 timestamp[NOISE_TIMESTAMP_LEN];
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	bool ret = false;

	/* Checked before any lock is taken: a buffer of the wrong size is the
	 * caller's bug, not a handshake failure.
	 */
	if (unlikely(!wg_wire_view_initiation(&v, l, dst, dst_len)))
		return false;

	down_read(&handshake->static_identity->lock);
	down_write(&handshake->lock);

	if (unlikely(!handshake->static_identity->has_identity))
		goto out;

	wg_wire_put_header(dst, MESSAGE_HANDSHAKE_INITIATION);

	if (handshake_init(suite, handshake->chaining_key, handshake->hash,
			   handshake->remote_static) != 0)
		goto out;

	/* e */
	if (wc_ecc_make_keypair_exim(handshake->ephemeral_private,
				     handshake->suite->layout->private_key_len,
				     v.unencrypted_ephemeral, l->public_key_len,
				     NOISE_CURVE_ID, WG_PUBLIC_KEY_COMPRESSED) != 0)
		goto out;

	if (message_ephemeral(l, v.unencrypted_ephemeral,
			      v.unencrypted_ephemeral, handshake->chaining_key,
			      handshake->hash) != 0)
		goto out;

	/* es */
	if (!mix_dh(l, handshake->chaining_key, key, handshake->ephemeral_private,
		    handshake->remote_static))
		goto out;

	/* s */
	if (message_encrypt(l, v.encrypted_static,
			    wg_wire_encrypted(l, l->public_key_len),
			    handshake->static_identity->static_public,
			    NOISE_PUBLIC_KEY_LEN, key, handshake->hash) != 0)
		goto out;

	/* ss */
	if (!mix_precomputed_dh(l, handshake->chaining_key, key,
				handshake->precomputed_static_static))
		goto out;

	/* {t} */
	tai64n_now(timestamp);
	if (message_encrypt(l, v.encrypted_timestamp,
			    wg_wire_encrypted(l, WG_WIRE_TIMESTAMP_LEN), timestamp,
			    NOISE_TIMESTAMP_LEN, key, handshake->hash) != 0)
		goto out;

	wg_wire_set_index(v.sender_index, wg_index_hashtable_insert(
		handshake->entry.peer->device->index_hashtable,
		&handshake->entry));

	handshake->state = HANDSHAKE_CREATED_INITIATION;
	ret = true;

out:

	up_write(&handshake->lock);
	up_read(&handshake->static_identity->lock);
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	WC_DEBUG_PR_FALSE_RET(ret);
}

struct wg_peer *
wg_noise_handshake_consume_initiation(const struct wg_initiation_view *src,
				      const struct wg_suite *suite,
				      struct wg_device *wg)
{
	const struct wg_wire_layout *l = suite->layout;
	struct wg_peer *peer = NULL, *ret_peer = NULL;
	struct noise_handshake *handshake;
	bool replay_attack, flood_attack;
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u8 chaining_key[WG_MAX_HASH_LEN];
	u8 hash[WG_MAX_HASH_LEN];
	u8 s[NOISE_PUBLIC_KEY_LEN];
	u8 e[NOISE_PUBLIC_KEY_LEN];
	u8 t[NOISE_TIMESTAMP_LEN];
	u64 initiation_consumption;

	down_read(&wg->static_identity.lock);
	if (unlikely(!wg->static_identity.has_identity))
		goto out;

	if (handshake_init(suite, chaining_key, hash,
			   wg->static_identity.static_public) != 0)
		goto out;

	/* e */
	if (message_ephemeral(l, e, src->unencrypted_ephemeral, chaining_key, hash) != 0)
		goto out;

	/* es */
	if (!mix_dh(l, chaining_key, key, wg->static_identity.static_private, e)) {
		WC_DEBUG_PR_CODEPOINT();
		goto out;
	}

	/* s */
	if (!message_decrypt(l, s, sizeof(s), src->encrypted_static,
			     wg_wire_encrypted(l, l->public_key_len), key, hash)) {
		WC_DEBUG_PR_CODEPOINT();
		goto out;
	}

	/* Lookup which peer we're actually talking to */
	peer = wg_pubkey_hashtable_lookup(wg->peer_hashtable, s);
	if (!peer) {
		WC_DEBUG_PR_CODEPOINT();
		goto out;
	}
	handshake = &peer->handshake;

	/* ss */
	if (!mix_precomputed_dh(l, chaining_key, key,
				handshake->precomputed_static_static)) {
		WC_DEBUG_PR_CODEPOINT();
		goto out;
	}

	/* {t} */
	if (!message_decrypt(l, t, sizeof(t), src->encrypted_timestamp,
			     wg_wire_encrypted(l, WG_WIRE_TIMESTAMP_LEN), key, hash)) {
		WC_DEBUG_PR_CODEPOINT();
		goto out;
	}

	/* Get an exclusive lock here, even though initially we only need a read
	 * lock -- this avoids a race window after the defensive tests and
	 * before storing the new ephemeral key.  The attack tests have a
	 * negligible CPU footprint, so the atomic ops (identically expensive
	 * for exclusive and shared) dominate here, militating for a single
	 * semaphore cycle with exclusive semantics.
	 */
	down_write(&handshake->lock);
	replay_attack = memcmp(t, handshake->latest_timestamp,
			       NOISE_TIMESTAMP_LEN) <= 0;
	flood_attack = (s64)handshake->last_initiation_consumption +
			       NSEC_PER_SEC / INITIATIONS_PER_SECOND >
		       (s64)ktime_get_coarse_boottime_ns();
	if (replay_attack || flood_attack) {
		up_write(&handshake->lock);
		WC_DEBUG_PR_CODEPOINT();
		goto out;
	}

	/* Success! Copy everything to peer */
	/* Answer in the suite we were asked in. The length gate resolved it
	 * (6ytx.24) and it rides here so create_response frames its reply the
	 * same way. Without this a device accepting two suites answers a
	 * SHA-384 initiation with a legacy response, the initiator rejects it,
	 * and both sides retry forever: the kernel log reads like success while
	 * no traffic ever flows.
	 */
	handshake->suite = suite;
	memcpy(handshake->remote_ephemeral, e, l->public_key_len);
	if (memcmp(t, handshake->latest_timestamp, NOISE_TIMESTAMP_LEN) > 0)
		memcpy(handshake->latest_timestamp, t, NOISE_TIMESTAMP_LEN);
	memcpy(handshake->hash, hash, l->hash_len);
	memcpy(handshake->chaining_key, chaining_key, l->hash_len);
	handshake->remote_index = wg_wire_get_index(src->sender_index);
	initiation_consumption = ktime_get_coarse_boottime_ns();
	if ((s64)(handshake->last_initiation_consumption - initiation_consumption) < 0)
		handshake->last_initiation_consumption = initiation_consumption;
	handshake->state = HANDSHAKE_CONSUMED_INITIATION;
	up_write(&handshake->lock);
	ret_peer = peer;

out:
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	memzero_explicit(hash, sizeof(hash));
	memzero_explicit(chaining_key, sizeof(chaining_key));
	memzero_explicit(s, NOISE_PUBLIC_KEY_LEN);
	up_read(&wg->static_identity.lock);
	if (!ret_peer)
		wg_peer_put(peer);
	WC_DEBUG_PR_NULL_RET(ret_peer);
}

bool wg_noise_handshake_create_response(u8 *dst, size_t dst_len,
					struct noise_handshake *handshake)
{
	/* The suite this handshake runs under, recorded by consume_initiation
	 * from what the length gate resolved. A response is always framed in
	 * the suite of the initiation it answers.
	 */
	const struct wg_suite *suite = handshake->suite;
	const struct wg_wire_layout *l = suite->layout;
	struct wg_response_view v;
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	bool ret = false;

	if (unlikely(!wg_wire_view_response(&v, l, dst, dst_len)))
		return false;

	down_read(&handshake->static_identity->lock);
	down_write(&handshake->lock);

	if (handshake->state != HANDSHAKE_CONSUMED_INITIATION)
		goto out;

	wg_wire_put_header(dst, MESSAGE_HANDSHAKE_RESPONSE);
	wg_wire_set_index(v.receiver_index, handshake->remote_index);

	/* e */
	if (wc_ecc_make_keypair_exim(handshake->ephemeral_private,
				     handshake->suite->layout->private_key_len,
				     v.unencrypted_ephemeral, l->public_key_len,
				     NOISE_CURVE_ID, WG_PUBLIC_KEY_COMPRESSED) != 0)
		goto out;

	if (message_ephemeral(l, v.unencrypted_ephemeral,
			      v.unencrypted_ephemeral, handshake->chaining_key,
			      handshake->hash) != 0)
		goto out;

	/* ee */
	if (!mix_dh(l, handshake->chaining_key, NULL, handshake->ephemeral_private,
		    handshake->remote_ephemeral))
		goto out;

	/* se */
	if (!mix_dh(l, handshake->chaining_key, NULL, handshake->ephemeral_private,
		    handshake->remote_static))
		goto out;

	/* psk */
	if (mix_psk(l, handshake->chaining_key, handshake->hash, key,
		    handshake->preshared_key) != 0)
		goto out;

	/* {} */
	if (message_encrypt(l, v.encrypted_nothing, wg_wire_encrypted(l, 0),
			    NULL, 0, key, handshake->hash) != 0)
		goto out;

	wg_wire_set_index(v.sender_index, wg_index_hashtable_insert(
		handshake->entry.peer->device->index_hashtable,
		&handshake->entry));

	handshake->state = HANDSHAKE_CREATED_RESPONSE;
	ret = true;

out:
	up_write(&handshake->lock);
	up_read(&handshake->static_identity->lock);
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	WC_DEBUG_PR_FALSE_RET(ret);
}

struct wg_peer *
wg_noise_handshake_consume_response(const struct wg_response_view *src,
				    const struct wg_suite *suite,
				    struct wg_device *wg)
{
	const struct wg_wire_layout *l = suite->layout;
	enum noise_handshake_state state = HANDSHAKE_ZEROED;
	struct wg_peer *peer = NULL, *ret_peer = NULL;
	struct noise_handshake *handshake;
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u8 hash[WG_MAX_HASH_LEN];
	u8 chaining_key[WG_MAX_HASH_LEN];
	u8 e[NOISE_PUBLIC_KEY_LEN];
	u8 ephemeral_private[NOISE_PRIVATE_KEY_LEN];
	u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN];

	down_read(&wg->static_identity.lock);

	if (unlikely(!wg->static_identity.has_identity))
		goto out;

	handshake = (struct noise_handshake *)wg_index_hashtable_lookup(
		wg->index_hashtable, INDEX_HASHTABLE_HANDSHAKE,
		wg_wire_get_index(src->receiver_index), &peer);
	if (unlikely(!handshake))
		goto out;

	down_read(&handshake->lock);
	state = handshake->state;
	memcpy(hash, handshake->hash, l->hash_len);
	memcpy(chaining_key, handshake->chaining_key, l->hash_len);
	memcpy(ephemeral_private, handshake->ephemeral_private,
	       NOISE_PRIVATE_KEY_LEN);
	memcpy(preshared_key, handshake->preshared_key,
	       NOISE_SYMMETRIC_KEY_LEN);
	up_read(&handshake->lock);

	if (state != HANDSHAKE_CREATED_INITIATION)
		goto fail;

	/* e */
	if (message_ephemeral(l, e, src->unencrypted_ephemeral, chaining_key, hash) != 0)
		goto fail;

	/* ee */
	if (!mix_dh(l, chaining_key, NULL, ephemeral_private, e))
		goto fail;

	/* se */
	if (!mix_dh(l, chaining_key, NULL, wg->static_identity.static_private, e))
		goto fail;

	/* psk */
	if (mix_psk(l, chaining_key, hash, key, preshared_key) != 0)
		goto fail;

	/* {} */
	if (!message_decrypt(l, NULL, 0, src->encrypted_nothing,
			     wg_wire_encrypted(l, 0), key, hash))
		goto fail;

	/* Success! Copy everything to peer */
	down_write(&handshake->lock);
	/* It's important to check that the state is still the same, while we
	 * have an exclusive lock.
	 */
	if (handshake->state != state) {
		up_write(&handshake->lock);
		goto fail;
	}
	memcpy(handshake->remote_ephemeral, e, NOISE_PUBLIC_KEY_LEN);
	memcpy(handshake->hash, hash, l->hash_len);
	memcpy(handshake->chaining_key, chaining_key, l->hash_len);
	handshake->remote_index = wg_wire_get_index(src->sender_index);
	handshake->state = HANDSHAKE_CONSUMED_RESPONSE;
	up_write(&handshake->lock);
	ret_peer = peer;
	goto out;

fail:
	wg_peer_put(peer);
out:
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	memzero_explicit(hash, sizeof(hash));
	memzero_explicit(chaining_key, sizeof(chaining_key));
	memzero_explicit(ephemeral_private, NOISE_PRIVATE_KEY_LEN);
	memzero_explicit(preshared_key, NOISE_SYMMETRIC_KEY_LEN);
	up_read(&wg->static_identity.lock);
	WC_DEBUG_PR_NULL_RET(ret_peer);
}

bool wg_noise_handshake_begin_session(struct noise_handshake *handshake,
				      struct noise_keypairs *keypairs)
{
	/* The handshake records its suite (6ytx.25), which is where the hash
	 * length and algorithm for the key derivation come from.
	 */
	const struct wg_wire_layout *l = handshake->suite->layout;
	struct noise_keypair *new_keypair = NULL;
	bool ret = false;

	down_write(&handshake->lock);
	if (handshake->state != HANDSHAKE_CREATED_RESPONSE &&
	    handshake->state != HANDSHAKE_CONSUMED_RESPONSE)
		goto out;

	new_keypair = keypair_create(handshake->entry.peer);
	if (!new_keypair)
		goto out;
	/* The handshake records its suite (6ytx.25), which is where the hash
	 * length and algorithm for the key derivation below come from.
	 */
	new_keypair->i_am_the_initiator = handshake->state ==
					  HANDSHAKE_CONSUMED_RESPONSE;
	new_keypair->remote_index = handshake->remote_index;

	if (new_keypair->i_am_the_initiator) {
		if (derive_keys(l, &new_keypair->sending, &new_keypair->receiving,
				handshake->chaining_key) != 0)
			goto out;
	}
	else {
		if (derive_keys(l, &new_keypair->receiving, &new_keypair->sending,
				handshake->chaining_key) != 0)
			goto out;
	}

	handshake_zero(handshake);
	rcu_read_lock_bh();
	if (likely(!READ_ONCE(container_of(handshake, struct wg_peer,
					   handshake)->is_dead))) {
		add_new_keypair(keypairs, new_keypair);
		net_dbg_ratelimited("%s: Keypair %llu created for peer %llu\n",
				    handshake->entry.peer->device->dev->name,
				    new_keypair->internal_id,
				    handshake->entry.peer->internal_id);
		ret = wg_index_hashtable_replace(
			handshake->entry.peer->device->index_hashtable,
			&handshake->entry, &new_keypair->entry);
		new_keypair = NULL; /* successfully added to keypairs */
	}
	rcu_read_unlock_bh();

out:
	up_write(&handshake->lock);

	if (new_keypair)
		kfree_sensitive(new_keypair);

	WC_DEBUG_PR_FALSE_RET(ret);
}

#include "selftest/noise.c"
