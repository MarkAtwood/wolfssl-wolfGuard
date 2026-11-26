// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 */

#ifdef DEBUG

/* The per-suite transcript starting state, against vectors computed outside
 * this module.
 *
 * The oracle is Python's hashlib, not wolfCrypt and not this file:
 *
 *   ChainKey = SHA256(suite name)
 *   Hash     = SHA256(ChainKey || "WolfGuard v1 info@wolfssl.com")
 *
 * That matters more here than in most places. These two values are the root of
 * every handshake transcript, so if they are wrong the module still builds,
 * still loads, and simply cannot talk to anything, with no indication of why.
 * Checking them against the code that produced them would prove nothing.
 */
bool __init wg_noise_selftest(void)
{
	/* Noise_IKpsk2_SECP256R1_AesGcm_SHA256, the suite compiled in. */
	static const u8 legacy_ck[NOISE_HASH_LEN] __initconst = {
		0x08, 0x2d, 0xaf, 0xe0, 0xb1, 0x9f, 0xee, 0x70,
		0x6a, 0x69, 0xf2, 0xb9, 0x5c, 0xa6, 0xe1, 0x36,
		0x9f, 0xab, 0xd5, 0x36, 0x5f, 0x0e, 0x91, 0x62,
		0x25, 0x74, 0x73, 0x5b, 0x7f, 0x24, 0xbe, 0x48,
	};
	static const u8 legacy_hash[NOISE_HASH_LEN] __initconst = {
		0x05, 0xb6, 0x88, 0xc3, 0xb9, 0x6e, 0xc7, 0x79,
		0x40, 0x77, 0x80, 0xba, 0xec, 0xbf, 0x19, 0x8e,
		0x39, 0xa1, 0x3d, 0x2c, 0x42, 0x74, 0x45, 0xef,
		0x28, 0x39, 0xcb, 0x5e, 0x21, 0x1b, 0x6a, 0x00,
	};
	/* The SHA-384 suite, which IS registered, checked at its own hash
	 * length against SHA-384 vectors. This is the case the whole per-suite
	 * transcript table exists for: a different name AND a different hash
	 * giving a different root, with an oracle outside this module.
	 */
	static const u8 sha384_ck[WC_SHA384_DIGEST_SIZE] __initconst = {
		0xed, 0x3a, 0x2b, 0x61, 0x9e, 0xfb, 0xf7, 0x55,
		0xe2, 0x92, 0x60, 0x32, 0x52, 0xa9, 0xd4, 0xbd,
		0x61, 0x27, 0xe5, 0x12, 0x2a, 0xb8, 0xd2, 0x50,
		0xfa, 0xcf, 0xc3, 0xf8, 0x6b, 0x08, 0x79, 0x95,
		0x9b, 0xa0, 0x8c, 0xff, 0x0b, 0xf0, 0x1d, 0x0b,
		0x97, 0xa2, 0x7c, 0x1f, 0xa2, 0x16, 0xde, 0x8c,
	};
	static const u8 sha384_hash[WC_SHA384_DIGEST_SIZE] __initconst = {
		0x64, 0xab, 0x5c, 0x5b, 0x46, 0xd4, 0xfc, 0xad,
		0x8e, 0xf4, 0x3d, 0x77, 0xb0, 0x1f, 0xed, 0x35,
		0x16, 0xf2, 0x21, 0x67, 0x49, 0xe3, 0xf7, 0x01,
		0xab, 0x8f, 0x33, 0xa6, 0xf2, 0x06, 0x78, 0x3a,
		0x1e, 0x60, 0xeb, 0xda, 0x19, 0xeb, 0xc5, 0x35,
		0x73, 0xea, 0x3c, 0xf6, 0xcd, 0xa2, 0x80, 0x13,
	};
	/* Noise_IKpsk2_SECP256R1_C_AesGcm_SHA256, the compressed-key suite.
	 * Not registered yet, which is 6ytx.22. Its vectors are here to show
	 * the NAME is what varies the starting state: if it were not bound in,
	 * two suites would share a transcript root and a peer speaking the
	 * wrong one could get further than it should.
	 */
	static const char compressed_name[] __initconst =
		"Noise_IKpsk2_SECP256R1_C_AesGcm_SHA256";
	static const u8 compressed_ck[NOISE_HASH_LEN] __initconst = {
		0x63, 0xa7, 0x17, 0x9a, 0xe1, 0xe2, 0xab, 0x4b,
		0xaf, 0xa1, 0x4a, 0x8b, 0xef, 0x1a, 0xa4, 0x68,
		0xe0, 0x14, 0x66, 0x5b, 0x8e, 0x92, 0xcf, 0xb6,
		0x1d, 0xe3, 0xa8, 0x8d, 0xca, 0x1c, 0xaa, 0x31,
	};
	static const u8 compressed_hash[NOISE_HASH_LEN] __initconst = {
		0x6c, 0xe7, 0x9a, 0xc2, 0xfc, 0x4e, 0x76, 0x82,
		0x36, 0xbe, 0xda, 0xfd, 0x19, 0x57, 0x01, 0x1d,
		0x36, 0x7d, 0x6d, 0x6c, 0x9d, 0xa4, 0x6b, 0x84,
		0xb1, 0xba, 0xe0, 0x2e, 0x73, 0xb5, 0x15, 0xbb,
	};
	const struct noise_suite_transcript *t;
	struct noise_suite_transcript scratch;
	bool success = true;

#define T(cond, fmt, ...) do {                                         \
		if (!(cond)) {                                         \
			pr_err("noise self-test: " fmt ": FAIL\n",     \
			       ##__VA_ARGS__);                         \
			success = false;                               \
		}                                                      \
	} while (0)

	t = wg_noise_transcript_of(WG_SUITE_LEGACY);
	T(t != NULL, "the legacy suite has no precomputed transcript");
	if (t) {
		T(!memcmp(t->chaining_key, legacy_ck, NOISE_HASH_LEN),
		  "the legacy chaining key does not match SHA256(name)");
		T(!memcmp(t->hash, legacy_hash, NOISE_HASH_LEN),
		  "the legacy hash does not match SHA256(ChainKey || identifier)");
	}

	t = wg_noise_transcript_of(WG_SUITE_SHA384);
	T(t != NULL, "the SHA-384 suite has no precomputed transcript");
	if (t) {
		T(!memcmp(t->chaining_key, sha384_ck, WC_SHA384_DIGEST_SIZE),
		  "the SHA-384 chaining key does not match SHA384(name)");
		T(!memcmp(t->hash, sha384_hash, WC_SHA384_DIGEST_SIZE),
		  "the SHA-384 hash does not match SHA384(ChainKey || identifier)");
		/* And the two suites must not share a root. */
		T(memcmp(t->chaining_key, legacy_ck, NOISE_HASH_LEN) != 0,
		  "the SHA-384 and legacy suites share a chaining key prefix");
	}

	T(wg_noise_transcript_of(WG_SUITE_NONE) == NULL,
	  "WG_SUITE_NONE resolved to a transcript");
	T(wg_noise_transcript_of(200) == NULL,
	  "an unregistered suite id resolved to a transcript");

	/* A different name must give a different root, and the right one. */
	if (precompute_transcript(wg_suite_legacy.layout, compressed_name,
				  &scratch) == 0) {
		T(!memcmp(scratch.chaining_key, compressed_ck, NOISE_HASH_LEN),
		  "the compressed-suite chaining key is wrong");
		T(!memcmp(scratch.hash, compressed_hash, NOISE_HASH_LEN),
		  "the compressed-suite hash is wrong");
		T(memcmp(scratch.chaining_key, legacy_ck, NOISE_HASH_LEN) != 0,
		  "two different suite names produced the same chaining key, so "
		  "the name is not bound into the transcript");
	} else {
		T(false, "precompute_transcript failed on a second name");
	}

	memzero_explicit(&scratch, sizeof(scratch));

#undef T

	if (success)
		pr_info("noise self-test: pass\n");
	return success;
}

#endif
