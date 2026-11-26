// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 */

#ifdef DEBUG

/* Check the layout functions the module actually calls.
 *
 * wire.c already asserts the same three numbers at build time, but those
 * assertions are written out longhand, because a function taking a pointer to
 * a const struct is not a constant expression. So they prove the arithmetic in
 * the macros, not the arithmetic in wg_wire_initiation_size and friends, and
 * an edit to the inline functions would sail past them. This closes that gap
 * by exercising the real path.
 *
 * The oracle is the other two implementations: 246, 157 and 72 are what Go and
 * Rust frame for this suite, which the interop matrix in WOLFGUARD-AGILITY's
 * kernel-rig confirms end to end. Nothing here is derived from the code under
 * test.
 */
bool __init wg_wire_selftest(void)
{
	const struct wg_wire_layout *l = &wg_wire_compiled_layout;
	struct wg_initiation_view iv;
	struct wg_response_view rv;
	struct wg_cookie_view cv;
	u8 buf[WG_WIRE_MAX_HANDSHAKE_LEN];
	bool success = true;

#define T(cond, fmt, ...) do {                                         \
		if (!(cond)) {                                         \
			pr_err("wire self-test: " fmt ": FAIL\n",      \
			       ##__VA_ARGS__);                         \
			success = false;                               \
		}                                                      \
	} while (0)

	T(wg_wire_initiation_size(l) == 246, "initiation size is %zu, want 246",
	  wg_wire_initiation_size(l));
	T(wg_wire_response_size(l) == 157, "response size is %zu, want 157",
	  wg_wire_response_size(l));
	T(wg_wire_cookie_size(l) == 72, "cookie size is %zu, want 72",
	  wg_wire_cookie_size(l));

	/* The MACs are the last two fields, so mac2 ends the message and mac1
	 * sits one MAC before it. Checked against the sizes above rather than
	 * recomputed from the layout, so a layout error cannot satisfy both.
	 */
	T(wg_wire_mac1_offset(l, 246) == 246 - 2 * 32,
	  "initiation mac1 offset is %zu", wg_wire_mac1_offset(l, 246));
	T(wg_wire_mac2_offset(l, 246) == 246 - 32,
	  "initiation mac2 offset is %zu", wg_wire_mac2_offset(l, 246));

	/* A view must refuse a length that is not exactly right, which is what
	 * keeps a caller from half-filling a buffer.
	 */
	T(wg_wire_view_initiation(&iv, l, buf, 246), "a 246 byte initiation was refused");
	T(!wg_wire_view_initiation(&iv, l, buf, 245), "a 245 byte initiation was accepted");
	T(!wg_wire_view_initiation(&iv, l, buf, 247), "a 247 byte initiation was accepted");
	T(wg_wire_view_response(&rv, l, buf, 157), "a 157 byte response was refused");
	T(!wg_wire_view_response(&rv, l, buf, 156), "a 156 byte response was accepted");
	T(wg_wire_view_cookie(&cv, l, buf, 72), "a 72 byte cookie was refused");
	T(!wg_wire_view_cookie(&cv, l, buf, 71), "a 71 byte cookie was accepted");

	/* Fields must land in ascending order and inside the message. A view
	 * whose pointers overlap would corrupt the next field silently.
	 */
	if (wg_wire_view_initiation(&iv, l, buf, 246)) {
		T(iv.sender_index == buf + 4, "sender_index is not at offset 4");
		T(iv.unencrypted_ephemeral == buf + 8, "ephemeral is not at offset 8");
		T(iv.encrypted_static == iv.unencrypted_ephemeral + 65,
		  "encrypted_static does not follow the ephemeral");
		T(iv.encrypted_timestamp == iv.encrypted_static + 65 + 16,
		  "encrypted_timestamp does not follow encrypted_static");
		T(iv.mac1 == buf + 246 - 64, "mac1 is not 64 bytes from the end");
		T(iv.mac2 == buf + 246 - 32, "mac2 is not 32 bytes from the end");
	}

	/* Scalars must survive a round trip through the unaligned helpers at
	 * every offset in a word, since nothing guarantees skb->data's
	 * alignment.
	 */
	{
		unsigned int off;

		for (off = 0; off < 4; ++off) {
			wg_wire_set_index(buf + off, cpu_to_le32(0x01020304));
			T(wg_wire_get_index(buf + off) == cpu_to_le32(0x01020304),
			  "index round trip failed at offset %u", off);
		}
	}

	/* --- resolving a suite: by name, or by length for the frozen pair --- */
	{
		struct wg_suite_index ix;
		/* Same lengths as the legacy suite under a DYNAMIC name. A
		 * length router could not serve both; the name tells them
		 * apart, so this must now be accepted. That is the ceiling the
		 * design removes, and this is where it is pinned.
		 */
		static const struct wg_suite same_lengths_named = {
			.id = 42,
			.name = ":P-256:HKDF-SHA-256:AEAD_AES_256_GCM",
			.layout = &wg_wire_compiled_layout,
		};
		/* A second NAMELESS suite of the legacy suite's lengths. The
		 * nameless path has only length to go on, so this must be
		 * refused however it is spelled. The name is one of the two
		 * frozen strings so that the refusal comes from the length
		 * collision rather than from the frozen-set check.
		 */
		static const struct wg_suite same_lengths_nameless = {
			.id = 43,
			.name = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s",
			.layout = &wg_wire_compiled_layout,
		};
		/* Nameless and not one of the two frozen constructions, so
		 * nothing on the wire would identify it.
		 */
		static const struct wg_suite invented_nameless = {
			.id = 44,
			.name = "Noise_IKpsk2_Invented_AesGcm_SHA256",
			.layout = &wg_wire_compiled_layout,
		};
		const struct wg_suite *sha384 = &wg_suite_sha384;
		size_t body_len, name_len, framed;
		u8 name[WG_NAME_MAX_LEN];
		__le32 idx;

		wg_suite_index_init(&ix);
		T(ix.n == 0, "a fresh index is not empty");
		T(wg_suite_nameless_for_length(&ix, 246) == NULL,
		  "an empty index resolved a nameless initiation");

		T(wg_suite_index_add(&ix, &wg_suite_legacy) == 0,
		  "the legacy suite was refused");
		T(wg_wire_initiation_size(wg_suite_sha384.layout) == 278,
		  "the SHA-384 initiation is %zu, want 278 as Go and Rust frame it",
		  wg_wire_initiation_size(wg_suite_sha384.layout));
		T(wg_wire_response_size(wg_suite_sha384.layout) == 189,
		  "the SHA-384 response is %zu, want 189",
		  wg_wire_response_size(wg_suite_sha384.layout));
		T(ix.n == 1, "the index holds %u suites, want 1", ix.n);

		/* The legacy suite is nameless, so it resolves by length and by
		 * nothing else. A named lookup must not find it.
		 */
		T(wg_suite_nameless_for_length(&ix, 246) == &wg_suite_legacy,
		  "a 246 byte nameless initiation did not resolve");
		T(wg_suite_nameless_for_length(&ix, 245) == NULL,
		  "a 245 byte nameless initiation resolved");
		T(wg_suite_by_wire_name(&ix,
					(const u8 *)wg_suite_legacy.name,
					strlen(wg_suite_legacy.name)) == NULL,
		  "the legacy suite resolved through the named path");

		/* The framed size is the length that actually arrives. */
		T(wg_wire_framed_initiation_size(&wg_suite_legacy) == 246,
		  "the legacy framed size is %zu, want 246 unchanged",
		  wg_wire_framed_initiation_size(&wg_suite_legacy));
		framed = 278 + strlen(sha384->name) + 1;
		T(wg_wire_framed_initiation_size(sha384) == framed,
		  "the SHA-384 framed size is %zu, want %zu",
		  wg_wire_framed_initiation_size(sha384), framed);

		T(wg_suite_index_add(&ix, sha384) == 0,
		  "the SHA-384 suite was refused");
		T(ix.n == 2, "the index holds %u suites, want 2", ix.n);
		T(wg_suite_by_wire_name(&ix, (const u8 *)sha384->name,
					strlen(sha384->name)) == sha384,
		  "the SHA-384 suite did not resolve by its name");
		T(wg_suite_by_wire_name(&ix, (const u8 *)sha384->name,
					strlen(sha384->name) - 1) == NULL,
		  "a truncated name resolved");
		T(wg_suite_nameless_for_length(&ix, 278) == NULL,
		  "a named suite's bare length resolved on the nameless path");

		/* The pre-authentication gate admits the length that arrives,
		 * which for a named suite includes the tail.
		 */
		T(wg_suite_index_admits_handshake(&ix,
						  MESSAGE_HANDSHAKE_INITIATION,
						  framed),
		  "the gate rejects the SHA-384 framed length %zu", framed);
		T(!wg_suite_index_admits_handshake(&ix,
						   MESSAGE_HANDSHAKE_INITIATION,
						   278),
		  "the gate admits a SHA-384 initiation with no name tail");
		T(wg_suite_index_admits_handshake(&ix,
						  MESSAGE_HANDSHAKE_INITIATION,
						  246),
		  "the gate rejects a nameless legacy initiation");
		T(wg_suite_index_admits_handshake(&ix,
						  MESSAGE_HANDSHAKE_RESPONSE, 189),
		  "the gate rejects a SHA-384 response");
		T(!wg_suite_index_admits_handshake(&ix, MESSAGE_DATA, 246),
		  "the gate admits a data message");

		/* Two suites of IDENTICAL length, told apart by name. */
		T(wg_suite_index_add(&ix, &same_lengths_named) == 0,
		  "a named suite of the legacy suite's lengths was refused, which is the ceiling this design removes");
		T(wg_suite_by_wire_name(&ix,
					(const u8 *)same_lengths_named.name,
					strlen(same_lengths_named.name)) ==
			  &same_lengths_named,
		  "the same-length named suite did not resolve by its name");
		T(wg_suite_nameless_for_length(&ix, 246) == &wg_suite_legacy,
		  "accepting a same-length named suite broke the nameless path");

		/* The two refusals that remain, both about the nameless path. */
		T(wg_suite_index_add(&ix, &same_lengths_nameless) == -EEXIST,
		  "a second nameless suite of the same initiation length was accepted");
		T(wg_suite_index_add(&ix, &invented_nameless) == -EINVAL,
		  "a nameless suite outside the two frozen constructions was accepted");
		T(ix.n == 3, "a refused add grew the index to %u, want 3", ix.n);

		/* --- the name tail on the wire --- */
		memset(buf, 0xa5, sizeof(buf));
		body_len = wg_wire_append_name_tail(buf, 278, sizeof(buf),
						    sha384->name);
		T(body_len == framed, "appending the name gave %zu, want %zu",
		  body_len, framed);
		T(buf[framed - 1] == strlen(sha384->name),
		  "the final byte is %u, want the name length %zu",
		  buf[framed - 1], strlen(sha384->name));

		T(wg_wire_split_name_tail(buf, framed, &body_len, name,
					  &name_len),
		  "a tail this module wrote did not split");
		T(body_len == 278, "the split body is %zu, want 278", body_len);
		T(name_len == strlen(sha384->name),
		  "the split name is %zu bytes, want %zu", name_len,
		  strlen(sha384->name));
		T(!memcmp(name, sha384->name, name_len),
		  "the split name is not the name that was written");

		/* A tail claiming more than the packet holds, and one claiming
		 * nothing, are both malformed. These run before anything is
		 * authenticated, so they must fail rather than read past.
		 */
		T(!wg_wire_split_name_tail(buf, name_len + 1, &body_len, name,
					   &name_len),
		  "a tail claiming the whole packet split");
		buf[framed - 1] = 0;
		T(!wg_wire_split_name_tail(buf, framed, &body_len, name,
					   &name_len),
		  "a zero-length name tail split");
		buf[framed - 1] = WG_NAME_MAX_LEN + 1;
		T(!wg_wire_split_name_tail(buf, framed, &body_len, name,
					   &name_len),
		  "an over-long name tail split");

		/* --- the index a response or cookie reply names --- */
		memset(buf, 0, sizeof(buf));
		wg_wire_set_index(buf + WG_WIRE_HEADER_LEN + WG_WIRE_INDEX_LEN,
				  cpu_to_le32(0xdeadbeef));
		T(wg_wire_receiver_index(MESSAGE_HANDSHAKE_RESPONSE, buf, 189,
					 &idx),
		  "a response's receiver index was not readable");
		T(idx == cpu_to_le32(0xdeadbeef),
		  "a response's receiver index read wrong");
		memset(buf, 0, sizeof(buf));
		wg_wire_set_index(buf + WG_WIRE_HEADER_LEN,
				  cpu_to_le32(0xfeedface));
		T(wg_wire_receiver_index(MESSAGE_HANDSHAKE_COOKIE, buf, 72,
					 &idx),
		  "a cookie reply's receiver index was not readable");
		T(idx == cpu_to_le32(0xfeedface),
		  "a cookie reply's receiver index read wrong");
		T(!wg_wire_receiver_index(MESSAGE_HANDSHAKE_INITIATION, buf,
					  246, &idx),
		  "an initiation reported a receiver index, which it has none of");
		T(!wg_wire_receiver_index(MESSAGE_HANDSHAKE_RESPONSE, buf, 8,
					  &idx),
		  "a packet too short to hold a receiver index reported one");
	}

	/* --- the name grammar, which runs pre-authentication --- */
	{
		static const char *const good[] = {
			":P-256:HKDF-SHA-256:AEAD_AES_256_GCM",
			":P-256:HKDF-SHA-384:AEAD_AES_256_GCM",
			":X25519+ML-KEM-768:HKDF-SHA-384:AEAD_AES_256_GCM",
			":a:b:c",
		};
		static const char *const bad[] = {
			"Noise_IKpsk2_SECP256R1_AesGcm_SHA256", /* no lead */
			":P-256:HKDF-SHA-256",                  /* two fields */
			":P-256:HKDF:SHA:256",                  /* four fields */
			":P-256::AEAD_AES_256_GCM",             /* empty field */
			":P-256:HKDF-SHA-256:",                 /* empty last */
			":a:b",                                 /* too short */
			":P 256:HKDF-SHA-256:AEAD_AES_256_GCM", /* space */
			":P-256:HKDF-SHA-256:AEAD/AES",         /* slash */
		};
		size_t i;

		for (i = 0; i < ARRAY_SIZE(good); ++i)
			T(wg_wire_name_valid((const u8 *)good[i],
					     strlen(good[i])),
			  "the grammar rejected %s", good[i]);
		for (i = 0; i < ARRAY_SIZE(bad); ++i)
			T(!wg_wire_name_valid((const u8 *)bad[i],
					      strlen(bad[i])),
			  "the grammar accepted %s", bad[i]);

		/* A name of exactly the cap, and one byte over it. */
		{
			u8 big[WG_NAME_MAX_LEN + 2];

			memset(big, 'a', sizeof(big));
			big[0] = ':';
			big[2] = ':';
			big[4] = ':';
			T(wg_wire_name_valid(big, WG_NAME_MAX_LEN),
			  "the grammar rejected a name of exactly the cap");
			T(!wg_wire_name_valid(big, WG_NAME_MAX_LEN + 1),
			  "the grammar accepted a name one byte over the cap");
		}

		/* Every byte, to pin the permitted set rather than sample it.
		 * A disallowed byte inside a field must be rejected.
		 */
		{
			u8 probe[] = ":a:b:cX";
			unsigned int b;

			for (b = 0; b < 256; ++b) {
				bool want = (b >= 'A' && b <= 'Z') ||
					    (b >= 'a' && b <= 'z') ||
					    (b >= '0' && b <= '9') ||
					    b == '-' || b == '_' ||
					    b == '.' || b == '+';

				probe[6] = (u8)b;
				T(wg_wire_name_valid(probe, sizeof(probe) - 1) ==
					  want,
				  "byte %#02x in a field: grammar says %d, want %d",
				  b, !want, want);
			}
		}
	}

#undef T

	if (success)
		pr_info("wire self-test: pass\n");
	return success;
}

#endif
