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

	/* --- the length-to-suite index --- */
	{
		struct wg_suite_index ix;
		/* Same lengths as the legacy suite, different id. Routing has
		 * only the length to go on, so a set holding both would parse
		 * a packet under whichever was registered first while its MACs
		 * were computed under the other. This must be refused.
		 */
		static const struct wg_suite collides = {
			.id = 42,
			.name = "same-lengths-different-id",
			.layout = &wg_wire_compiled_layout,
		};
		/* A plausible second suite: SHA-384 doubles nothing but the MAC
		 * and cookie lengths, which is enough to make every handshake
		 * length differ, so this one is servable alongside the legacy.
		 */
		static const struct wg_wire_layout sha384 = {
			.public_key_len = NOISE_PUBLIC_KEY_LEN,
			.authtag_len = NOISE_AUTHTAG_LEN,
			.mac_len = 48,
			.cookie_len = 48,
			.cookie_nonce_len = COOKIE_NONCE_LEN,
		};
		static const struct wg_suite distinct = {
			.id = 43,
			.name = "distinct-lengths",
			.layout = &sha384,
		};

		wg_suite_index_init(&ix);
		T(ix.n == 0, "a fresh index is not empty");
		T(wg_suite_for_length(&ix, MESSAGE_HANDSHAKE_INITIATION, 246) == NULL,
		  "an empty index resolved an initiation");

		T(wg_suite_index_add(&ix, &wg_suite_legacy) == 0,
		  "the legacy suite was refused");
		T(ix.n == 1, "the index holds %u suites, want 1", ix.n);

		T(wg_suite_for_length(&ix, MESSAGE_HANDSHAKE_INITIATION, 246) ==
		  &wg_suite_legacy, "a 246 byte initiation did not resolve");
		T(wg_suite_for_length(&ix, MESSAGE_HANDSHAKE_RESPONSE, 157) ==
		  &wg_suite_legacy, "a 157 byte response did not resolve");
		T(wg_suite_for_length(&ix, MESSAGE_HANDSHAKE_COOKIE, 72) ==
		  &wg_suite_legacy, "a 72 byte cookie did not resolve");

		/* A length belonging to no suite, and a length belonging to the
		 * wrong type, both have to miss. The second is the one that
		 * would let a response be parsed as an initiation.
		 */
		T(wg_suite_for_length(&ix, MESSAGE_HANDSHAKE_INITIATION, 245) == NULL,
		  "a 245 byte initiation resolved");
		T(wg_suite_for_length(&ix, MESSAGE_HANDSHAKE_INITIATION, 157) == NULL,
		  "a response length resolved as an initiation");
		T(wg_suite_for_length(&ix, MESSAGE_DATA, 246) == NULL,
		  "a data message resolved to a suite");

		T(wg_suite_by_id(&ix, WG_SUITE_LEGACY) == &wg_suite_legacy,
		  "lookup by id failed");
		T(wg_suite_by_id(&ix, 99) == NULL, "an unknown id resolved");

		/* The same suite twice, by id. */
		T(wg_suite_index_add(&ix, &wg_suite_legacy) == -EEXIST,
		  "the same suite was added twice");

		/* The real hazard: a different suite with colliding lengths. */
		T(wg_suite_index_add(&ix, &collides) == -EEXIST,
		  "a suite with colliding handshake lengths was accepted");
		T(ix.n == 1, "a refused add still grew the index to %u", ix.n);

		/* And a suite that does not collide is accepted, so the check
		 * is not simply refusing everything.
		 */
		T(wg_suite_index_add(&ix, &distinct) == 0,
		  "a suite with distinct lengths was refused");
		T(ix.n == 2, "the index holds %u suites, want 2", ix.n);
		T(wg_suite_for_length(&ix, MESSAGE_HANDSHAKE_INITIATION,
				      wg_wire_initiation_size(&sha384)) == &distinct,
		  "the second suite's initiation did not resolve to it");
		T(wg_suite_for_length(&ix, MESSAGE_HANDSHAKE_INITIATION, 246) ==
		  &wg_suite_legacy,
		  "adding a second suite broke the first one's routing");
	}

#undef T

	if (success)
		pr_info("wire self-test: pass\n");
	return success;
}

#endif
