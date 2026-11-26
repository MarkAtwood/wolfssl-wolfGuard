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

#undef T

	if (success)
		pr_info("wire self-test: pass\n");
	return success;
}

#endif
