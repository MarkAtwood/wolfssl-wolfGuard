// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 wolfSSL Inc. All Rights Reserved.
 */

#include "wire_name.h"

#include <linux/kernel.h>

/* permitted reports whether b may appear inside a primitive name.
 *
 * The set covers every character used by the public registries this targets,
 * including the plus sign for hybrid key exchanges, and nothing else. It
 * excludes the colon, which keeps field splitting unambiguous, and every byte
 * outside printable ASCII. Must match handshakename.permitted.
 */
static bool permitted(u8 b)
{
	if (b >= 'A' && b <= 'Z')
		return true;
	if (b >= 'a' && b <= 'z')
		return true;
	if (b >= '0' && b <= '9')
		return true;
	return b == '-' || b == '_' || b == '.' || b == '+';
}

bool wg_wire_name_valid(const u8 *name, size_t len)
{
	size_t i;
	unsigned int fields = 0;
	size_t field_len = 0;

	if (len > WG_NAME_MAX_LEN || len < WG_NAME_MIN_LEN)
		return false;
	if (name[0] != WG_NAME_LEAD)
		return false;

	/* Exactly three fields, none empty, separated by the lead byte. The
	 * loop counts a field when it ends, so the final one is counted after
	 * it rather than inside.
	 */
	for (i = 1; i < len; ++i) {
		if (name[i] == WG_NAME_LEAD) {
			if (field_len == 0)
				return false;
			if (++fields > WG_NAME_FIELDS)
				return false;
			field_len = 0;
			continue;
		}
		if (!permitted(name[i]))
			return false;
		++field_len;
	}

	if (field_len == 0)
		return false;
	return ++fields == WG_NAME_FIELDS;
}
