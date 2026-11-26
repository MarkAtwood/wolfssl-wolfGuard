// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * Portions Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "containers.h"
#include "config.h"
#include "ipc.h"
#include "subcommands.h"

/* Turn `unaccept-suite X` into the accept set without X.
 *
 * The kernel can only be told the whole accept set, so this reads what the
 * device serves now, drops the named suites, and lets ipc_set_device send the
 * remainder under WGDEVICE_REPLACE_ACCEPT_SUITES.
 *
 * Two consequences of doing it here rather than in the kernel, both worth
 * knowing before relying on it. It is read-modify-write, so a second process
 * changing the accept set between the read and the write loses that change; for
 * an operator command that is the same race `wg set` already has elsewhere, and
 * a netlink attribute for removal is what would close it. And a name that the
 * device does not currently accept is an ERROR rather than a no-op, because the
 * alternative is to silently succeed at not doing what was asked, and an
 * operator unaccepting a typo would believe a suite had stopped being served.
 */
static bool resolve_unaccept_suites(struct wgdevice *device)
{
	struct wgdevice *current = NULL;
	struct wgsuite *drop;
	bool ret = false;

	if (ipc_get_device(&current, device->name) != 0) {
		perror("Unable to read the interface's accept set");
		goto out;
	}

	for (drop = device->first_unaccept_suite; drop; drop = drop->next_suite) {
		struct wgsuite *have;
		bool found = false;

		for (have = current->first_suite; have; have = have->next_suite) {
			if (!strcmp(have->name, drop->name)) {
				found = true;
				break;
			}
		}
		if (!found) {
			fprintf(stderr, "`%s' is not in this interface's accept set\n", drop->name);
			goto out;
		}
	}

	/* Anything the caller also asked to accept in the same command stays,
	 * so `wg set wg0 accept-suite A unaccept-suite B` means exactly that.
	 */
	for (struct wgsuite *have = current->first_suite; have; have = have->next_suite) {
		bool dropped = false;

		for (drop = device->first_unaccept_suite; drop; drop = drop->next_suite) {
			if (!strcmp(have->name, drop->name)) {
				dropped = true;
				break;
			}
		}
		if (dropped)
			continue;
		if (!wgdevice_add_accept_suite(device, have->name))
			goto out;
	}

	if (!device->first_suite) {
		fprintf(stderr, "Refusing to leave `%s' with an empty accept set: it would answer no handshake at all\n",
			device->name);
		goto out;
	}

	device->flags |= WGDEVICE_REPLACE_ACCEPT_SUITES;
	ret = true;
out:
	free_wgdevice(current);
	return ret;
}

int set_main(int argc, char *argv[])
{
	struct wgdevice *device = NULL;
	int ret = 1;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s %s <interface> [listen-port <port>] [fwmark <mark>] [private-key <file path>] [accept-suite <name>] [unaccept-suite <name>] [local-suite <name>] [peer <base64 public key> [remove] [preshared-key <file path>] [endpoint <ip>:<port>] [persistent-keepalive <interval seconds>] [suite <name>] [allowed-ips <ip1>/<cidr1>[,<ip2>/<cidr2>]...] ]...\n", PROG_NAME, argv[0]);
		return 1;
	}

	device = config_read_cmd(argv + 2, argc - 2);
	if (!device)
		goto cleanup;
	strncpy(device->name, argv[1], IFNAMSIZ -  1);
	device->name[IFNAMSIZ - 1] = '\0';

	if (device->first_unaccept_suite && !resolve_unaccept_suites(device))
		goto cleanup;

	if (ipc_set_device(device) != 0) {
		perror("Unable to modify interface");
		goto cleanup;
	}

	ret = 0;

cleanup:
	free_wgdevice(device);
	return ret;
}
