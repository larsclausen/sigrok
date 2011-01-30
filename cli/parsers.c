/*
 * This file is part of the sigrok project.
 *
 * Copyright (C) 2011 Bert Vermeulen <bert@biot.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <glib.h>
#include <sigrok.h>
#include "sigrok-cli.h"

char **parse_probestring(int max_probes, const char *probestring)
{
	int tmp, b, e, i;
	char **tokens, **range, **probelist, *name, str[8];
	gboolean error;

	error = FALSE;
	range = NULL;
	probelist = g_malloc0(max_probes * sizeof(char *));
	tokens = g_strsplit(probestring, ",", max_probes);

	for (i = 0; tokens[i]; i++) {
		if (strchr(tokens[i], '-')) {
			/* A range of probes in the form 1-5. */
			range = g_strsplit(tokens[i], "-", 2);
			if (!range[0] || !range[1] || range[2]) {
				/* Need exactly two arguments. */
				printf("Invalid probe syntax '%s'.\n",
				       tokens[i]);
				error = TRUE;
				break;
			}

			b = strtol(range[0], NULL, 10);
			e = strtol(range[1], NULL, 10);
			if (b < 1 || e > max_probes || b >= e) {
				printf("Invalid probe range '%s'.\n",
				       tokens[i]);
				error = TRUE;
				break;
			}

			while (b <= e) {
				snprintf(str, 7, "%d", b);
				probelist[b - 1] = g_strdup(str);
				b++;
			}
		} else {
			tmp = strtol(tokens[i], NULL, 10);
			if (tmp < 1 || tmp > max_probes) {
				printf("Invalid probe %d.\n", tmp);
				error = TRUE;
				break;
			}

			if ((name = strchr(tokens[i], '='))) {
				probelist[tmp - 1] = g_strdup(++name);
				if (strlen(probelist[tmp - 1]) > MAX_PROBENAME_LEN)
					probelist[tmp - 1][MAX_PROBENAME_LEN] = 0;
			} else {
				snprintf(str, 7, "%d", tmp);
				probelist[tmp - 1] = g_strdup(str);
			}
		}
	}

	if (error) {
		for (i = 0; i < max_probes; i++)
			if (probelist[i])
				g_free(probelist[i]);
		g_free(probelist);
		probelist = NULL;
	}

	g_strfreev(tokens);
	if (range)
		g_strfreev(range);

	return probelist;
}

char **parse_triggerstring(struct sr_device *device, const char *triggerstring)
{
	GSList *l;
	struct probe *probe;
	int max_probes, probenum, i;
	char **tokens, **triggerlist, *trigger, *tc, *trigger_types;
	gboolean error;

	max_probes = g_slist_length(device->probes);
	error = FALSE;
	triggerlist = g_malloc0(max_probes * sizeof(char *));
	tokens = g_strsplit(triggerstring, ",", max_probes);
	trigger_types = device->plugin->get_device_info(0, DI_TRIGGER_TYPES);
	if (trigger_types == NULL)
		return NULL;

	for (i = 0; tokens[i]; i++) {
		if (tokens[i][0] < '0' || tokens[i][0] > '9') {
			/* Named probe */
			probenum = 0;
			for (l = device->probes; l; l = l->next) {
				probe = (struct probe *)l->data;
				if (probe->enabled
				    && !strncmp(probe->name, tokens[i],
						strlen(probe->name))) {
					probenum = probe->index;
					break;
				}
			}
		} else {
			probenum = strtol(tokens[i], NULL, 10);
		}

		if (probenum < 1 || probenum > max_probes) {
			printf("Invalid probe.\n");
			error = TRUE;
			break;
		}

		if ((trigger = strchr(tokens[i], '='))) {
			for (tc = ++trigger; *tc; tc++) {
				if (strchr(trigger_types, *tc) == NULL) {
					printf("Unsupported trigger type "
					       "'%c'\n", *tc);
					error = TRUE;
					break;
				}
			}
			if (!error)
				triggerlist[probenum - 1] = g_strdup(trigger);
		}
	}
	g_strfreev(tokens);

	if (error) {
		for (i = 0; i < max_probes; i++)
			if (triggerlist[i])
				g_free(triggerlist[i]);
		g_free(triggerlist);
		triggerlist = NULL;
	}

	return triggerlist;
}

uint64_t parse_sizestring(const char *sizestring)
{
	int multiplier;
	uint64_t val;
	char *s;

	val = strtoull(sizestring, &s, 10);
	multiplier = 0;
	while (s && *s && multiplier == 0) {
		switch (*s) {
		case ' ':
			break;
		case 'k':
		case 'K':
			multiplier = KHZ(1);
			break;
		case 'm':
		case 'M':
			multiplier = MHZ(1);
			break;
		case 'g':
		case 'G':
			multiplier = GHZ(1);
			break;
		default:
			val = 0;
			multiplier = -1;
		}
		s++;
	}
	if (multiplier > 0)
		val *= multiplier;

	return val;
}

GHashTable *parse_generic_arg(const char *arg)
{
	GHashTable *hash;
	int i;
	char **elements, *e;

	if (!arg || !arg[0])
		return NULL;

	hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	elements = g_strsplit(arg, ":", 0);
	g_hash_table_insert(hash, g_strdup("sigrok_key"), g_strdup(elements[0]));
	for (i = 1; elements[i]; i++) {
		e = strchr(elements[i], '=');
		if (!e)
			g_hash_table_insert(hash, g_strdup(elements[i]), NULL);
		else {
			*e++ = '\0';
			g_hash_table_insert(hash, g_strdup(elements[i]), g_strdup(e));
		}
	}
	g_strfreev(elements);

	return hash;
}

struct sr_device *parse_devicestring(const char *devicestring)
{
	struct sr_device *device, *d;
	struct sr_device_plugin *plugin;
	GSList *devices, *plugins, *l, *p;
	int num_devices, device_num, device_cnt;
	char *tmp;

	if (!devicestring)
		return NULL;

	device = NULL;
	device_num = strtol(devicestring, &tmp, 10);
	if (tmp != devicestring) {
		/* argument is numeric, meaning a device ID. Make all driver
		 * plugins scan for devices.
		 */
		num_devices = num_real_devices();
		if (device_num < 0 || device_num >= num_devices)
			return NULL;

		device_cnt = 0;
		devices = device_list();
		for (l = devices; l; l = l->next) {
			d = l->data;
			if (strstr(d->plugin->name, "demo"))
				continue;
			if (device_cnt == device_num) {
				if (device_num == device_cnt) {
					device = d;
					break;
				}
			}
			device_cnt++;
		}
	} else {
		/* select device by driver -- only initialize that driver,
		 * no need to let them all scan
		 */
		device = NULL;
		plugins = list_hwplugins();
		for (p = plugins; p; p = p->next) {
			plugin = p->data;
			if (strcmp(plugin->name, devicestring))
				continue;
			num_devices = device_plugin_init(plugin);
			if (num_devices == 1) {
				devices = device_list();
				device = devices->data;
			} else if (num_devices > 1) {
				printf("driver '%s' found %d devices, select by ID instead.\n",
						devicestring, num_devices);
			}
			/* fall through: selected driver found no devices */
			break;
		}
	}

	return device;
}

uint64_t parse_timestring(const char *timestring)
{
	uint64_t time_msec;
	char *s;

	time_msec = strtoull(timestring, &s, 10);
	if (time_msec == 0 && s == timestring)
		return 0;

	if (s && *s) {
		while (*s == ' ')
			s++;
		if (!strcmp(s, "s"))
			time_msec *= 1000;
		else if (!strcmp(s, "ms"))
			; /* redundant */
		else
			return 0;
	}

	return time_msec;
}

