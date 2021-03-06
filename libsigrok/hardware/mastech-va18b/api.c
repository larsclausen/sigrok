/*
 * This file is part of the sigrok project.
 *
 * Copyright (C) 2012 Uwe Hermann <uwe@hermann-uwe.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <stdlib.h>
#include "sigrok.h"
#include "sigrok-internal.h"

#define MIN_NUM_SAMPLES 1

struct context {
	uint64_t limit_samples;
	uint64_t limit_msec; /* TODO: Implement. */
	uint64_t num_samples;
	void *session_dev_id;
};

static const int hwcaps[] = {
	SR_HWCAP_OSCILLOSCOPE,
	SR_HWCAP_LIMIT_SAMPLES,
	// SR_HWCAP_LIMIT_MSEC,
	// SR_HWCAP_CONTINUOUS,
	0,
};

static const char *probe_names[] = {
	"Probe",
	NULL,
};

static GSList *dev_insts = NULL;

/* Function prototypes. */
static int hw_dev_acquisition_stop(int dev_index, void *cb_data);

static int hw_init(const char *devinfo)
{
	struct sr_dev_inst *sdi;
	struct context *ctx;
	int devcnt = 0;

	/* Avoid compiler warnings. */
	(void)devinfo; /* TODO: This specifies the serial port to use. */

	if (!(ctx = g_try_malloc0(sizeof(struct context)))) {
		sr_err("va18b: %s: ctx malloc failed.", __func__);
		return 0;
	}

	ctx->limit_samples = 0;
	ctx->limit_msec = 0;
	ctx->num_samples = 0;
	ctx->session_dev_id = NULL;

	if (!(sdi = sr_dev_inst_new(devcnt, SR_ST_ACTIVE,
				    "Mastech", "VA18B", ""))) {
		sr_err("va18b: %s: sr_dev_inst_new returned NULL.", __func__);
		return 0;
	}

	sdi->priv = ctx;
	dev_insts = g_slist_append(dev_insts, sdi);

	devcnt = 1;

	return devcnt;
}

static int hw_dev_open(int dev_index)
{
	/* Avoid compiler warnings. */
	(void)dev_index;

	/* TODO. */

	return SR_OK;
}

static int hw_dev_close(int dev_index)
{
	/* Avoid compiler warnings. */
	(void)dev_index;

	/* TODO. */

	return SR_OK;
}

static int hw_cleanup(void)
{
	GSList *l;
	struct sr_dev_inst *sdi;
	struct context *ctx;

	/* Properly close and free all devices. */
	for (l = dev_insts; l; l = l->next) {
		if (!(sdi = l->data)) {
			/* Log error, but continue cleaning up the rest. */
			sr_err("va18b: %s: sdi was NULL, continuing.",
			       __func__);
			continue;
		}
		if (!(ctx = sdi->priv)) {
			/* Log error, but continue cleaning up the rest. */
			sr_err("va18b: %s: sdi->priv was NULL, continuing.",
			       __func__);
			continue;
		}

		/* TODO. */

		sr_dev_inst_free(sdi);
	}

	g_slist_free(dev_insts);
	dev_insts = NULL;

	return SR_OK;
}

static const void *hw_dev_info_get(int dev_index, int dev_info_id)
{
	struct sr_dev_inst *sdi;
	struct context *ctx;
	const void *info;
	uint64_t tmp;
	int tmpint;

	if (!(sdi = sr_dev_inst_get(dev_insts, dev_index))) {
		sr_err("va18b: %s: sdi was NULL.", __func__);
		return NULL;
	}

	if (!(ctx = sdi->priv)) {
		sr_err("va18b: %s: sdi->priv was NULL.", __func__);
		return NULL;
	}

	sr_spew("va18b: %s: dev_index %d, dev_info_id %d.", __func__,
		dev_index, dev_info_id);

	switch (dev_info_id) {
	case SR_DI_INST:
		info = sdi;
		sr_spew("va18b: %s: Returning sdi.", __func__);
		break;
	case SR_DI_NUM_PROBES:
		tmpint = 1;
		info = (int *)tmpint;
		sr_spew("va18b: %s: Returning number of probes: 1.", __func__);
		break;
	case SR_DI_PROBE_NAMES:
		info = probe_names;
		sr_spew("va18b: %s: Returning probenames.", __func__);
		break;
	case SR_DI_CUR_SAMPLERATE:
		/* FIXME */
		tmp = 1;
		info = (uint64_t *)&tmp;
		sr_spew("va18b: %s: Returning samplerate: %" PRIu64 "Hz.",
			__func__, tmp);
		break;
	default:
		/* Unknown device info ID, return NULL. */
		sr_err("va18b: %s: Unknown device info ID: %d.",
		       __func__, dev_info_id);
		info = NULL;
		break;
	}

	return info;
}

static int hw_dev_status_get(int dev_index)
{
	struct sr_dev_inst *sdi;

	if (!(sdi = sr_dev_inst_get(dev_insts, dev_index))) {
		sr_err("va18b: %s: sdi was NULL, device not found.", __func__);
		return SR_ST_NOT_FOUND;
	}

	sr_dbg("va18b: Returning status: %d.", sdi->status);

	return sdi->status;
}

static const int *hw_hwcap_get_all(void)
{
	sr_spew("va18b: Returning list of device capabilities.");

	return hwcaps;
}

static int hw_dev_config_set(int dev_index, int hwcap, const void *value)
{
	struct sr_dev_inst *sdi;
	struct context *ctx;

	if (!(sdi = sr_dev_inst_get(dev_insts, dev_index))) {
		sr_err("va18b: %s: sdi was NULL.", __func__);
		return SR_ERR_BUG;
	}

	if (!(ctx = sdi->priv)) {
		sr_err("va18b: %s: sdi->priv was NULL.", __func__);
		return SR_ERR_BUG;
	}

	sr_spew("va18b: %s: dev_index %d, hwcap %d.", __func__,
		dev_index, hwcap);

	switch (hwcap) {
	case SR_HWCAP_PROBECONFIG:
		/* TODO: Required? */
		break;
	case SR_HWCAP_LIMIT_MSEC:
		if (*(const uint64_t *)value == 0) {
			sr_err("va18b: %s: LIMIT_MSEC can't be 0.", __func__);
			return SR_ERR;
		}
		ctx->limit_msec = *(const uint64_t *)value;
		sr_dbg("va18b: Setting LIMIT_MSEC to %" PRIu64 ".",
		       ctx->limit_msec);
		break;
	case SR_HWCAP_LIMIT_SAMPLES:
		if (*(const uint64_t *)value < MIN_NUM_SAMPLES) {
			sr_err("va18b: %s: LIMIT_SAMPLES too small.", __func__);
			return SR_ERR;
		}
		ctx->limit_samples = *(const uint64_t *)value;
		sr_dbg("va18b: Setting LIMIT_SAMPLES to %" PRIu64 ".",
		       ctx->limit_samples);
		break;
	default:
		/* Unknown capability, return SR_ERR. */
		sr_err("va18b: %s: Unknown capability: %d.", __func__, hwcap);
		return SR_ERR;
		break;
	}

	return SR_OK;
}

static int receive_data(int fd, int revents, void *cb_data)
{
	struct sr_dev_inst *sdi;
	struct sr_datafeed_packet packet;
	struct sr_datafeed_analog analog;
	struct context *ctx;
	int num_probes;

	/* Avoid compiler warnings. */
	(void)fd;
	(void)revents;

	if (!(sdi = cb_data)) {
		sr_err("va18b: %s: cb_data was NULL.", __func__);
		return FALSE;
	}

	if (!(ctx = sdi->priv)) {
		sr_err("va18b: %s: sdi->priv was NULL.", __func__);
		return FALSE;
	}

	sr_dbg("va18b: Sending SR_DF_ANALOG packet with 1 sample.");
	/* TODO: timestamp. */
	num_probes = 1;
	packet.type = SR_DF_ANALOG;
	packet.payload = &analog;
	analog.num_samples = 1;
	analog.mq = SR_MQ_VOLTAGE;
	analog.unit = SR_UNIT_VOLT;
	/* TODO: Check alloc return value. */
	analog.data = g_try_malloc(analog.num_samples * sizeof(float) * num_probes);
	analog.data[0] = rand() % 42; /* Transmit dummy data for now. */
	sr_session_send(ctx->session_dev_id, &packet);

	ctx->num_samples++;

	/* Support for SR_HWCAP_LIMIT_SAMPLES. */
	if (ctx->limit_samples > 0 && ctx->num_samples > ctx->limit_samples) {
		hw_dev_acquisition_stop(0 /* FIXME? */, cb_data);
		return FALSE;
	}

	return TRUE;
}

static int hw_dev_acquisition_start(int dev_index, void *cb_data)
{
	struct sr_datafeed_packet packet;
	struct sr_datafeed_header header;
	struct sr_datafeed_meta_analog meta;
	struct sr_dev_inst *sdi;
	struct context *ctx;

	if (!(sdi = sr_dev_inst_get(dev_insts, dev_index))) {
		sr_err("va18b: %s: sdi was NULL.", __func__);
		return SR_ERR_BUG;
	}

	if (!(ctx = sdi->priv)) {
		sr_err("va18b: %s: sdi->priv was NULL.", __func__);
		return SR_ERR_BUG;
	}

	sr_dbg("va18b: Starting acquisition.");

	ctx->session_dev_id = cb_data;

	/* Send header packet to the session bus. */
	sr_dbg("va18b: Sending SR_DF_HEADER.");
	packet.type = SR_DF_HEADER;
	packet.payload = (uint8_t *)&header;
	header.feed_version = 1;
	gettimeofday(&header.starttime, NULL);
	sr_session_send(ctx->session_dev_id, &packet);

	/* Send metadata about the SR_DF_ANALOG packets to come. */
	sr_dbg("va18b: Sending SR_DF_META_ANALOG.");
	packet.type = SR_DF_META_ANALOG;
	packet.payload = &meta;
	meta.num_probes = 1;
	sr_session_send(ctx->session_dev_id, &packet);

	/* Hook up a dummy handler to receive data from the device. */
	sr_source_add(-1, G_IO_IN, 0, receive_data, sdi);

	return SR_OK;
}

static int hw_dev_acquisition_stop(int dev_index, void *cb_data)
{
	struct sr_datafeed_packet packet;

	/* Avoid compiler warnings. */
	(void)dev_index;

	sr_dbg("va18b: Stopping acquisition.");

	/* Send end packet to the session bus. */
	sr_dbg("va18b: Sending SR_DF_END.");
	packet.type = SR_DF_END;
	sr_session_send(cb_data, &packet);

	return SR_OK;
}

SR_PRIV struct sr_dev_driver mastech_va18b_driver_info = {
	.name = "mastech-va18b",
	.longname = "Mastech VA18B",
	.api_version = 1,
	.init = hw_init,
	.cleanup = hw_cleanup,
	.dev_open = hw_dev_open,
	.dev_close = hw_dev_close,
	.dev_info_get = hw_dev_info_get,
	.dev_status_get = hw_dev_status_get,
	.hwcap_get_all = hw_hwcap_get_all,
	.dev_config_set = hw_dev_config_set,
	.dev_acquisition_start = hw_dev_acquisition_start,
	.dev_acquisition_stop = hw_dev_acquisition_stop,
};
