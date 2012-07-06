/*
 * This file is part of the sigrok project.
 *
 * Copyright (C) 2010-2012 Bert Vermeulen <bert@biot.com>
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

#ifndef LIBSIGROK_SIGROK_H
#define LIBSIGROK_SIGROK_H

#include <stdio.h>
#include <sys/time.h>
#include <stdint.h>
#include <inttypes.h>
#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Status/error codes returned by libsigrok functions.
 *
 * All possible return codes of libsigrok functions must be listed here.
 * Functions should never return hardcoded numbers as status, but rather
 * use these #defines instead. All error codes are negative numbers.
 *
 * The error codes are globally unique in libsigrok, i.e. if one of the
 * libsigrok functions returns a "malloc error" it must be exactly the same
 * return value as used by all other functions to indicate "malloc error".
 * There must be no functions which indicate two different errors via the
 * same return code.
 *
 * Also, for compatibility reasons, no defined return codes are ever removed
 * or reused for different #defines later. You can only add new #defines and
 * return codes, but never remove or redefine existing ones.
 */
#define SR_OK                 0 /* No error */
#define SR_ERR               -1 /* Generic/unspecified error */
#define SR_ERR_MALLOC        -2 /* Malloc/calloc/realloc error */
#define SR_ERR_ARG           -3 /* Function argument error */
#define SR_ERR_BUG           -4 /* Errors hinting at internal bugs */
#define SR_ERR_SAMPLERATE    -5 /* Incorrect samplerate */

#define SR_MAX_NUM_PROBES    64 /* Limited by uint64_t. */
#define SR_MAX_PROBENAME_LEN 32

/* Handy little macros */
#define SR_HZ(n)  (n)
#define SR_KHZ(n) ((n) * 1000)
#define SR_MHZ(n) ((n) * 1000000)
#define SR_GHZ(n) ((n) * 1000000000)

#define SR_HZ_TO_NS(n) (1000000000 / (n))

/* libsigrok loglevels. */
#define SR_LOG_NONE           0 /**< Output no messages at all. */
#define SR_LOG_ERR            1 /**< Output error messages. */
#define SR_LOG_WARN           2 /**< Output warnings. */
#define SR_LOG_INFO           3 /**< Output informational messages. */
#define SR_LOG_DBG            4 /**< Output debug messages. */
#define SR_LOG_SPEW           5 /**< Output very noisy debug messages. */

/*
 * Use SR_API to mark public API symbols, and SR_PRIV for private symbols.
 *
 * Variables and functions marked 'static' are private already and don't
 * need SR_PRIV. However, functions which are not static (because they need
 * to be used in other libsigrok-internal files) but are also not meant to
 * be part of the public libsigrok API, must use SR_PRIV.
 *
 * This uses the 'visibility' feature of gcc (requires gcc >= 4.0).
 *
 * This feature is not available on MinGW/Windows, as it is a feature of
 * ELF files and MinGW/Windows uses PE files.
 *
 * Details: http://gcc.gnu.org/wiki/Visibility
 */

/* Marks public libsigrok API symbols. */
#ifndef _WIN32
#define SR_API __attribute__((visibility("default")))
#else
#define SR_API
#endif

/* Marks private, non-public libsigrok symbols (not part of the API). */
#ifndef _WIN32
#define SR_PRIV __attribute__((visibility("hidden")))
#else
#define SR_PRIV
#endif

typedef int (*sr_receive_data_callback_t)(int fd, int revents, void *cb_data);

/* Data types used by hardware drivers for dev_config_set() */
enum {
	SR_T_UINT64,
	SR_T_CHAR,
	SR_T_BOOL,
	SR_T_FLOAT,
	SR_T_RATIONAL_PERIOD,
	SR_T_RATIONAL_VOLT,
	SR_T_KEYVALUE,
};

struct sr_rational {
	/* numerator */
	uint64_t p;
	/* denominator */
	uint64_t q;
};

/* sr_datafeed_packet.type values */
enum {
	SR_DF_HEADER,
	SR_DF_END,
	SR_DF_TRIGGER,
	SR_DF_LOGIC,
	SR_DF_META_LOGIC,
	SR_DF_ANALOG,
	SR_DF_META_ANALOG,
	SR_DF_FRAME_BEGIN,
	SR_DF_FRAME_END,
};

/* sr_datafeed_analog.mq values */
enum {
	SR_MQ_VOLTAGE,
	SR_MQ_CURRENT,
	SR_MQ_RESISTANCE,
	SR_MQ_CAPACITANCE,
	SR_MQ_TEMPERATURE,
	SR_MQ_FREQUENCY,
	SR_MQ_DUTY_CYCLE,
};

/* sr_datafeed_analog.unit values */
enum {
	SR_UNIT_VOLT,
	SR_UNIT_AMPERE,
	SR_UNIT_OHM,
	SR_UNIT_FARAD,
	SR_UNIT_CELSIUS,
	SR_UNIT_KELVIN,
	SR_UNIT_HERTZ,
	SR_UNIT_PERCENTAGE,
};

struct sr_datafeed_packet {
	uint16_t type;
	void *payload;
};

struct sr_datafeed_header {
	int feed_version;
	struct timeval starttime;
};

struct sr_datafeed_meta_logic {
	int num_probes;
	uint64_t samplerate;
};

struct sr_datafeed_logic {
	uint64_t length;
	uint16_t unitsize;
	void *data;
};

struct sr_datafeed_meta_analog {
	int num_probes;
};

struct sr_datafeed_analog {
	int num_samples;
	int mq; /* Measured quantity (e.g. voltage, current, temperature) */
	int unit; /* Unit in which the MQ is measured. */
	float *data;
};

struct sr_input {
	struct sr_input_format *format;
	char *param;
	struct sr_dev *vdev;
};

struct sr_input_format {
	char *id;
	char *description;
	int (*format_match) (const char *filename);
	int (*init) (struct sr_input *in);
	int (*loadfile) (struct sr_input *in, const char *filename);
};

struct sr_output {
	struct sr_output_format *format;
	struct sr_dev *dev;
	char *param;
	void *internal;
};

struct sr_output_format {
	char *id;
	char *description;
	int df_type;
	int (*init) (struct sr_output *o);
	int (*data) (struct sr_output *o, const uint8_t *data_in,
		     uint64_t length_in, uint8_t **data_out,
		     uint64_t *length_out);
	int (*event) (struct sr_output *o, int event_type, uint8_t **data_out,
		      uint64_t *length_out);
};

struct sr_datastore {
	/* Size in bytes of the number of units stored in this datastore */
	int ds_unitsize;
	unsigned int num_units; /* TODO: uint64_t */
	GSList *chunklist;
};

/*
 * This represents a generic device connected to the system.
 * For device-specific information, ask the driver. The driver_index refers
 * to the device index within that driver; it may be handling more than one
 * device. All relevant driver calls take a dev_index parameter for this.
 */
struct sr_dev {
	/* Which driver handles this device */
	struct sr_dev_driver *driver;
	/* A driver may handle multiple devices of the same type */
	int driver_index;
	/* List of struct sr_probe* */
	GSList *probes;
	/* Data acquired by this device, if any */
	struct sr_datastore *datastore;
};

enum {
	SR_PROBE_TYPE_LOGIC,
};

struct sr_probe {
	int index;
	int type;
	gboolean enabled;
	char *name;
	char *trigger;
};

/* Hardware driver capabilities */
enum {
	SR_HWCAP_DUMMY = 0, /* Used to terminate lists. Must be 0! */

	/*--- Device classes ------------------------------------------------*/

	/** The device can act as logic analyzer. */
	SR_HWCAP_LOGIC_ANALYZER,

	/** The device can act as an oscilloscope. */
	SR_HWCAP_OSCILLOSCOPE,

	/** The device can act as a multimeter. */
	SR_HWCAP_MULTIMETER,

	/** The device is a demo device. */
	SR_HWCAP_DEMO_DEV,


	/*--- Device communication ------------------------------------------*/
	/** Some drivers cannot detect the exact model they're talking to. */
	SR_HWCAP_MODEL,

	/** Specification on how to connect to a device */
	SR_HWCAP_CONN,

	/** Serial communication spec: <data bits><parity><stop bit> e.g. 8n1 */
	SR_HWCAP_SERIALCOMM,


	/*--- Device configuration ------------------------------------------*/

	/** The device supports setting/changing its samplerate. */
	SR_HWCAP_SAMPLERATE,

	/* TODO: Better description? Rename to PROBE_AND_TRIGGER_CONFIG? */
	/** The device supports setting a probe mask. */
	SR_HWCAP_PROBECONFIG,

	/** The device supports setting a pre/post-trigger capture ratio. */
	SR_HWCAP_CAPTURE_RATIO,

	/* TODO? */
	/** The device supports setting a pattern (pattern generator mode). */
	SR_HWCAP_PATTERN_MODE,

	/** The device supports Run Length Encoding. */
	SR_HWCAP_RLE,

	/** The device supports setting trigger slope. */
	SR_HWCAP_TRIGGER_SLOPE,

	/** Trigger source. */
	SR_HWCAP_TRIGGER_SOURCE,

	/** Horizontal trigger position */
	SR_HWCAP_HORIZ_TRIGGERPOS,

	/** Buffer size. */
	SR_HWCAP_BUFFERSIZE,

	/** Time base. */
	SR_HWCAP_TIMEBASE,

	/** Filter. */
	SR_HWCAP_FILTER,

	/** Volts/div. */
	SR_HWCAP_VDIV,

	/** Coupling. */
	SR_HWCAP_COUPLING,


	/*--- Special stuff -------------------------------------------------*/

	/* TODO: Better description. */
	/** The device supports specifying a capturefile to inject. */
	SR_HWCAP_CAPTUREFILE,

	/* TODO: Better description. */
	/** The device supports specifying the capturefile unit size. */
	SR_HWCAP_CAPTURE_UNITSIZE,

	/* TODO: Better description. */
	/** The device supports setting the number of probes. */
	SR_HWCAP_CAPTURE_NUM_PROBES,


	/*--- Acquisition modes ---------------------------------------------*/

	/**
	 * The device supports setting a sample time limit, i.e. how long the
	 * sample acquisition should run (in ms).
	 */
	SR_HWCAP_LIMIT_MSEC,

	/**
	 * The device supports setting a sample number limit, i.e. how many
	 * samples should be acquired.
	 */
	SR_HWCAP_LIMIT_SAMPLES,

	/**
	 * The device supports setting a frame limit, i.e. how many
	 * frames should be acquired.
	 */
	SR_HWCAP_LIMIT_FRAMES,

	/**
	 * The device supports continuous sampling, i.e. neither a time limit
	 * nor a sample number limit has to be supplied, it will just acquire
	 * samples continuously, until explicitly stopped by a certain command.
	 */
	SR_HWCAP_CONTINUOUS,

};

struct sr_hwcap_option {
	int hwcap;
	int type;
	char *description;
	char *shortname;
};

struct sr_dev_inst {
	int index;
	int status;
	int inst_type;
	char *vendor;
	char *model;
	char *version;
	void *priv;
};

/* sr_dev_inst types */
enum {
	/** Device instance type for USB devices. */
	SR_INST_USB,
	/** Device instance type for serial port devices. */
	SR_INST_SERIAL,
};

/* Device instance status */
enum {
	SR_ST_NOT_FOUND,
	/* Found, but still booting */
	SR_ST_INITIALIZING,
	/* Live, but not in use */
	SR_ST_INACTIVE,
	/* Actively in use in a session */
	SR_ST_ACTIVE,
};

/*
 * TODO: This sucks, you just kinda have to "know" the returned type.
 * TODO: Need a DI to return the number of trigger stages supported.
 */

/* Device info IDs */
enum {
	/* struct sr_dev_inst for this specific device */
	SR_DI_INST,
	/* The number of probes connected to this device */
	SR_DI_NUM_PROBES,
	/* The probe names on this device */
	SR_DI_PROBE_NAMES,
	/* Samplerates supported by this device, (struct sr_samplerates) */
	SR_DI_SAMPLERATES,
	/* Types of logic trigger supported, out of "01crf" (char *) */
	SR_DI_TRIGGER_TYPES,
	/* The currently set samplerate in Hz (uint64_t) */
	SR_DI_CUR_SAMPLERATE,
	/* Supported patterns (in pattern generator mode) */
	SR_DI_PATTERNS,
	/* Supported buffer sizes */
	SR_DI_BUFFERSIZES,
	/* Supported time bases */
	SR_DI_TIMEBASES,
	/* Supported trigger sources */
	SR_DI_TRIGGER_SOURCES,
	/* Supported filter targets */
	SR_DI_FILTERS,
	/* Valid volts/div values */
	SR_DI_VDIVS,
	/* Coupling options */
	SR_DI_COUPLING,
};

/*
 * A device supports either a range of samplerates with steps of a given
 * granularity, or is limited to a set of defined samplerates. Use either
 * step or list, but not both.
 */
struct sr_samplerates {
	uint64_t low;
	uint64_t high;
	uint64_t step;
	const uint64_t *list;
};

struct sr_dev_driver {
	/* Driver-specific */
	char *name;
	char *longname;
	int api_version;
	int (*init) (const char *devinfo);
	int (*cleanup) (void);

	/* Device-specific */
	int (*dev_open) (int dev_index);
	int (*dev_close) (int dev_index);
	const void *(*dev_info_get) (int dev_index, int dev_info_id);
	int (*dev_status_get) (int dev_index);
	const int *(*hwcap_get_all) (void);
	int (*dev_config_set) (int dev_index, int hwcap, const void *value);
	int (*dev_acquisition_start) (int dev_index, void *session_dev_id);
	int (*dev_acquisition_stop) (int dev_index, void *session_dev_id);
};

struct sr_session {
	/* List of struct sr_dev* */
	GSList *devs;
	/* list of sr_receive_data_callback_t */
	GSList *datafeed_callbacks;
	GTimeVal starttime;
	gboolean running;

	unsigned int num_sources;

	/* Both "sources" and "pollfds" are of the same size and contain pairs of
	 * descriptor and callback function. We can not embed the GPollFD into the
	 * source struct since we want to be able to pass the array of all poll
	 * descriptors to g_poll.
	 */
	struct source *sources;
	GPollFD *pollfds;
	int source_timeout;
};

#include "proto.h"
#include "version.h"

#ifdef __cplusplus
}
#endif

#endif
