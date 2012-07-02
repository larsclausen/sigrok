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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <glib.h>
#include "libsigrok.h"
#include "libsigrok-internal.h"

struct source {
	int timeout;
	sr_receive_data_callback_t cb;
	void *cb_data;

	/* This is used to keep track of the object (fd, pollfd or channel) which is
	 * being polled and will be used to match the source when removing it again.
	 */
	gintptr poll_object;
};

struct sr_session_source {
	GSource source;

	unsigned int num_sources;
	/* Both "sources" and "pollfds" are of the same size and contain pairs of
	 * descriptor and callback function. We can not embed the GPollFD into the
	 * source struct since we want to be able to pass the array of all poll
	 * descriptors to g_poll.
	 */
	GPollFD *pollfds;
	struct source *sources;
	int source_timeout;

	gint64 expiration;
};

/* There can only be one session at a time. */
/* 'session' is not static, it's used elsewhere (via 'extern'). */
struct sr_session *session;

static int _sr_session_source_remove(gintptr poll_object);

static gboolean sr_session_source_prepare(GSource *gsource, gint *timeout)
{
	struct sr_session_source *source = (struct sr_session_source *)gsource;
	*timeout = source->source_timeout;
	source->expiration = g_source_get_time(gsource) + source->source_timeout;
	return FALSE;
}

static gboolean sr_session_source_check(GSource *gsource)
{
	struct sr_session_source *source = (struct sr_session_source *)gsource;
	unsigned int i;

	for (i = 0; i < source->num_sources; i++) {
		if (source->pollfds[i].revents > 0)
			return TRUE;
	}

	return source->source_timeout > 0 &&
		source->expiration <= g_source_get_time(gsource);
}

static gboolean sr_session_source_dispatch(GSource *gsource,
		GSourceFunc callback, gpointer user_data)
{
	struct sr_session_source *source = (struct sr_session_source *)gsource;
	gboolean timedout;
	unsigned int i;

	(void)callback;
	(void)user_data;

	timedout = source->source_timeout > 0 &&
			source->expiration <= g_source_get_time(gsource);

	for (i = 0; i < source->num_sources; i++) {
		if ((source->pollfds[i].revents > 0) ||
			(timedout &&
			source->sources[i].timeout == source->source_timeout)) {
			if (!source->sources[i].cb(source->pollfds[i].fd, source->pollfds[i].revents,
					  source->sources[i].cb_data))
				_sr_session_source_remove(source->sources[i].poll_object);
		}
	}
	return TRUE;
}

static void sr_session_source_finalize(GSource *gsource)
{
	struct sr_session_source *source = (struct sr_session_source *)gsource;

	g_free(source->sources);
	g_free(source->pollfds);
}

static GSourceFuncs sr_session_source_funcs = {
	sr_session_source_prepare,
	sr_session_source_check,
	sr_session_source_dispatch,
	sr_session_source_finalize,
	NULL, NULL
};

/**
 * Create a new session.
 *
 * TODO: Should it use the file-global "session" variable or take an argument?
 *       The same question applies to all the other session functions.
 *
 * @return A pointer to the newly allocated session, or NULL upon errors.
 */
SR_API struct sr_session *sr_session_new(void)
{
	if (!(session = g_try_malloc0(sizeof(struct sr_session)))) {
		sr_err("session: %s: session malloc failed", __func__);
		return NULL; /* TODO: SR_ERR_MALLOC? */
	}

	session->source = (struct sr_session_source *)g_source_new(&sr_session_source_funcs,
			sizeof(*session->source));
	session->source->num_sources = 0;
	session->source->sources = NULL;
	session->source->pollfds = NULL;
	session->source->source_timeout = -1;

	return session;
}

/**
 * Destroy the current session.
 *
 * This frees up all memory used by the session.
 *
 * @return SR_OK upon success, SR_ERR_BUG if no session exists.
 */
SR_API int sr_session_destroy(void)
{
	if (!session) {
		sr_err("session: %s: session was NULL", __func__);
		return SR_ERR_BUG;
	}

	sr_session_dev_remove_all();
	g_source_destroy(&session->source->source);

	/* TODO: Error checks needed? */

	/* TODO: Loop over protocol decoders and free them. */
	g_free(session);
	session = NULL;

	return SR_OK;
}

static void sr_dev_close(struct sr_dev *dev)
{
	if (dev->driver->dev_close)
		dev->driver->dev_close(dev->driver_index);
}

/**
 * Remove all the devices from the current session. TODO?
 *
 * The session itself (i.e., the struct sr_session) is not free'd and still
 * exists after this function returns.
 *
 * @return SR_OK upon success, SR_ERR_BUG if no session exists.
 */
SR_API int sr_session_dev_remove_all(void)
{
	if (!session) {
		sr_err("session: %s: session was NULL", __func__);
		return SR_ERR_BUG;
	}

	g_slist_free_full(session->devs, (GDestroyNotify)sr_dev_close);
	session->devs = NULL;

	return SR_OK;
}

/**
 * Add a device to the current session.
 *
 * @param dev The device to add to the current session. Must not be NULL.
 *            Also, dev->driver and dev->driver->dev_open must not be NULL.
 *
 * @return SR_OK upon success, SR_ERR_ARG upon invalid arguments.
 */
SR_API int sr_session_dev_add(struct sr_dev *dev)
{
	int ret;

	if (!dev) {
		sr_err("session: %s: dev was NULL", __func__);
		return SR_ERR_ARG;
	}

	if (!session) {
		sr_err("session: %s: session was NULL", __func__);
		return SR_ERR_BUG;
	}

	/* If dev->driver is NULL, this is a virtual device. */
	if (!dev->driver) {
		sr_dbg("session: %s: dev->driver was NULL, this seems to be "
		       "a virtual device; continuing", __func__);
		/* Just add the device, don't run dev_open(). */
		session->devs = g_slist_append(session->devs, dev);
		return SR_OK;
	}

	/* dev->driver is non-NULL (i.e. we have a real device). */
	if (!dev->driver->dev_open) {
		sr_err("session: %s: dev->driver->dev_open was NULL",
		       __func__);
		return SR_ERR_BUG;
	}

	if ((ret = dev->driver->dev_open(dev->driver_index)) != SR_OK) {
		sr_err("session: %s: dev_open failed (%d)", __func__, ret);
		return ret;
	}

	session->devs = g_slist_append(session->devs, dev);

	return SR_OK;
}

/**
 * Remove all datafeed callbacks in the current session.
 *
 * @return SR_OK upon success, SR_ERR_BUG if no session exists.
 */
SR_API int sr_session_datafeed_callback_remove_all(void)
{
	if (!session) {
		sr_err("session: %s: session was NULL", __func__);
		return SR_ERR_BUG;
	}

	g_slist_free(session->datafeed_callbacks);
	session->datafeed_callbacks = NULL;

	return SR_OK;
}

/**
 * Add a datafeed callback to the current session.
 *
 * @param cb Function to call when a chunk of data is received.
 *           Must not be NULL.
 *
 * @return SR_OK upon success, SR_ERR_BUG if no session exists.
 */
SR_API int sr_session_datafeed_callback_add(sr_datafeed_callback_t cb)
{
	if (!session) {
		sr_err("session: %s: session was NULL", __func__);
		return SR_ERR_BUG;
	}

	if (!cb) {
		sr_err("session: %s: cb was NULL", __func__);
		return SR_ERR_ARG;
	}

	session->datafeed_callbacks =
	    g_slist_append(session->datafeed_callbacks, cb);

	return SR_OK;
}

/**
 * TODO.
 */
static int sr_session_run_poll(void)
{
	struct sr_session_source *source = session->source;
	unsigned int i;
	int ret;

	while (session->running) {
		ret = g_poll(source->pollfds, source->num_sources, source->source_timeout);

		for (i = 0; i < source->num_sources; i++) {
			if (source->pollfds[i].revents > 0 || (ret == 0
				&& source->source_timeout == source->sources[i].timeout)) {
				/*
				 * Invoke the source's callback on an event,
				 * or if the poll timeout out and this source
				 * asked for that timeout.
				 */
				if (!source->sources[i].cb(source->pollfds[i].fd, source->pollfds[i].revents,
						  source->sources[i].cb_data))
					_sr_session_source_remove(source->sources[i].poll_object);
			}
		}
	}

	return SR_OK;
}

/**
 * Attach a session to a GMainContext
 *
 * @param context The session will be attached to this GMainContext
 *
 * Note: Once attached it can not be attached to another GMainContext.
 * Destroying the session will remove it from the its GMainContext.
 */
SR_API void sr_session_attach(GMainContext *context)
{
	g_source_attach(&session->source->source, context);
}

/**
 * Start a session.
 *
 * There can only be one session at a time.
 *
 * @return SR_OK upon success, SR_ERR upon errors.
 */
SR_API int sr_session_start(void)
{
	struct sr_dev *dev;
	GSList *l;
	int ret;

	if (!session) {
		sr_err("session: %s: session was NULL; a session must be "
		       "created first, before starting it.", __func__);
		return SR_ERR_BUG;
	}

	if (!session->devs) {
		/* TODO: Actually the case? */
		sr_err("session: %s: session->devs was NULL; a session "
		       "cannot be started without devices.", __func__);
		return SR_ERR_BUG;
	}

	/* TODO: Check driver_index validity? */

	sr_info("session: starting");

	for (l = session->devs; l; l = l->next) {
		dev = l->data;
		/* TODO: Check for dev != NULL. */
		if ((ret = dev->driver->dev_acquisition_start(
				dev->driver_index, dev)) != SR_OK) {
			sr_err("session: %s: could not start an acquisition "
			       "(%d)", __func__, ret);
			break;
		}
	}

	/* TODO: What if there are multiple devices? Which return code? */
	session->running = TRUE;

	return ret;
}

/**
 * Run the session.
 *
 * TODO: Various error checks etc.
 *
 * @return SR_OK upon success, SR_ERR_BUG upon errors.
 */
SR_API int sr_session_run(void)
{
	struct sr_session_source *source;
	if (!session) {
		sr_err("session: %s: session was NULL; a session must be "
		       "created first, before running it.", __func__);
		return SR_ERR_BUG;
	}

	source = session->source;

	if (!session->devs) {
		/* TODO: Actually the case? */
		sr_err("session: %s: session->devs was NULL; a session "
		       "cannot be run without devices.", __func__);
		return SR_ERR_BUG;
	}

	sr_info("session: running");
	session->running = TRUE;

	/* Do we have real sources? */
	if (source->num_sources == 1 && source->pollfds[0].fd == -1) {
		/* Dummy source, freewheel over it. */
		while (session->running)
			source->sources[0].cb(-1, 0, source->sources[0].cb_data);
	} else {
		/* Real sources, use g_poll() main loop. */
		sr_session_run_poll();
	}

	return SR_OK;
}

/**
 * Halt the current session.
 *
 * This function is deprecated and should not be used in new code, use
 * sr_session_stop() instead. The behaviour of this function is identical to
 * sr_session_stop().
 *
 * @return SR_OK upon success, SR_ERR_BUG if no session exists.
 */
SR_API int sr_session_halt(void)
{
	return sr_session_stop();
}

/**
 * Stop the current session.
 *
 * The current session is stopped immediately, with all acquisition sessions
 * being stopped and hardware drivers cleaned up.
 *
 * @return SR_OK upon success, SR_ERR_BUG if no session exists.
 */
SR_API int sr_session_stop(void)
{
	struct sr_dev *dev;
	GSList *l;

	if (!session) {
		sr_err("session: %s: session was NULL", __func__);
		return SR_ERR_BUG;
	}

	if (!session->running)
		return SR_OK;

	sr_info("session: stopping");
	session->running = FALSE;

	for (l = session->devs; l; l = l->next) {
		dev = l->data;
		/* Check for dev != NULL. */
		if (dev->driver) {
			if (dev->driver->dev_acquisition_stop)
				dev->driver->dev_acquisition_stop(dev->driver_index, dev);
		}
	}

	return SR_OK;
}

/**
 * Debug helper.
 *
 * @param packet The packet to show debugging information for.
 */
static void datafeed_dump(struct sr_datafeed_packet *packet)
{
	struct sr_datafeed_logic *logic;
	struct sr_datafeed_analog *analog;

	switch (packet->type) {
	case SR_DF_HEADER:
		sr_dbg("bus: received SR_DF_HEADER");
		break;
	case SR_DF_TRIGGER:
		sr_dbg("bus: received SR_DF_TRIGGER");
		break;
	case SR_DF_META_LOGIC:
		sr_dbg("bus: received SR_DF_META_LOGIC");
		break;
	case SR_DF_LOGIC:
		logic = packet->payload;
		/* TODO: Check for logic != NULL. */
		sr_dbg("bus: received SR_DF_LOGIC %" PRIu64 " bytes", logic->length);
		break;
	case SR_DF_META_ANALOG:
		sr_dbg("bus: received SR_DF_META_LOGIC");
		break;
	case SR_DF_ANALOG:
		analog = packet->payload;
		/* TODO: Check for analog != NULL. */
		sr_dbg("bus: received SR_DF_ANALOG %d samples", analog->num_samples);
		break;
	case SR_DF_END:
		sr_dbg("bus: received SR_DF_END");
		break;
	case SR_DF_FRAME_BEGIN:
		sr_dbg("bus: received SR_DF_FRAME_BEGIN");
		break;
	case SR_DF_FRAME_END:
		sr_dbg("bus: received SR_DF_FRAME_END");
		break;
	default:
		sr_dbg("bus: received unknown packet type %d", packet->type);
		break;
	}
}

/**
 * Send a packet to whatever is listening on the datafeed bus.
 *
 * Hardware drivers use this to send a data packet to the frontend.
 *
 * @param dev TODO.
 * @param packet The datafeed packet to send to the session bus.
 *
 * @return SR_OK upon success, SR_ERR_ARG upon invalid arguments.
 */
SR_PRIV int sr_session_send(struct sr_dev *dev,
			    struct sr_datafeed_packet *packet)
{
	GSList *l;
	sr_datafeed_callback_t cb;

	if (!dev) {
		sr_err("session: %s: dev was NULL", __func__);
		return SR_ERR_ARG;
	}

	if (!packet) {
		sr_err("session: %s: packet was NULL", __func__);
		return SR_ERR_ARG;
	}

	for (l = session->datafeed_callbacks; l; l = l->next) {
		if (sr_log_loglevel_get() >= SR_LOG_DBG)
			datafeed_dump(packet);
		cb = l->data;
		/* TODO: Check for cb != NULL. */
		cb(dev, packet);
	}

	return SR_OK;
}

static int _sr_session_source_add(GPollFD *pollfd, int timeout,
	sr_receive_data_callback_t cb, void *cb_data, gintptr poll_object)
{
	struct sr_session_source *source = session->source;
	struct source *new_sources, *s;
	unsigned int i;
	GPollFD *new_pollfds;

	if (!cb) {
		sr_err("session: %s: cb was NULL", __func__);
		return SR_ERR_ARG;
	}

	/* This is a bit ugly, but the realloc may change the address of the
	 * pollfds, so we have to remove before them and add them back afterwards. */
	for (i = 0; i < source->num_sources; i++)
		g_source_remove_poll((GSource *)source, &source->pollfds[i]);

	/* Note: cb_data can be NULL, that's not a bug. */

	new_pollfds = g_try_realloc(source->pollfds, sizeof(GPollFD) * (source->num_sources + 1));
	if (!new_pollfds) {
		sr_err("session: %s: new_pollfds malloc failed", __func__);
		return SR_ERR_MALLOC;
	}

	new_sources = g_try_realloc(source->sources, sizeof(struct source) * (source->num_sources + 1));
	if (!new_sources) {
		sr_err("session: %s: new_sources malloc failed", __func__);
		return SR_ERR_MALLOC;
	}

	new_pollfds[source->num_sources] = *pollfd;
	s = &new_sources[source->num_sources];
	s->timeout = timeout;
	s->cb = cb;
	s->cb_data = cb_data;
	s->poll_object = poll_object;

	source->num_sources++;

	for (i = 0; i < source->num_sources; i++)
		g_source_add_poll((GSource *)source, &new_pollfds[i]);

	source->pollfds = new_pollfds;
	source->sources = new_sources;

	if (timeout != source->source_timeout && timeout > 0
	    && (source->source_timeout == -1 || timeout < source->source_timeout))
		source->source_timeout = timeout;

	return SR_OK;
}

/**
 * Add a event source for a file descriptor.
 *
 * @param fd The file descriptor.
 * @param events Events to check for.
 * @param timeout Max time to wait before the callback is called, ignored if 0.
 * @param cb Callback function to add. Must not be NULL.
 * @param cb_data Data for the callback function. Can be NULL.
 *
 * @return SR_OK upon success, SR_ERR_ARG upon invalid arguments, or
 *         SR_ERR_MALLOC upon memory allocation errors.
 */
SR_API int sr_session_source_add(int fd, int events, int timeout,
		sr_receive_data_callback_t cb, void *cb_data)
{
	GPollFD p;

	p.fd = fd;
	p.events = events;

	return _sr_session_source_add(&p, timeout, cb, cb_data, (gintptr)fd);
}

/**
 * Add an event source for a GPollFD.
 *
 * TODO: More error checks etc.
 *
 * @param pollfd The GPollFD.
 * @param timeout Max time to wait before the callback is called, ignored if 0.
 * @param cb Callback function to add. Must not be NULL.
 * @param cb_data Data for the callback function. Can be NULL.
 *
 * @return SR_OK upon success, SR_ERR_ARG upon invalid arguments, or
 *         SR_ERR_MALLOC upon memory allocation errors.
 */
SR_API int sr_session_source_add_pollfd(GPollFD *pollfd, int timeout,
		sr_receive_data_callback_t cb, void *cb_data)
{
	return _sr_session_source_add(pollfd, timeout, cb,
				      cb_data, (gintptr)pollfd);
}

/**
 * Add an event source for a GIOChannel.
 *
 * TODO: More error checks etc.
 *
 * @param channel The GIOChannel.
 * @param events Events to poll on.
 * @param timeout Max time to wait before the callback is called, ignored if 0.
 * @param cb Callback function to add. Must not be NULL.
 * @param cb_data Data for the callback function. Can be NULL.
 *
 * @return SR_OK upon success, SR_ERR_ARG upon invalid arguments, or
 *         SR_ERR_MALLOC upon memory allocation errors.
 */
SR_API int sr_session_source_add_channel(GIOChannel *channel, int events,
		int timeout, sr_receive_data_callback_t cb, void *cb_data)
{
	GPollFD p;

#ifdef _WIN32
	g_io_channel_win32_make_pollfd(channel,
			events, &p);
#else
	p.fd = g_io_channel_unix_get_fd(channel);
	p.events = events;
#endif

	return _sr_session_source_add(&p, timeout, cb, cb_data, (gintptr)channel);
}


static int _sr_session_source_remove(gintptr poll_object)
{
	struct sr_session_source *source = session->source;
	struct source *new_sources;
	GPollFD *new_pollfds;
	unsigned int old, i;

	if (!source->sources || !source->num_sources) {
		sr_err("session: %s: sources was NULL", __func__);
		return SR_ERR_BUG;
	}

	for (old = 0; old < source->num_sources; old++) {
		if (source->sources[old].poll_object == poll_object)
			break;
	}

	/* fd not found, nothing to do */
	if (old == source->num_sources)
		return SR_OK;

	for (i = 0; i < source->num_sources; i++)
		g_source_remove_poll((GSource *)source, &source->pollfds[i]);

	source->num_sources -= 1;

	if (old != source->num_sources) {
		memmove(&source->pollfds[old], &source->pollfds[old+1],
			(source->num_sources - old) * sizeof(GPollFD));
		memmove(&source->sources[old], &source->sources[old+1],
			(source->num_sources - old) * sizeof(struct source));
	}

	new_pollfds = g_try_realloc(source->pollfds, sizeof(GPollFD) * source->num_sources);
	if (!new_pollfds && source->num_sources > 0) {
		sr_err("session: %s: new_pollfds malloc failed", __func__);
		return SR_ERR_MALLOC;
	}

	source->pollfds = new_pollfds;

	new_sources = g_try_realloc(source->sources, sizeof(struct source) * source->num_sources);
	if (!new_sources && source->num_sources > 0) {
		sr_err("session: %s: new_sources malloc failed", __func__);
		return SR_ERR_MALLOC;
	}

	source->sources = new_sources;

	for (i = 0; i < source->num_sources; i++)
		g_source_add_poll((GSource *)source, &source->pollfds[i]);

	return SR_OK;
}

/*
 * Remove the source belonging to the specified file descriptor.
 *
 * TODO: More error checks.
 *
 * @param fd The file descriptor for which the source should be removed.
 *
 * @return SR_OK upon success, SR_ERR_ARG upon invalid arguments, or
 *         SR_ERR_MALLOC upon memory allocation errors, SR_ERR_BUG upon
 *         internal errors.
 */
SR_API int sr_session_source_remove(int fd)
{
	return _sr_session_source_remove((gintptr)fd);
}

/**
 * Remove the source belonging to the specified poll descriptor.
 *
 * TODO: More error checks.
 *
 * @param pollfd The poll descriptor for which the source should be removed.
 *
 * @return SR_OK upon success, SR_ERR_ARG upon invalid arguments, or
 *         SR_ERR_MALLOC upon memory allocation errors, SR_ERR_BUG upon
 *         internal errors.
 */
SR_API int sr_session_source_remove_pollfd(GPollFD *pollfd)
{
	return _sr_session_source_remove((gintptr)pollfd);
}

/*
 * Remove the source belonging to the specified channel.
 *
 * TODO: More error checks.
 *
 * @param channel The channel for which the source should be removed.
 *
 * @return SR_OK upon success, SR_ERR_ARG upon invalid arguments, or
 *         SR_ERR_MALLOC upon memory allocation errors, SR_ERR_BUG upon
 *         internal errors.
 */
SR_API int sr_session_source_remove_channel(GIOChannel *channel)
{
	return _sr_session_source_remove((gintptr)channel);
}
