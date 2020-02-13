/*
 * mod_agora for FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2011-2012, Barracuda Networks Inc.
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is mod_agora for FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * The Initial Developer of the Original Code is Barracuda Networks Inc.
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Mathieu Rene <mrene@avgs.ca>
 * Anthony Minessale II <anthm@freeswitch.org>
 * William King <william.king@quentustech.com>
 * Seven Du <dujinfang@gmail.com>
 *
 * mod_agora.c -- RTMP Endpoint Module
 *
 */

#include "agora.h"
#define AGORA_EVENT_CUSTOM "agora::custom"

SWITCH_MODULE_LOAD_FUNCTION(mod_agora_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_agora_shutdown);
SWITCH_MODULE_RUNTIME_FUNCTION(mod_agora_runtime);
SWITCH_MODULE_DEFINITION(mod_agora, mod_agora_load, mod_agora_shutdown, mod_agora_runtime);

typedef enum {
	TFLAG_IO = (1 << 0),
	TFLAG_DETACHED = (1 << 1), /* Call isn't the current active call */
	TFLAG_BREAK = (1 << 2),
	TFLAG_THREE_WAY = (1 << 3),		   /* In a three-way call */
	TFLAG_VID_WAIT_KEYFRAME = (1 << 4) /* Wait for video keyframe */
} TFLAGS;

struct agora_profile {
	char *name; /* < Profile name */

	const char *appid;
	const char *context;  /* < Default dialplan name */
	const char *dialplan; /* < Default dialplan context */

	switch_memory_pool_t *pool;				  /* < Memory pool */
	switch_thread_rwlock_t *rwlock;			  /* < Rwlock for reference counting */
	uint32_t flags;							  /* < PFLAGS */
	switch_mutex_t *mutex;					  /* < Mutex for call count */
	int calls;								  /* < Active calls count */
	int clients;							  /* < Number of connected clients */
	switch_hash_t *agora_pvt_hash;			  /* < Active rtmp sessions */
	switch_thread_rwlock_t *agora_pvt_rwlock; /* < rwlock for session hashtable */
};
typedef struct agora_profile agora_profile_t;

struct agora_private {
	agora_profile_t *profile;
	switch_codec_t read_codec; //后续把这个交给agora_session初始化
	switch_codec_t write_codec;
	switch_frame_t read_frame;
	unsigned char databuf[SWITCH_RECOMMENDED_BUFFER_SIZE]; /* < Buffer for read_frame */
	unsigned int flags;
	switch_mutex_t *flag_mutex;
	agora_session_t *agora_session;

	switch_caller_profile_t *caller_profile;
	switch_core_session_t *session;
	switch_channel_t *channel;

	const char *auth_user;
	const char *auth_domain;
	const char *auth;

	const char *display_callee_id_name;
	const char *display_callee_id_number;
};
typedef struct agora_private agora_private_t;

/*** Endpoint interface ***/
switch_call_cause_t agora_session_create_call(agora_session_t *rsession, switch_core_session_t **newsession,
											  int read_channel, int write_channel, const char *number,
											  const char *auth_user, const char *auth_domain, switch_event_t *event);

switch_status_t agora_on_execute(switch_core_session_t *session);
switch_status_t agora_send_dtmf(switch_core_session_t *session, const switch_dtmf_t *dtmf);
switch_status_t agora_receive_message(switch_core_session_t *session, switch_core_session_message_t *msg);
switch_status_t agora_receive_event(switch_core_session_t *session, switch_event_t *event);
switch_status_t agora_on_init(switch_core_session_t *session);
switch_status_t agora_on_hangup(switch_core_session_t *session);
switch_status_t agora_on_destroy(switch_core_session_t *session);
switch_status_t agora_on_routing(switch_core_session_t *session);
switch_status_t agora_on_exchange_media(switch_core_session_t *session);
switch_status_t agora_on_soft_execute(switch_core_session_t *session);
switch_call_cause_t agora_outgoing_channel(switch_core_session_t *session, switch_event_t *var_event,
										   switch_caller_profile_t *outbound_profile,
										   switch_core_session_t **new_session, switch_memory_pool_t **pool,
										   switch_originate_flag_t flags, switch_call_cause_t *cancel_cause);
switch_status_t agora_read_frame(switch_core_session_t *session, switch_frame_t **frame, switch_io_flag_t flags,
								 int stream_id);
switch_status_t agora_write_frame(switch_core_session_t *session, switch_frame_t *frame, switch_io_flag_t flags,
								  int stream_id);
switch_status_t agora_kill_channel(switch_core_session_t *session, int sig);

switch_status_t agora_tech_init(agora_private_t *tech_pvt, switch_core_session_t *session);
agora_profile_t *agora_profile_locate(const char *name);
void agora_profile_release(agora_profile_t *profile);

//读取配置文件相关
static switch_status_t config_profile(agora_profile_t *profile, switch_bool_t reload);
static switch_xml_config_item_t *get_instructions(agora_profile_t *profile);

void agora_notify_call_state(switch_core_session_t *session)
{
	// todo
}

switch_state_handler_table_t agora_state_handlers = {
	/*.on_init */ agora_on_init,
	/*.on_routing */ agora_on_routing,
	/*.on_execute */ agora_on_execute,
	/*.on_hangup */ agora_on_hangup,
	/*.on_exchange_media */ agora_on_exchange_media,
	/*.on_soft_execute */ agora_on_soft_execute,
	/*.on_consume_media */ NULL,
	/*.on_hibernate */ NULL,
	/*.on_reset */ NULL,
	/*.on_park */ NULL,
	/*.on_reporting */ NULL,
	/*.on_destroy */ agora_on_destroy};

switch_io_routines_t agora_io_routines = {
	/*.outgoing_channel */ agora_outgoing_channel,
	/*.read_frame */ agora_read_frame,
	/*.write_frame */ agora_write_frame,
	/*.kill_channel */ agora_kill_channel,
	/*.send_dtmf */ agora_send_dtmf,
	/*.receive_message */ agora_receive_message,
	/*.receive_event */ agora_receive_event,
	/*.state_change*/ NULL,
	/*.agora_read_vid_frame */ NULL,
	/*.agora_write_vid_frame */ NULL};

struct mod_agora_globals {
	switch_endpoint_interface_t *agora_endpoint_interface;
	switch_memory_pool_t *pool;
	switch_mutex_t *mutex;
	switch_hash_t *profile_hash;
	switch_thread_rwlock_t *profile_rwlock;
	switch_hash_t *invoke_hash; //底层回调hash，暂时不用
	int running;
};
struct mod_agora_globals agora_globals;

static void agora_set_channel_variables(switch_core_session_t *session)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	agora_private_t *tech_pvt = switch_core_session_get_private(session);

	switch_channel_set_variable(channel, "agora_profile", tech_pvt->profile->name);
	// switch_channel_set_variable_printf(channel, "agora_remote_port", "%d", rsession->remote_port);
}

switch_status_t agora_tech_init(agora_private_t *tech_pvt, switch_core_session_t *session)
{
	switch_assert(session && tech_pvt);
	tech_pvt->read_frame.data = tech_pvt->databuf;
	tech_pvt->read_frame.buflen = sizeof(tech_pvt->databuf);
	// switch_mutex_init(&tech_pvt->mutex, SWITCH_MUTEX_NESTED, switch_core_session_get_pool(session));
	switch_mutex_init(&tech_pvt->flag_mutex, SWITCH_MUTEX_NESTED, switch_core_session_get_pool(session));
	tech_pvt->session = session;
	// session 的初始化 todo fixme

	tech_pvt->channel = switch_core_session_get_channel(session);
	switch_core_session_set_private(session, tech_pvt);
	/* Initialize read & write codecs */
	if (switch_core_codec_init(&tech_pvt->read_codec, /* name */ "L16", /* modname */ NULL,
							   /* fmtp */ NULL, /* rate */ 16000, /* ms */ 20, /* channels */ 1,
							   /* flags */ SWITCH_CODEC_FLAG_ENCODE | SWITCH_CODEC_FLAG_DECODE,
							   /* codec settings */ NULL,
							   switch_core_session_get_pool(session)) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Can't initialize read codec\n");

		return SWITCH_STATUS_FALSE;
	}

	if (switch_core_codec_init(&tech_pvt->write_codec, /* name */ "L16", /* modname */ NULL,
							   /* fmtp */ NULL, /* rate */ 16000, /* ms */ 20, /* channels */ 1,
							   /* flags */ SWITCH_CODEC_FLAG_ENCODE | SWITCH_CODEC_FLAG_DECODE,
							   /* codec settings */ NULL,
							   switch_core_session_get_pool(session)) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Can't initialize write codec\n");

		return SWITCH_STATUS_FALSE;
	}

	switch_core_session_set_read_codec(session, &tech_pvt->read_codec);
	switch_core_session_set_write_codec(session, &tech_pvt->write_codec);
	tech_pvt->agora_session =
		agora_init_session(tech_pvt->caller_profile->destination_number);
	if (tech_pvt->agora_session == NULL) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Can't initialize write codec\n");
		return SWITCH_STATUS_FALSE;
	}

	// static inline uint8_t agora_audio_codec(int channels, int bits, int rate, agora_audio_format_t format) {
	// tech_pvt->audio_codec = 0xB2; //agora_audio_codec(1, 16, 0 /* speex is always 8000  */, agora_AUDIO_SPEEX);

	switch_channel_set_flag(tech_pvt->channel, CF_AUDIO);

	// switch_core_session_start_video_thread(session);

	return SWITCH_STATUS_SUCCESS;
}

/*
   State methods they get called when the state changes to the specific state
   returning SWITCH_STATUS_SUCCESS tells the core to execute the standard state method next
   so if you fully implement the state you can return SWITCH_STATUS_FALSE to skip it.
*/
switch_status_t agora_on_init(switch_core_session_t *session)
{
	// switch_channel_t *channel;
	// agora_private_t *tech_pvt = NULL;
	// agora_session_t *rsession = NULL;

	// tech_pvt = switch_core_session_get_private(session);
	// assert(tech_pvt != NULL);

	// rsession = tech_pvt->agora_session;

	// channel = switch_core_session_get_channel(session);
	// assert(channel != NULL);

	// switch_channel_set_flag(channel, CF_CNG_PLC);

	// agora_notify_call_state(session);

	// switch_set_flag_locked(tech_pvt, TFLAG_IO);

	// switch_mutex_lock(rsession->profile->mutex);
	// rsession->profile->calls++;
	// switch_mutex_unlock(rsession->profile->mutex);

	// switch_mutex_lock(rsession->count_mutex);
	// rsession->active_sessions++;
	// switch_mutex_unlock(rsession->count_mutex);

	return SWITCH_STATUS_SUCCESS;
}

switch_status_t agora_on_routing(switch_core_session_t *session)
{
	switch_channel_t *channel = NULL;
	agora_private_t *tech_pvt = NULL;

	channel = switch_core_session_get_channel(session);
	assert(channel != NULL);

	tech_pvt = switch_core_session_get_private(session);
	assert(tech_pvt != NULL);

	agora_notify_call_state(session);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "%s CHANNEL ROUTING\n",
					  switch_channel_get_name(channel));

	return SWITCH_STATUS_SUCCESS;
}

switch_status_t agora_on_execute(switch_core_session_t *session)
{

	switch_channel_t *channel = NULL;
	agora_private_t *tech_pvt = NULL;

	channel = switch_core_session_get_channel(session);
	assert(channel != NULL);

	tech_pvt = switch_core_session_get_private(session);
	assert(tech_pvt != NULL);

	agora_notify_call_state(session);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "%s CHANNEL EXECUTE\n",
					  switch_channel_get_name(channel));

	return SWITCH_STATUS_SUCCESS;
}

switch_status_t agora_on_destroy(switch_core_session_t *session)
{
	switch_channel_t *channel = NULL;
	agora_private_t *tech_pvt = NULL;

	channel = switch_core_session_get_channel(session);
	assert(channel != NULL);

	tech_pvt = switch_core_session_get_private(session);

	if (tech_pvt) {
		if (switch_core_codec_ready(&tech_pvt->read_codec)) {
			switch_core_codec_destroy(&tech_pvt->read_codec);
		}

		if (switch_core_codec_ready(&tech_pvt->write_codec)) {
			switch_core_codec_destroy(&tech_pvt->write_codec);
		}

		// switch_core_timer_destroy(&tech_pvt->timer);
		agora_destory_session(tech_pvt->agora_session);
	}

	return SWITCH_STATUS_SUCCESS;
}

switch_status_t agora_on_hangup(switch_core_session_t *session)
{
	// switch_channel_t *channel = NULL;
	// agora_private_t *tech_pvt = NULL;
	// agora_session_t *rsession = NULL;

	// channel = switch_core_session_get_channel(session);
	// assert(channel != NULL);

	// tech_pvt = switch_core_session_get_private(session);
	// assert(tech_pvt != NULL);
	// rsession = tech_pvt->agora_session;
	// 	switch_clear_flag_locked(tech_pvt, TFLAG_IO);

	// 	if (rsession == NULL) {
	// 		/*
	// 		 * If the FS channel is calling hangup, but the rsession is already destroyed, then there is nothing that
	// can
	// be
	// 		 * done,
	// 		 * wihtout segfaulting. If there are any actions that need to be done even if the rsession is already
	// destroyed,
	// 		 * then move them
	// 		 * above here, or after the done target.
	// 		 */
	// 		goto done;
	// 	}

	// 	switch_thread_rwlock_wrlock(rsession->rwlock);
	// 	// switch_thread_cond_signal(tech_pvt->cond);
	// 	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "%s CHANNEL HANGUP\n",
	// 					  switch_channel_get_name(channel));

	// 	if (rsession->tech_pvt == tech_pvt) {
	// 		agora_private_t *other_tech_pvt = NULL;
	// 		const char *s;
	// 		if ((s = switch_channel_get_variable(channel, agora_ATTACH_ON_HANGUP_VARIABLE)) && !zstr(s)) {
	// 			other_tech_pvt = agora_locate_private(rsession, s);
	// 		}
	// 		agora_attach_private(rsession, other_tech_pvt);
	// 	}

	// 	agora_notify_call_state(session);
	// 	agora_send_onhangup(session);

	// 	/*
	// 	 * If the session_rwlock is already locked, then there is a larger possibility that the rsession
	// 	 * is looping through because the rsession is trying to hang them up. If that is the case, then there
	// 	 * is really no reason to foce this hash_delete. Just timeout, and let the rsession handle the final cleanup
	// 	 * since it now checks for the existence of the FS session safely.
	// 	 */
	// 	if (switch_thread_rwlock_trywrlock_timeout(rsession->session_rwlock, 10) == SWITCH_STATUS_SUCCESS) {
	// 		/*
	// 		 * Why the heck would rsession->session_hash ever be null here?!?
	// 		 * We only got here because the tech_pvt->agora_session wasn't null....!!!!
	// 		 */
	// 		if (rsession->session_hash) {
	// 			switch_core_hash_delete(rsession->session_hash, switch_core_session_get_uuid(session));
	// 		}
	// 		switch_thread_rwlock_unlock(rsession->session_rwlock);
	// 	}

	// #if 0
	// 	// this block could replace the above if block, not sure if it's safe
	// 	switch_core_hash_delete_wrlock(rsession->session_hash, switch_core_session_get_uuid(session),
	// rsession->session_rwlock);

	// 	switch_mutex_lock(rsession->count_mutex);
	// 	rsession->active_sessions--;
	// 	switch_mutex_unlock(rsession->count_mutex);
	// #endif

	// #ifndef agora_DONT_HOLD
	// 	if (switch_channel_test_flag(channel, CF_HOLD)) {
	// 		switch_channel_mark_hold(channel, SWITCH_FALSE);
	// 		switch_ivr_unhold(session);
	// 	}
	// #endif

	// 	switch_thread_rwlock_unlock(rsession->rwlock);

	// done:
	return SWITCH_STATUS_SUCCESS;
}

switch_status_t agora_kill_channel(switch_core_session_t *session, int sig)
{
	switch_channel_t *channel = NULL;
	agora_private_t *tech_pvt = NULL;

	channel = switch_core_session_get_channel(session);
	assert(channel != NULL);

	tech_pvt = switch_core_session_get_private(session);
	assert(tech_pvt != NULL);

	switch (sig) {
	case SWITCH_SIG_KILL:
		switch_clear_flag_locked(tech_pvt, TFLAG_IO);

		break;
	case SWITCH_SIG_BREAK:
		switch_set_flag_locked(tech_pvt, TFLAG_BREAK);
		break;
	default:
		break;
	}

	return SWITCH_STATUS_SUCCESS;
}

switch_status_t agora_on_exchange_media(switch_core_session_t *session)
{
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "CHANNEL LOOPBACK\n");
	agora_notify_call_state(session);
	return SWITCH_STATUS_SUCCESS;
}

switch_status_t agora_on_soft_execute(switch_core_session_t *session)
{
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "CHANNEL TRANSMIT\n");
	agora_notify_call_state(session);
	return SWITCH_STATUS_SUCCESS;
}

switch_status_t agora_send_dtmf(switch_core_session_t *session, const switch_dtmf_t *dtmf)
{
	agora_private_t *tech_pvt = switch_core_session_get_private(session);
	switch_assert(tech_pvt != NULL);

	return SWITCH_STATUS_SUCCESS;
}

// c从SDK 读取数据
switch_status_t agora_read_frame(switch_core_session_t *session, switch_frame_t **frame, switch_io_flag_t flags,
								 int stream_id)
{
	switch_channel_t *channel = NULL;
	agora_private_t *tech_pvt = NULL;
	agora_session_t *rsession = NULL;
	// switch_time_t started = switch_time_now();
	// unsigned int elapsed;
	switch_byte_t *data;
	uint16_t len;

	channel = switch_core_session_get_channel(session);
	assert(channel != NULL);

	tech_pvt = switch_core_session_get_private(session);
	assert(tech_pvt != NULL);
	rsession = tech_pvt->agora_session;

	if (rsession->state >= RS_DESTROY) {
		return SWITCH_STATUS_FALSE;
	}

	if (switch_test_flag(tech_pvt, TFLAG_DETACHED)) {
		// switch_core_timer_next(&tech_pvt->timer);
		goto cng;
	}

	tech_pvt->read_frame.flags = SFF_NONE;
	tech_pvt->read_frame.codec = &tech_pvt->read_codec;

	// switch_core_timer_next(&tech_pvt->timer);

	if (switch_buffer_inuse(rsession->readbuf) < 172) {
		/* Not enough data in buffer, return CNG frame */
		goto cng;
	} else {
		len = agora_read_data_from_session(rsession, &tech_pvt->read_frame);
		if (len <= 0) {
			goto cng;
		}
	}

	*frame = &tech_pvt->read_frame;

	return SWITCH_STATUS_SUCCESS;

cng:

	data = (switch_byte_t *)tech_pvt->read_frame.data;
	data[0] = 65;
	data[1] = 0;
	tech_pvt->read_frame.datalen = 2;
	tech_pvt->read_frame.flags = SFF_CNG;
	tech_pvt->read_frame.codec = &tech_pvt->read_codec;

	// switch_core_timer_sync(&tech_pvt->timer);
	*frame = &tech_pvt->read_frame;

	return SWITCH_STATUS_SUCCESS;
}

switch_status_t agora_write_frame(switch_core_session_t *session, switch_frame_t *frame, switch_io_flag_t flags,
								  int stream_id)
{
	switch_channel_t *channel = NULL;
	agora_private_t *tech_pvt = NULL;
	agora_session_t *rsession = NULL;
	// switch_frame_t *pframe;
	// switch_time_t ts;
	switch_status_t status = SWITCH_STATUS_SUCCESS;

	channel = switch_core_session_get_channel(session);
	assert(channel != NULL);

	tech_pvt = switch_core_session_get_private(session);
	assert(tech_pvt != NULL);
	rsession = tech_pvt->agora_session;

	if (rsession == NULL) {
		return SWITCH_STATUS_FALSE;
	}
	if (!switch_test_flag(tech_pvt, TFLAG_IO)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "TFLAG_IO not set\n");
		switch_goto_status(SWITCH_STATUS_FALSE, end);
	}

	if (switch_test_flag(tech_pvt, TFLAG_DETACHED)) {
		switch_goto_status(SWITCH_STATUS_SUCCESS, end);
	}

	if (rsession->state >= RS_DESTROY) {
		switch_goto_status(SWITCH_STATUS_FALSE, end);
	}

	if (frame->datalen + 1 > frame->buflen) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Datalen too big\n");
		switch_goto_status(SWITCH_STATUS_FALSE, end);
	}

	if (frame->flags & SFF_CNG) {
		switch_goto_status(SWITCH_STATUS_SUCCESS, end);
	}

	/* Build message */
	agora_write_data_to_session(rsession, frame);
end:
	return status;
}

switch_status_t agora_receive_message(switch_core_session_t *session, switch_core_session_message_t *msg)
{
	switch_channel_t *channel;
	agora_private_t *tech_pvt;

	channel = switch_core_session_get_channel(session);
	assert(channel != NULL);

	tech_pvt = (agora_private_t *)switch_core_session_get_private(session);
	assert(tech_pvt != NULL);

	switch (msg->message_id) {
	case SWITCH_MESSAGE_INDICATE_ANSWER:
		switch_channel_mark_answered(channel);
		agora_notify_call_state(session);
		break;
	case SWITCH_MESSAGE_INDICATE_RINGING:
		switch_channel_mark_ring_ready(channel);
		agora_notify_call_state(session);
		break;
	case SWITCH_MESSAGE_INDICATE_PROGRESS:
		switch_channel_mark_pre_answered(channel);
		agora_notify_call_state(session);
		break;
	case SWITCH_MESSAGE_INDICATE_HOLD:
	case SWITCH_MESSAGE_INDICATE_UNHOLD:
		agora_notify_call_state(session);
		break;
	case SWITCH_MESSAGE_INDICATE_BRIDGE:
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Flushing read buffer\n");

		break;
	case SWITCH_MESSAGE_INDICATE_DISPLAY: {
		const char *name = msg->string_array_arg[0], *number = msg->string_array_arg[1];
		char *arg = NULL;
		char *argv[2] = {0};
		// int argc;

		if (zstr(name) && !zstr(msg->string_arg)) {
			arg = strdup(msg->string_arg);
			switch_assert(arg);

			switch_separate_string(arg, '|', argv, (sizeof(argv) / sizeof(argv[0])));
			name = argv[0];
			number = argv[1];
		}

		if (!zstr(name)) {
			if (zstr(number)) {
				switch_caller_profile_t *caller_profile = switch_channel_get_caller_profile(channel);
				number = caller_profile->destination_number;
			}

			if (zstr(tech_pvt->display_callee_id_name) || strcmp(tech_pvt->display_callee_id_name, name)) {
				tech_pvt->display_callee_id_name = switch_core_session_strdup(session, name);
			}

			if (zstr(tech_pvt->display_callee_id_number) || strcmp(tech_pvt->display_callee_id_number, number)) {
				tech_pvt->display_callee_id_number = switch_core_session_strdup(session, number);
			}

			// agora_send_display_update(session);
		}

		switch_safe_free(arg);
	} break;
	case SWITCH_MESSAGE_INDICATE_DEBUG_MEDIA: {
		// agora_session_t *rsession = tech_pvt->agora_session;
		// const char *direction = msg->string_array_arg[0];
		// int video = 0;

		// if (direction && *direction == 'v') {
		// 	direction++;
		// 	video = 1;
		// }
		/*
		if (!zstr(direction) && !zstr(msg->string_array_arg[1])) {
			int both = !strcasecmp(direction, "both");
			uint8_t flag = 0;

			if (both || !strcasecmp(direction, "read")) {
				flag |= (video ? agora_MD_VIDEO_READ : agora_MD_AUDIO_READ);
			}

			if (both || !strcasecmp(direction, "write")) {
				flag |= (video ? agora_MD_VIDEO_WRITE : agora_MD_AUDIO_WRITE);
			}

			if (flag) {
				if (switch_true(msg->string_array_arg[1])) {
					rsession->media_debug |= flag;
				} else {
					rsession->media_debug &= ~flag;
				}
			} else {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Invalid Options\n");
			}

		}*/
	} break;
	default:
		break;
	}

	return SWITCH_STATUS_SUCCESS;
}

/* Make sure when you have 2 sessions in the same scope that you pass the appropriate one to the routines
   that allocate memory or you will have 1 channel with memory allocated from another channel's pool!
*/
switch_call_cause_t agora_outgoing_channel(switch_core_session_t *session, switch_event_t *var_event,
										   switch_caller_profile_t *outbound_profile,
										   switch_core_session_t **newsession, switch_memory_pool_t **inpool,
										   switch_originate_flag_t flags, switch_call_cause_t *cancel_cause)
{
	agora_private_t *tech_pvt;
	switch_caller_profile_t *caller_profile;
	switch_channel_t *channel;
	switch_call_cause_t cause = SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER;
	switch_memory_pool_t *pool;
	char *destination = NULL, *auth, *user, *domain;
	*newsession = NULL;

	if (zstr(outbound_profile->destination_number)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "No destination\n");
		goto fail;
	}

	destination = strdup(outbound_profile->destination_number);

	if ((auth = strchr(destination, '/'))) {
		*auth++ = '\0';
	}

	if (!(*newsession = switch_core_session_request_uuid(agora_globals.agora_endpoint_interface, flags,
														 SWITCH_CALL_DIRECTION_OUTBOUND, inpool,
														 switch_event_get_header(var_event, "origination_uuid")))) {
		goto fail;
	}

	pool = switch_core_session_get_pool(*newsession);

	channel = switch_core_session_get_channel(*newsession);
	// switch_channel_set_name(channel, switch_core_session_sprintf(*newsession, "agora/%s/%s", rsession->profile->name,
	// 															 outbound_profile->destination_number));

	caller_profile = switch_caller_profile_dup(pool, outbound_profile);
	switch_channel_set_caller_profile(channel, caller_profile);

	tech_pvt = switch_core_alloc(pool, sizeof(agora_private_t));
	// tech_pvt->agora_session = rsession;
	// tech_pvt->write_channel = agora_DEFAULT_STREAM_AUDIO;
	tech_pvt->session = *newsession;
	tech_pvt->caller_profile = caller_profile;
	switch_core_session_add_stream(*newsession, NULL);
	tech_pvt->profile = agora_profile_locate(destination);

	if (agora_tech_init(tech_pvt, *newsession) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(*newsession), SWITCH_LOG_ERROR, "tech_init failed\n");
		cause = SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER;
		goto fail;
	}

	if (!zstr(auth)) {
		tech_pvt->auth = switch_core_session_strdup(*newsession, auth);
		switch_split_user_domain(auth, &user, &domain);
		tech_pvt->auth_user = switch_core_session_strdup(*newsession, user);
		tech_pvt->auth_domain = switch_core_session_strdup(*newsession, domain);
	}

	

	switch_channel_ring_ready(channel);
	// agora_send_incoming_call(*newsession, var_event); //todo 通知别人有电话进来
	switch_channel_mark_pre_answered(channel);
	switch_channel_mark_answered(channel);
	switch_channel_set_state(channel, CS_INIT);
	switch_set_flag_locked(tech_pvt, TFLAG_IO);

	agora_set_channel_variables(*newsession);

	return SWITCH_CAUSE_SUCCESS;

fail:
	if (*newsession) {
		if (!switch_core_session_running(*newsession) && !switch_core_session_started(*newsession)) {
			switch_core_session_destroy(newsession);
		}
	}
	switch_safe_free(destination);
	return cause;
}

switch_status_t agora_receive_event(switch_core_session_t *session, switch_event_t *event)
{
	// agora_private_t *tech_pvt = switch_core_session_get_private(session);
	// agora_session_t *rsession = tech_pvt->agora_session;
	// switch_assert(tech_pvt != NULL);

	// /* Deliver the event as a custom message to the target rtmp session */
	// switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Session", switch_core_session_get_uuid(session));

	// agora_send_event(rsession, event);

	return SWITCH_STATUS_SUCCESS;
}

agora_profile_t *agora_profile_locate(const char *name)
{
	agora_profile_t *profile =
		switch_core_hash_find_rdlock(agora_globals.profile_hash, name, agora_globals.profile_rwlock);

	if (profile) {
		if (switch_thread_rwlock_tryrdlock(profile->rwlock) != SWITCH_STATUS_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Profile %s is locked\n", name);
			profile = NULL;
		}
	}

	return profile;
}

void agora_profile_release(agora_profile_t *profile) { switch_thread_rwlock_unlock(profile->rwlock); }

/*agora_session_t *agora_session_locate(const char *uuid)
{
	agora_session_t *rsession =
		switch_core_hash_find_rdlock(agora_globals.session_hash, uuid, agora_globals.session_rwlock);

	if (!rsession || rsession->state >= RS_DESTROY) {
		return NULL;
	}

	switch_thread_rwlock_rdlock(rsession->rwlock);

	return rsession;
}*/

void agora_session_rwunlock(agora_session_t *rsession) { switch_thread_rwlock_unlock(rsession->rwlock); }

// void agora_event_fill(agora_session_t *rsession, switch_event_t *event)
// {
// 	switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "AGORA_APPID", rsession->profile->appid);
// 	// switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "RTMP-Flash-Version", rsession->flashVer);
// 	// switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "RTMP-SWF-URL", rsession->swfUrl);
// 	// switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "RTMP-TC-URL", rsession->tcUrl);
// 	// switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "RTMP-Page-URL", rsession->pageUrl);
// 	// switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "RTMP-Profile", rsession->profile->name);
// 	// switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Network-Port", "%d", rsession->remote_port);
// 	// switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Network-IP", rsession->remote_address);
// 	switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "AGORA-Profile", rsession->profile->name);
// }

static void agora_garbage_colletor(void)
{
	// switch_hash_index_t *hi = NULL;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "AGORA Garbage Collection\n");

	// 	switch_thread_rwlock_wrlock(agora_globals.session_rwlock);

	// top:

	// 	for (hi = switch_core_hash_first_iter(agora_globals.agora_pvt, hi); hi; hi = switch_core_hash_next(&hi)) {
	// 		void *val;
	// 		const void *key;
	// 		switch_ssize_t keylen;
	// 		agora_session_t *rsession;

	// 		switch_core_hash_this(hi, &key, &keylen, &val);
	// 		rsession = (agora_session_t *)val;

	// 		if (rsession->state == RS_DESTROY) {
	// 			if (agora_real_session_destroy(&rsession) == SWITCH_STATUS_SUCCESS) {
	// 				goto top;
	// 			}
	// 		}
	// 	}
	// 	switch_safe_free(hi);

	// 	switch_thread_rwlock_unlock(agora_globals.session_rwlock);
}

switch_status_t agora_session_destroy(agora_session_t **rsession)
{
	switch_status_t status = SWITCH_STATUS_FALSE;

	switch_mutex_lock(agora_globals.mutex);
	if (rsession && *rsession) {
		(*rsession)->state = RS_DESTROY;
		*rsession = NULL;
		status = SWITCH_STATUS_SUCCESS;
	}
	switch_mutex_unlock(agora_globals.mutex);

	return status;
}

switch_status_t agora_real_session_destroy(agora_session_t **rsession)
{
	// switch_hash_index_t *hi;
	// switch_event_t *event;
	// int sess = 0;

	// 	switch_thread_rwlock_rdlock((*rsession)->session_rwlock);
	// 	for (hi = switch_core_hash_first((*rsession)->session_hash); hi; hi = switch_core_hash_next(&hi)) {
	// 		void *val;
	// 		const void *key;
	// 		switch_ssize_t keylen;
	// 		switch_channel_t *channel;
	// 		switch_core_session_t *session;

	// 		switch_core_hash_this(hi, &key, &keylen, &val);

	// 		/* If there are any sessions attached, abort the destroy operation */
	// 		if ((session = switch_core_session_locate((char *)key)) != NULL) {
	// 			channel = switch_core_session_get_channel(session);
	// 			switch_channel_hangup(channel, SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER);
	// 			switch_core_session_rwunlock(session);
	// 			sess++;
	// 		}
	// 	}
	// 	switch_thread_rwlock_unlock((*rsession)->session_rwlock);

	// 	if (sess) {
	// 		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "RTMP session [%s] %p still busy.\n",
	// 						  (*rsession)->uuid, (void *)*rsession);
	// 		return SWITCH_STATUS_FALSE;
	// 	}

	// 	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "RTMP session [%s] %p will be destroyed.\n",
	// 					  (*rsession)->uuid, (void *)*rsession);

	// 	if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, agora_EVENT_DISCONNECT) == SWITCH_STATUS_SUCCESS)
	// {
	// 		agora_event_fill(*rsession, event);
	// 		switch_event_fire(&event);
	// 	}

	// 	switch_core_hash_delete(agora_globals.session_hash, (*rsession)->uuid);
	// 	switch_core_hash_delete_wrlock((*rsession)->profile->session_hash, (*rsession)->uuid,
	// 								   (*rsession)->profile->session_rwlock);
	// 	agora_clear_registration(*rsession, NULL, NULL);
	// 	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "RTMP session ended [%s]\n", (*rsession)->uuid);

	// 	switch_mutex_lock((*rsession)->profile->mutex);
	// 	if ((*rsession)->profile->calls < 1) {
	// 		(*rsession)->profile->calls = 0;
	// 	} else {
	// 		(*rsession)->profile->calls--;
	// 	}
	// 	switch_mutex_unlock((*rsession)->profile->mutex);

	// 	switch_thread_rwlock_wrlock((*rsession)->rwlock);
	// 	switch_thread_rwlock_unlock((*rsession)->rwlock);

	// #ifdef agora_DEBUG_IO
	// 	fclose((*rsession)->io_debug_in);
	// 	fclose((*rsession)->io_debug_out);
	// #endif

	// 	switch_mutex_lock((*rsession)->profile->mutex);
	// 	(*rsession)->profile->clients--;
	// 	switch_mutex_unlock((*rsession)->profile->mutex);

	// 	switch_core_hash_destroy(&(*rsession)->session_hash);

	// 	switch_core_destroy_memory_pool(&(*rsession)->pool);

	*rsession = NULL;

	return SWITCH_STATUS_SUCCESS;
}

// switch_call_cause_t agora_session_create_call(agora_session_t *rsession, switch_core_session_t **newsession,
// 											  int read_channel, int write_channel, const char *number,
// 											  const char *auth_user, const char *auth_domain, switch_event_t *event)
// {
// 	switch_memory_pool_t *pool;
// 	agora_private_t *tech_pvt;
// 	switch_caller_profile_t *caller_profile;
// 	switch_channel_t *channel;
// 	const char *dialplan, *context;

// 	if (!(*newsession = switch_core_session_request(agora_globals.agora_endpoint_interface,
// 													SWITCH_CALL_DIRECTION_INBOUND, SOF_NONE, NULL))) {
// 		return SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER;
// 	}
// 	switch_log_printf(SWITCH_CHANNEL_UUID_LOG(rsession->uuid), SWITCH_LOG_INFO, "New FreeSWITCH session created: %s\n",
// 					  switch_core_session_get_uuid(*newsession));

// 	pool = switch_core_session_get_pool(*newsession);
// 	channel = switch_core_session_get_channel(*newsession);
// 	switch_channel_set_name(channel,
// 							switch_core_session_sprintf(*newsession, "rtmp/%s/%s", rsession->profile->name, number));

// 	if (!zstr(auth_user) && !zstr(auth_domain)) {
// 		const char *s = switch_core_session_sprintf(*newsession, "%s@%s", auth_user, auth_domain);
// 		switch_ivr_set_user(*newsession, s);
// 		switch_channel_set_variable(channel, "agora_authorized", "true");
// 	}

// 	if (!(context = switch_channel_get_variable(channel, "user_context"))) {
// 		if (!(context = rsession->profile->context)) {
// 			context = "public";
// 		}
// 	}

// 	if (!(dialplan = switch_channel_get_variable(channel, "inbound_dialplan"))) {
// 		if (!(dialplan = rsession->profile->dialplan)) {
// 			dialplan = "XML";
// 		}
// 	}

// 	caller_profile = switch_caller_profile_new(pool, switch_str_nil(auth_user), dialplan, SWITCH_DEFAULT_CLID_NAME,
// 											   !zstr(auth_user) ? auth_user : SWITCH_DEFAULT_CLID_NUMBER,
// 											   rsession->remote_address /* net addr */, NULL /* ani   */,
// 											   NULL /* anii  */, NULL /* rdnis */, "mod_agora", context, number);

// 	switch_channel_set_caller_profile(channel, caller_profile);

// 	tech_pvt = switch_core_alloc(pool, sizeof(agora_private_t));
// 	tech_pvt->agora_session = rsession;
// 	tech_pvt->write_channel = agora_DEFAULT_STREAM_AUDIO;
// 	tech_pvt->session = *newsession;
// 	tech_pvt->caller_profile = caller_profile;
// 	switch_core_session_add_stream(*newsession, NULL);

// 	if (event) {
// 		const char *want_video = switch_event_get_header(event, "wantVideo");
// 		const char *bandwidth = switch_event_get_header(event, "incomingBandwidth");

// 		if (want_video && switch_true(want_video)) {
// 			tech_pvt->has_video = 1;
// 			switch_channel_set_variable(channel, "video_possible", "true");
// 		}

// 		if (!zstr(bandwidth)) {
// 			tech_pvt->video_max_bandwidth_out = switch_core_strdup(pool, bandwidth);
// 		}
// 	}

// 	if (agora_tech_init(tech_pvt, rsession, *newsession) != SWITCH_STATUS_SUCCESS) {
// 		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "tech_init failed\n");
// 		goto fail;
// 	}

// 	if (!zstr(auth_user) && !zstr(auth_domain)) {
// 		tech_pvt->auth_user = switch_core_session_strdup(*newsession, auth_user);
// 		tech_pvt->auth_domain = switch_core_session_strdup(*newsession, auth_domain);
// 		tech_pvt->auth = switch_core_session_sprintf(*newsession, "%s@%s", auth_user, auth_domain);
// 	}

// 	switch_channel_set_state(channel, CS_INIT);
// 	switch_set_flag_locked(tech_pvt, TFLAG_IO);
// 	switch_set_flag_locked(tech_pvt, TFLAG_DETACHED);
// 	agora_set_channel_variables(*newsession);

// 	if (0 && event) {
// 		switch_event_header_t *hp;

// 		for (hp = event->headers; hp; hp = hp->next) {
// 			switch_channel_set_variable_name_printf(channel, hp->value, agora_USER_VARIABLE_PREFIX "_%s", hp->name);
// 			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s\n", hp->name);
// 		}
// 	}

// 	if (switch_core_session_thread_launch(tech_pvt->session) == SWITCH_STATUS_FALSE) {
// 		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't spawn thread\n");
// 		goto fail;
// 	}

// 	switch_core_hash_insert_wrlock(rsession->session_hash, switch_core_session_get_uuid(*newsession), tech_pvt,
// 								   rsession->session_rwlock);

// 	return SWITCH_CAUSE_SUCCESS;

// fail:

// 	if (!switch_core_session_running(*newsession) && !switch_core_session_started(*newsession)) {
// 		switch_core_session_destroy(newsession);
// 	}

// 	return SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER;
// }

switch_status_t agora_profile_start(const char *profilename)
{
	switch_memory_pool_t *pool;
	agora_profile_t *profile;

	switch_assert(profilename);

	switch_core_new_memory_pool(&pool);
	profile = switch_core_alloc(pool, sizeof(*profile));
	profile->pool = pool;
	profile->name = switch_core_strdup(pool, profilename);

	if (config_profile(profile, SWITCH_FALSE) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Config failed\n");
		goto fail;
	}

	switch_thread_rwlock_create(&profile->rwlock, pool);
	switch_mutex_init(&profile->mutex, SWITCH_MUTEX_NESTED, pool);
	switch_core_hash_init(&profile->agora_pvt_hash);
	switch_thread_rwlock_create(&profile->agora_pvt_rwlock, pool);

	agora_init_module(profile->appid);

	switch_core_hash_insert_wrlock(agora_globals.profile_hash, profile->name, profile, agora_globals.profile_rwlock);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Started profile %s\n", profile->name);

	return SWITCH_STATUS_SUCCESS;
fail:
	switch_core_destroy_memory_pool(&pool);
	return SWITCH_STATUS_FALSE;
}

switch_status_t agora_profile_destroy(agora_profile_t **profile)
{
	// int sanity = 0;
	switch_hash_index_t *hi = NULL;
	switch_xml_config_item_t *instructions = get_instructions(*profile);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Stopping profile: %s\n", (*profile)->name);

	switch_core_hash_delete_wrlock(agora_globals.profile_hash, (*profile)->name, agora_globals.profile_rwlock);

	switch_thread_rwlock_wrlock((*profile)->rwlock);

	/* Kill all sessions */
	while ((hi = switch_core_hash_first_iter((*profile)->agora_pvt_hash, hi))) {
		void *val;
		agora_session_t *rsession;
		const void *key;
		switch_ssize_t keylen;
		switch_core_hash_this(hi, &key, &keylen, &val);

		rsession = val;

		if (rsession->state != RS_DESTROY) agora_session_destroy(&rsession);
	}

	switch_thread_rwlock_unlock((*profile)->rwlock);

	switch_xml_config_cleanup(instructions);

	switch_core_destroy_memory_pool(&(*profile)->pool);

	free(instructions);

	return SWITCH_STATUS_SUCCESS;
}
// agora_private_t *agora_locate_private(agora_session_t *rsession, const char *uuid)
// {
// 	return switch_core_hash_find_rdlock(rsession->profile->agora_pvt_hash, uuid, rsession->profile->agora_pvt_rwlock);
// }

static switch_xml_config_item_t *get_instructions(agora_profile_t *profile)
{
	switch_xml_config_item_t *dup;
	// static switch_xml_config_int_options_t opt_chunksize = {SWITCH_TRUE,	  /* enforce min */
	// 128, SWITCH_TRUE, /* Enforce Max */
	// 65536};
	// static switch_xml_config_int_options_t opt_bufferlen = {SWITCH_FALSE, 0, SWITCH_TRUE, INT32_MAX};
	switch_xml_config_item_t instructions[] = {
		/* parameter name        type                 reloadable   pointer                         default value
		   options structure */
		SWITCH_CONFIG_ITEM("context", SWITCH_CONFIG_STRING, CONFIG_RELOADABLE, &profile->context, "public",
						   &switch_config_string_strdup, "", "The dialplan context to use for inbound calls"),
		SWITCH_CONFIG_ITEM("dialplan", SWITCH_CONFIG_STRING, CONFIG_RELOADABLE, &profile->dialplan, "XML",
						   &switch_config_string_strdup, "", "The dialplan to use for inbound calls"),
		SWITCH_CONFIG_ITEM("appid", SWITCH_CONFIG_STRING, 0, &profile->appid, "", &switch_config_string_strdup,
						   "app-id", "the profile agora appid"),
		SWITCH_CONFIG_ITEM_END()};

	dup = malloc(sizeof(instructions));
	memcpy(dup, instructions, sizeof(instructions));
	return dup;
}

static switch_status_t config_profile(agora_profile_t *profile, switch_bool_t reload)
{
	switch_xml_t cfg, xml, x_profiles, x_profile, x_settings;
	switch_status_t status = SWITCH_STATUS_FALSE;
	switch_xml_config_item_t *instructions = (profile ? get_instructions(profile) : NULL);
	switch_event_t *event = NULL;
	int count;
	const char *file = "agora.conf";

	if (!(xml = switch_xml_open_cfg(file, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Could not open %s\n", file);
		goto done;
	}

	if (!(x_profiles = switch_xml_child(cfg, "profiles"))) {
		goto done;
	}

	for (x_profile = switch_xml_child(x_profiles, "profile"); x_profile; x_profile = x_profile->next) {
		const char *name = switch_xml_attr_soft(x_profile, "name");
		if (strcmp(name, profile->name)) {
			continue;
		}

		if (!(x_settings = switch_xml_child(x_profile, "settings"))) {
			goto done;
		}

		count = switch_event_import_xml(switch_xml_child(x_settings, "param"), "name", "value", &event);
		status = switch_xml_config_parse_event(event, count, reload, instructions);
	}

done:
	if (xml) {
		switch_xml_free(xml);
	}
	switch_safe_free(instructions);
	if (event) {
		switch_event_destroy(&event);
	}
	return status;
}

static void agora_event_handler(switch_event_t *event)
{
	// agora_session_t *rsession;
	// const char *uuid;

	// if (!event) {
	// 	return;
	// }

	/*
		uuid = switch_event_get_header(event, "RTMP-Session-ID");
		if (zstr(uuid)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "RTMP Custom event without RTMP-Session-ID\n");
			return;
		}

		if ((rsession = agora_session_locate(uuid))) {
			agora_send_event(rsession, event);
			agora_session_rwunlock(rsession);
		}
		*/
}

#define agora_CONTACT_FUNCTION_SYNTAX "profile/user@domain[/[!]nickname]"
SWITCH_STANDARD_API(agora_contact_function)
{
	int argc;
	char *argv[5];
	char *dup = NULL;
	char *szprofile = NULL, *user = NULL;
	// const char *nickname = NULL;
	agora_profile_t *profile = NULL;
	// switch_bool_t first = SWITCH_TRUE;

	if (zstr(cmd)) {
		goto usage;
	}

	dup = strdup(cmd);
	argc = switch_split(dup, '/', argv);

	if (argc < 2 || zstr(argv[0]) || zstr(argv[1])) {
		goto usage;
	}

	szprofile = argv[0];
	if (!strchr(argv[1], '@')) {
		goto usage;
	}

	user = argv[1];
	// nickname = argv[2];

	if (!(profile = agora_profile_locate(szprofile))) {
		stream->write_function(stream, "-ERR No such profile\n");
		goto done;
	}
	stream->write_function(stream, "agora/%s/%s", profile->name, user);
	goto done;

usage:
	stream->write_function(stream, "Usage: agora_contact " agora_CONTACT_FUNCTION_SYNTAX "\n");

done:
	if (profile) {
		agora_profile_release(profile);
	}
	switch_safe_free(dup);
	return SWITCH_STATUS_SUCCESS;
}

// static const char *state2name(int state)
// {
// 	switch (state) {
// 	case RS_HANDSHAKE:
// 		return "HANDSHAKE";
// 	case RS_HANDSHAKE2:
// 		return "HANDSHAKE2";
// 	case RS_ESTABLISHED:
// 		return "ESTABLISHED";
// 	default:
// 		return "DESTROY (PENDING)";
// 	}
// }

#define agora_FUNCTION_SYNTAX                                                                                          \
	"profile [profilename] [start | stop | rescan | restart]\nstatus profile [profilename]\nstatus profile "           \
	"[profilename] [reg | sessions]\nsession [session_id] [kill | login [user@domain] | logout [user@domain]]"
SWITCH_STANDARD_API(agora_function)
{
	int argc;
	char *argv[10];
	char *dup = NULL;

	if (zstr(cmd)) {
		goto usage;
	}

	dup = strdup(cmd);
	argc = switch_split(dup, ' ', argv);

	if (argc < 1 || zstr(argv[0])) {
		goto usage;
	}
	/*
		if (!strcmp(argv[0], "profile")) {
			if (zstr(argv[1]) || zstr(argv[2])) {
				goto usage;
			}
			if (!strcmp(argv[2], "start")) {
				agora_profile_t *profile = agora_profile_locate(argv[1]);
				if (profile) {
					agora_profile_release(profile);
					stream->write_function(stream, "-ERR Profile %s is already started\n", argv[2]);
				} else {
					agora_profile_start(argv[1]);
					stream->write_function(stream, "+OK\n");
				}
			} else if (!strcmp(argv[2], "stop")) {
				agora_profile_t *profile = agora_profile_locate(argv[1]);
				if (profile) {
					agora_profile_release(profile);
					agora_profile_destroy(&profile);
					stream->write_function(stream, "+OK\n");
				} else {
					stream->write_function(stream, "-ERR No such profile\n");
				}
			} else if (!strcmp(argv[2], "rescan")) {
				agora_profile_t *profile = agora_profile_locate(argv[1]);
				if (profile) {
					if (config_profile(profile, SWITCH_TRUE) == SWITCH_STATUS_SUCCESS) {
						stream->write_function(stream, "+OK\n");
					} else {
						stream->write_function(stream, "-ERR Config error\n");
					}
					agora_profile_release(profile);
				}
			} else if (!strcmp(argv[2], "restart")) {
				agora_profile_t *profile = agora_profile_locate(argv[1]);
				if (profile) {
					agora_profile_release(profile);
					agora_profile_destroy(&profile);
					agora_profile_start(argv[1]);
					stream->write_function(stream, "+OK\n");
				} else {
					agora_profile_start(argv[1]);
					stream->write_function(stream, "-OK (wasn't started, started anyways)\n");
				}
			} else {
				goto usage;
			}
		} else if (!strcmp(argv[0], "status")) {
			if (!zstr(argv[1]) && !strcmp(argv[1], "profile") && !zstr(argv[2])) {
				agora_profile_t *profile;

				if ((profile = agora_profile_locate(argv[2]))) {
					stream->write_function(stream, "Profile: %s\n", profile->name);
					stream->write_function(stream, "I/O Backend: %s\n", profile->io->name);
					stream->write_function(stream, "Bind address: %s\n", profile->io->address);
					stream->write_function(stream, "Active calls: %d\n", profile->calls);

					if (!zstr(argv[3]) && !strcmp(argv[3], "sessions")) {
						switch_hash_index_t *hi;
						stream->write_function(stream, "\nSessions:\n");
						stream->write_function(stream, "uuid,address,user,domain,flashVer,state\n");
						switch_thread_rwlock_rdlock(profile->session_rwlock);
						for (hi = switch_core_hash_first(profile->session_hash); hi; hi = switch_core_hash_next(&hi)) {
							void *val;
							const void *key;
							switch_ssize_t keylen;
							agora_session_t *item;
							switch_core_hash_this(hi, &key, &keylen, &val);

							item = (agora_session_t *)val;
							stream->write_function(stream, "%s,%s:%d,%s,%s,%s,%s\n", item->uuid, item->remote_address,
												   item->remote_port, item->account ? item->account->user : NULL,
												   item->account ? item->account->domain : NULL, item->flashVer,
												   state2name(item->state));
						}
						switch_thread_rwlock_unlock(profile->session_rwlock);
					} else if (!zstr(argv[3]) && !strcmp(argv[3], "reg")) {
						switch_hash_index_t *hi;
						stream->write_function(stream, "\nRegistrations:\n");
						stream->write_function(stream, "user,nickname,uuid\n");

						switch_thread_rwlock_rdlock(profile->reg_rwlock);
						for (hi = switch_core_hash_first(profile->reg_hash); hi; hi = switch_core_hash_next(&hi)) {
							void *val;
							const void *key;
							switch_ssize_t keylen;
							agora_reg_t *item;
							switch_core_hash_this(hi, &key, &keylen, &val);

							item = (agora_reg_t *)val;
							for (; item; item = item->next) {
								stream->write_function(stream, "%s,%s,%s\n", key, switch_str_nil(item->nickname),
													   item->uuid);
							}
						}
						switch_thread_rwlock_unlock(profile->reg_rwlock);
					} else {
						stream->write_function(stream, "Dialplan: %s\n", profile->dialplan);
						stream->write_function(stream, "Context: %s\n", profile->context);
					}

					agora_profile_release(profile);
				} else {
					stream->write_function(stream, "-ERR No such profile [%s]\n", argv[2]);
				}
			} else {
				switch_hash_index_t *hi = NULL;
				switch_thread_rwlock_rdlock(agora_globals.profile_rwlock);
				for (hi = switch_core_hash_first_iter(agora_globals.profile_hash, hi); hi;
					 hi = switch_core_hash_next(&hi)) {
					void *val;
					const void *key;
					switch_ssize_t keylen;
					agora_profile_t *item;
					switch_core_hash_this(hi, &key, &keylen, &val);

					item = (agora_profile_t *)val;
					stream->write_function(stream, "%s\t%s:%s\tprofile\n", item->name, item->io->name,
	   item->io->address);
				}
				switch_thread_rwlock_unlock(agora_globals.profile_rwlock);
			}

		} else if (!strcmp(argv[0], "session")) {
			agora_session_t *rsession;

			if (zstr(argv[1]) || zstr(argv[2])) {
				goto usage;
			}

			rsession = agora_session_locate(argv[1]);
			if (!rsession) {
				stream->write_function(stream, "-ERR No such session\n");
				goto done;
			}

			if (!strcmp(argv[2], "login")) {
				char *user, *domain;
				if (zstr(argv[3])) {
					goto usage;
				}
				switch_split_user_domain(argv[3], &user, &domain);

				if (!zstr(user) && !zstr(domain)) {
					agora_session_login(rsession, user, domain);
					stream->write_function(stream, "+OK\n");
				} else {
					stream->write_function(stream, "-ERR I need user@domain\n");
				}
			} else if (!strcmp(argv[2], "logout")) {
				char *user, *domain;
				if (zstr(argv[3])) {
					goto usage;
				}
				switch_split_user_domain(argv[3], &user, &domain);

				if (!zstr(user) && !zstr(domain)) {
					agora_session_logout(rsession, user, domain);
					stream->write_function(stream, "+OK\n");
				} else {
					stream->write_function(stream, "-ERR I need user@domain\n");
				}
			} else if (!strcmp(argv[2], "kill")) {
				agora_session_rwunlock(rsession);
				agora_session_destroy(&rsession);
				stream->write_function(stream, "+OK\n");
			} else if (!strcmp(argv[2], "call")) {
				switch_core_session_t *newsession = NULL;
				char *dest = argv[3];
				char *user = argv[4];
				char *domain = NULL;

				if (!zstr(user) && (domain = strchr(user, '@'))) {
					*domain++ = '\0';
				}

				if (!zstr(dest)) {
					if (agora_session_create_call(rsession, &newsession, 0, agora_DEFAULT_STREAM_AUDIO, dest, user,
	   domain,
												  NULL) != SWITCH_CAUSE_SUCCESS) {
						stream->write_function(stream, "-ERR Couldn't create new call\n");
					} else {
						agora_private_t *new_pvt = switch_core_session_get_private(newsession);
						agora_send_invoke_free(rsession, 3, 0, 0, amf0_str("onMakeCall"), amf0_number_new(0),
											   amf0_null_new(), amf0_str(switch_core_session_get_uuid(newsession)),
											   amf0_str(switch_str_nil(dest)), amf0_str(switch_str_nil(new_pvt->auth)),
											   NULL);

						agora_attach_private(rsession, switch_core_session_get_private(newsession));
						stream->write_function(stream, "+OK\n");
					}
				} else {
					stream->write_function(stream, "-ERR Missing destination number\n");
				}
			} else if (!strcmp(argv[2], "ping")) {
				agora_ping(rsession);
				stream->write_function(stream, "+OK\n");
			} else {
				stream->write_function(stream, "-ERR No such session action [%s]\n", argv[2]);
			}

			if (rsession) {
				agora_session_rwunlock(rsession);
			}
		} else {
			goto usage;
		}
		*/
	goto done;

usage:
	stream->write_function(stream, "-ERR Usage: " agora_FUNCTION_SYNTAX "\n");

done:
	switch_safe_free(dup);
	return SWITCH_STATUS_SUCCESS;
}
//底层lib回调，暂时没用
#define AGORA_INVOKE_FUNCTION_ARGS int argc, void *argv[]
typedef switch_status_t (*agora_invoke_function_t)(AGORA_INVOKE_FUNCTION_ARGS);
static inline void agora_register_invoke_function(const char *name, agora_invoke_function_t func)
{
	switch_core_hash_insert(agora_globals.invoke_hash, name, (void *)(intptr_t)func);
}

static switch_status_t console_complete_hashtable(switch_hash_t *hash, const char *line, const char *cursor,
												  switch_console_callback_match_t **matches)
{
	switch_hash_index_t *hi;
	void *val;
	const void *vvar;
	switch_console_callback_match_t *my_matches = NULL;
	switch_status_t status = SWITCH_STATUS_FALSE;

	for (hi = switch_core_hash_first(hash); hi; hi = switch_core_hash_next(&hi)) {
		switch_core_hash_this(hi, &vvar, NULL, &val);
		switch_console_push_match(&my_matches, (const char *)vvar);
	}

	if (my_matches) {
		*matches = my_matches;
		status = SWITCH_STATUS_SUCCESS;
	}

	return status;
}

static switch_status_t list_profiles(const char *line, const char *cursor, switch_console_callback_match_t **matches)
{
	switch_status_t status;
	switch_thread_rwlock_rdlock(agora_globals.profile_rwlock);
	status = console_complete_hashtable(agora_globals.profile_hash, line, cursor, matches);
	switch_thread_rwlock_unlock(agora_globals.profile_rwlock);
	return status;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_agora_load)
{
	switch_api_interface_t *api_interface;
	agora_globals.pool = pool;

	//注册事件
	// if (switch_event_reserve_subclass(agora_EVENT_ATTACH) != SWITCH_STATUS_SUCCESS) {
	// 	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't register subclass %s!\n", agora_EVENT_ATTACH);
	// 	return SWITCH_STATUS_TERM;
	// }
	memset(&agora_globals, 0, sizeof(agora_globals));

	switch_mutex_init(&agora_globals.mutex, SWITCH_MUTEX_NESTED, pool);
	switch_core_hash_init(&agora_globals.profile_hash);
	switch_core_hash_init(&agora_globals.invoke_hash);
	switch_thread_rwlock_create(&agora_globals.profile_rwlock, pool);

	// agora_register_invoke_function("log", agora_i_log);//注册底层回调

	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
	agora_globals.agora_endpoint_interface =
		switch_loadable_module_create_interface(*module_interface, SWITCH_ENDPOINT_INTERFACE);
	agora_globals.agora_endpoint_interface->interface_name = "agora";
	agora_globals.agora_endpoint_interface->io_routines = &agora_io_routines;
	agora_globals.agora_endpoint_interface->state_handler = &agora_state_handlers;

	SWITCH_ADD_API(api_interface, "agora", "agora management", agora_function, agora_FUNCTION_SYNTAX);
	SWITCH_ADD_API(api_interface, "agora_contact", "agora contact", agora_contact_function,
				   agora_CONTACT_FUNCTION_SYNTAX);

	switch_console_set_complete("add agora status");
	switch_console_set_complete("add agora status profile ::agora::list_profiles");
	switch_console_set_complete("add agora status profile ::agora::list_profiles sessions");
	switch_console_set_complete("add agora status profile ::agora::list_profiles reg");
	switch_console_set_complete("add agora profile ::agora::list_profiles start");
	switch_console_set_complete("add agora profile ::agora::list_profiles stop");
	switch_console_set_complete("add agora profile ::agora::list_profiles restart");
	switch_console_set_complete("add agora profile ::agora::list_profiles rescan");

	switch_console_add_complete_func("::rtmp::list_profiles", list_profiles);

	switch_event_bind("mod_agora", SWITCH_EVENT_CUSTOM, AGORA_EVENT_CUSTOM, agora_event_handler, NULL);

	{
		switch_xml_t cfg, xml, x_profiles, x_profile;
		const char *file = "rtmp.conf";

		if (!(xml = switch_xml_open_cfg(file, &cfg, NULL))) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Could not open %s\n", file);
			goto done;
		}

		if (!(x_profiles = switch_xml_child(cfg, "profiles"))) {
			goto done;
		}

		for (x_profile = switch_xml_child(x_profiles, "profile"); x_profile; x_profile = x_profile->next) {
			const char *name = switch_xml_attr_soft(x_profile, "name");
			agora_profile_start(name);
		}
	done:
		if (xml) {
			switch_xml_free(xml);
		}
	}

	agora_globals.running = 1;

	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_agora_shutdown)
{
	switch_hash_index_t *hi = NULL;

	// switch_event_free_subclass(agora_EVENT_ATTACH);

	switch_mutex_lock(agora_globals.mutex);
	while ((hi = switch_core_hash_first_iter(agora_globals.profile_hash, hi))) {
		void *val;
		const void *key;
		switch_ssize_t keylen;
		agora_profile_t *item;
		switch_core_hash_this(hi, &key, &keylen, &val);

		item = (agora_profile_t *)val;

		switch_mutex_unlock(agora_globals.mutex);
		agora_profile_destroy(&item);
		switch_mutex_lock(agora_globals.mutex);
	}
	switch_mutex_unlock(agora_globals.mutex);

	switch_event_unbind_callback(agora_event_handler);

	switch_core_hash_destroy(&agora_globals.profile_hash);
	switch_core_hash_destroy(&agora_globals.invoke_hash);

	agora_globals.running = 0;

	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_RUNTIME_FUNCTION(mod_agora_runtime)
{

	while (agora_globals.running) {
		agora_garbage_colletor();
		switch_yield(10000000);
	}

	return SWITCH_STATUS_TERM;
}

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet:
 */
