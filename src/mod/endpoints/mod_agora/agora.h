#pragma once

#include <switch.h>
#include <switch_types.h>
#include <switch_core.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <string>

using std::string;

const int room_id_len = 16;
class agora_context;
typedef struct agora_session agora_session_t;
typedef struct agora_private agora_private_t;

enum PCM_TYPE{
	JOIN_SUCCESS_PCM 		= 0,
	DISABLE_AUDIO_PCM 		= 1,
	ENABLE_AUDIO_PCM 		= 2,
	HOST_DISABLE_AUDIO_PCM 	= 3,
	HOST_ENABLE_AUDIO_PCM 	= 4,
	FINISH_MEET_PCM 		= 5,
	INVALID_OPERA_PCM 		= 6,
	INVITE_CODE_ERR_PCM 	= 7,
	SILENCE_PCM			 	= 8
};

typedef enum { INIT = 0, JOINED = 1, RS_DESTROY = 2 } agora_session_state_t;

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

typedef struct pcm_play_ctx{
	PCM_TYPE play_type;
	uint32_t buffer_read_offset;
}pcm_play_ctx_t;

struct agora_session {
	switch_memory_pool_t * pool;
    unsigned char databuf[SWITCH_RECOMMENDED_BUFFER_SIZE]; /* < Buffer for read_frame */
	switch_buffer_t *readbuf;
	switch_mutex_t *readbuf_mutex;
	agora_session_state_t state;
	switch_thread_rwlock_t *rwlock;
	switch_thread_t *thread;
	uint32_t flags;
	agora_private_t *agora_private;
    agora_context* agora_ctx;

	int src_number; //源号码
	int uid;		//coco会议中的号码
	char room_id[16]; //coco会议的房间号

	switch_mutex_t *av_enable_mutex;
	int video_enable;
	int audio_enable;
	int playbacking;
	int playing_hangup;
	pcm_play_ctx_t pcm_play_info;
	struct timeval last_play_read_time; //上层回调太频繁，用来控制读取间隔

	//缓存
	char dtmf_digit;
	string dtmf_meet_id;

};


int  agora_init_module(const char* appid);
agora_session_t *agora_init_session(int src_number, string &invite_code);

int agora_read_data_from_session(agora_session_t * session, switch_frame_t *read_frame);
int agora_write_data_to_session(agora_session_t * session, switch_frame_t *read_frame);
//状态消息上报

int agora_destory_session(agora_session_t * session);
int agora_release_module();
int agora_handle_dtmf(agora_session_t *session, char digit);
int write_pcm_back(agora_session_t *session, PCM_TYPE pcm_type);
void agora_set_session_play_pcm(agora_session_t* session, PCM_TYPE type);
switch_size_t agora_read_pcm(pcm_play_ctx_t *play_ctx, void *data, switch_size_t datalen);
void agora_channel_hangup(agora_private_t *session);
void agora_join_meet(agora_session_t *session, string &invite_code);

typedef void * (*recv_callback_t)(void *data, void *arg);