#pragma once

#include <switch.h>
#include <switch_types.h>
#include <switch_core.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>




const int room_id_len = 16;

typedef enum { INIT = 0, JOINED = 1, RS_DESTROY = 2 } agora_session_state_t;
class agora_context;

struct agora_session {
	switch_memory_pool_t * pool;
    unsigned char databuf[SWITCH_RECOMMENDED_BUFFER_SIZE]; /* < Buffer for read_frame */
	switch_buffer_t *readbuf;
	switch_mutex_t *readbuf_mutex;
	agora_session_state_t state;
	switch_thread_rwlock_t *rwlock;
	switch_thread_t *thread;
	uint32_t flags;

    agora_context* agora_ctx;

	int uid;
	char room_id[16];

	switch_mutex_t *av_enable_mutex;
	int video_enable ;
	int audio_enable ;

};
typedef struct agora_session agora_session_t;


int  agora_init_module(const char* appid);
agora_session_t * agora_init_session(int src_number, char *room_id, char *channelID);

int agora_read_data_from_session(agora_session_t * session, switch_frame_t *read_frame);
int agora_write_data_to_session(agora_session_t * session, switch_frame_t *read_frame);
//状态消息上报
//todo
int agora_destory_session(agora_session_t * session);
int agora_release_module();

typedef void * (*recv_callback_t)(void *data, void *arg);