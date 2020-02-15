
#ifndef INCLUDE_AGORA_H
#define INCLUDE_AGORA_H

#include <switch.h>
#include <switch_types.h>
#include <switch_core.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "AudioFrameObserver.h"

namespace agora {
    namespace rtc {
        class IRtcEngineEventHandler;
        class IRtcEngine;
        class RtcEngineParameters;
    }
}


typedef enum { INIT = 0, JOINED = 1, RS_DESTROY = 2 } agora_session_state_t;

struct agora_session {
	switch_memory_pool_t * pool;
    unsigned char databuf[SWITCH_RECOMMENDED_BUFFER_SIZE]; /* < Buffer for read_frame */
	switch_buffer_t *readbuf;
	switch_mutex_t *readbuf_mutex;
	agora_session_state_t state;
	switch_thread_rwlock_t *rwlock;
	switch_thread_t *thread;
	uint32_t flags;

    //agora 
    IRtcEngine*     m_agoraEngine;
    RtcEngineParameters* m_parameters;
    agora::util::AutoPtr<agora::media::IMediaEngine> mediaEngine;
    AudioFrameObserver *audioFrameObserver;
};
typedef struct agora_session agora_session_t;

int  agora_init_module(const char* appid);
agora_session_t * agora_init_session(char *channelID);

int agora_read_data_from_session(agora_session_t * session, switch_frame_t *read_frame);
int agora_write_data_to_session(agora_session_t * session, switch_frame_t *read_frame);
//状态消息上报
//todo
int agora_destory_session(agora_session_t * session);
int agora_release_module();

#endif
