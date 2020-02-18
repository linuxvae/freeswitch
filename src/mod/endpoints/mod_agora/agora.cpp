#include "agora.h"
#include "IAgoraRtcEngine.h"
#include "AudioFrameObserver.h"
#include "IAgoraMediaEngine.h"
#include "AGEngineEventHandler.h"
#include <stdio.h>

#if !defined(min)
#define min(a, b) ((a) <= (b) ? (a) : (b))
#endif
#if !defined(max)
#define max(a, b) ((a) >= (b) ? (a) : (b))
#endif

#define F_PATH "/root/test.pcm"
#define OUT_PATH "/root/out.pcm"
#define INPUT_PATH "/root/inputAudio.pcm"
static FILE *g_fp = NULL;
static FILE *g_out_fp = NULL;
static FILE *g_input_fp = NULL;

#define PCM_16000_16_1_SIZE 640
AGEngineEventHandler eventHandler;

typedef void (*write_data_callback_t )(void *dst, void *src, int len);


namespace agora {
    namespace rtc {
        class IRtcEngineEventHandler;
        class IRtcEngine;
        class RtcEngineParameters;
    }
}

using namespace agora::rtc;

class agora_context{
public:
	agora_context(){
		//init agora
    	m_agoraEngine = createAgoraRtcEngine();
		mediaEngine = new agora::util::AutoPtr<agora::media::IMediaEngine>();
		this->nSampleRate = 16000;
		this->nChannels = 1;
	}
	
	~agora_context(){

		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "agora deconstruct\n");

		//stop to push frame
		if(m_parameters){
			m_parameters->setExternalAudioSource(false, this->nSampleRate, this->nChannels);
			delete m_parameters;
            m_parameters = NULL;
		}
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "2222222\n");

		//stop observer incoming rtp
		if(mediaEngine){
			(*mediaEngine)->registerAudioFrameObserver(NULL);
			delete mediaEngine;
			mediaEngine = NULL;	
		}
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "3333333\n");


		if(m_agoraEngine != NULL) {
			m_agoraEngine->leaveChannel();
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "leave channel\n");
			m_agoraEngine->release(true);
			m_agoraEngine = NULL;
        }
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "444444444\n");


		if(audioFrameObserver){
			delete audioFrameObserver;
			audioFrameObserver = NULL;
		}
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "66666666666\n");

		//TODO free mediaEngine
	}

	int init(char *appId){
    	//initlize 
    	RtcEngineContext ctx;

		//here can set status change callback
   	 	ctx.eventHandler = &eventHandler; 
   		ctx.appId = appId;
   		int ret = m_agoraEngine->initialize(ctx);
		if(ret){
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "init mediaEngine failed\n");
				return -1;
		}
   		(*mediaEngine).queryInterface(m_agoraEngine, agora::AGORA_IID_MEDIA_ENGINE);
   		m_parameters = new RtcEngineParameters(m_agoraEngine);

	}
	void setup_Media(/*TODO can add some args to control*/){
    	//media basic setup 
  		int ret = m_agoraEngine->setChannelProfile(CHANNEL_PROFILE_LIVE_BROADCASTING);
		if(ret == 0)
      		ret = m_agoraEngine->setClientRole(CLIENT_ROLE_BROADCASTER);
 	    m_agoraEngine->enableAudio();
  	  	m_parameters->muteLocalAudioStream(0);
  	 	m_agoraEngine->setAudioProfile((AUDIO_PROFILE_TYPE)0, (AUDIO_SCENARIO_TYPE)0);
  	  	m_parameters->enableWebSdkInteroperability(0);
	}

	void set_palyback_callback(write_data_callback_t callback, void *userdata, 
								int sampleRate = 16000, int channel =1, int renderTime = 20){
	 	//set audioFrame receive parameter and callback observer
		m_parameters->setPlaybackAudioFrameParameters(/*sampleRate*/sampleRate, /*channel*/channel,
													  /*mode*/RAW_AUDIO_FRAME_OP_MODE_READ_ONLY,
													   /*samplespercall*/sampleRate * renderTime / 1000 );
		audioFrameObserver = new AudioFrameObserver(callback, userdata);
		(*mediaEngine)->registerAudioFrameObserver(audioFrameObserver);
	}

	void join_channel(char *dynamicKey, char *channelId, char *info , int uid ){
   		m_agoraEngine->joinChannel(dynamicKey, channelId, info, uid); 
	}

	void enable_external_source(int nSampleRate = 32000, int nChannels = 1){
		//enable external audio source
    	m_parameters->setExternalAudioSource(true, /*nSampleRate*/nSampleRate, /*nChannels*/nChannels);
	}

	void incoming_data(void *data, int nsampleRate, int nChannels, int renderTimeMs){


		agora::media::IAudioFrameObserver::AudioFrame frame;
    	int nSampleRate = nsampleRate;
   		frame.bytesPerSample = 2;
   		frame.channels = nChannels;
   		frame.renderTimeMs = renderTimeMs;
   		frame.samples = nSampleRate * renderTimeMs / 1000;  
		frame.samplesPerSec = nSampleRate;
   		frame.type = agora::media::IAudioFrameObserver::AUDIO_FRAME_TYPE::FRAME_TYPE_PCM16;
    	frame.buffer = data;
		

    	(*mediaEngine)->pushAudioFrame(agora::media::MEDIA_SOURCE_TYPE::AUDIO_RECORDING_SOURCE, &frame, true);
	}

private:
    //agora 
    IRtcEngine*     m_agoraEngine;
    RtcEngineParameters* m_parameters;
    agora::util::AutoPtr<agora::media::IMediaEngine> *mediaEngine;
    AudioFrameObserver *audioFrameObserver;
	AGEngineEventHandler eventHandler;

	int nSampleRate;
	int nChannels;

};

void write_frame_callback(void *dst, void *src, int len){

	agora_session_t *session = (agora_session_t *)dst;
	if(session && session->state == JOINED){
		switch_mutex_lock(session->readbuf_mutex);

		switch_buffer_write(session->readbuf, src, len);

		switch_mutex_unlock(session->readbuf_mutex);
	}
	
	return;
}


int agora_init_module(const char *appid) { return 0; }

agora_session_t *agora_init_session(char *channelID)
{

	switch_memory_pool_t *pool = NULL;
	agora_session_t *session = NULL;
	switch_core_new_memory_pool(&pool);
	session = switch_core_alloc(pool, sizeof(agora_session_t));
	switch_mutex_init(&session->readbuf_mutex, SWITCH_MUTEX_NESTED, pool);
	switch_buffer_create_dynamic(&session->readbuf, 512, 512, 1024000);
	session->state = INIT;
	session->pool = pool;
    
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,"init mediaEngine successfully\n");


	agora_context *agora_ctx = new agora_context();
	agora_ctx->init("fe4b413a89e2440296df19089e518041");
	agora_ctx->setup_Media();
	agora_ctx->set_palyback_callback(write_frame_callback, session);
	agora_ctx->enable_external_source(/*nSampleRate*/ 32000,  /*nChannels*/1);
	agora_ctx->join_channel(/*dynamicKey*/NULL, /*channelId*/"w123", /*info*/NULL, /*uid*/301);

	session->agora_ctx = agora_ctx;
	session->state = JOINED;

    // //init agora
    // session->m_agoraEngine = createAgoraRtcEngine(); 
    // //initlize 
    // RtcEngineContext ctx;

    // ctx.eventHandler = &eventHandler; //here can set status change callback
    // ctx.appId = "fe4b413a89e2440296df19089e518041";
    // int ret = session->m_agoraEngine->initialize(ctx);
	// if(!ret){
	// 		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,"init mediaEngine successfully\n");
	// }
    // session->mediaEngine.queryInterface(session->m_agoraEngine, agora::AGORA_IID_MEDIA_ENGINE);
    // session->m_parameters = new RtcEngineParameters(session->m_agoraEngine);

    // //media basic setup 
  	// ret = session->m_agoraEngine->setChannelProfile(CHANNEL_PROFILE_LIVE_BROADCASTING);
	// if(ret == 0)
    //     ret = session->m_agoraEngine->setClientRole(CLIENT_ROLE_BROADCASTER);
    // session->m_agoraEngine->enableAudio();
    // session->m_parameters->muteLocalAudioStream(0);
    // session->m_agoraEngine->setAudioProfile((AUDIO_PROFILE_TYPE)0, (AUDIO_SCENARIO_TYPE)0);
    // session->m_parameters->enableWebSdkInteroperability(0);
	
	
    

	// //set audioFrame receive parameter and callback observer
	// session->m_parameters->setPlaybackAudioFrameParameters(/*sampleRate*/16000, /*channel*/1,
	// 												  /*mode*/RAW_AUDIO_FRAME_OP_MODE_READ_ONLY, /*samplespercall*/16000/50);
	// session->audioFrameObserver = new AudioFrameObserver(write_frame_callback, session);
	// //session->audioFrameObserver->setAgoraSession(session);
    // session->mediaEngine->registerAudioFrameObserver(session->audioFrameObserver);

	// //join channel
    // //session->m_agoraEngine->joinChannel(/*dynamicKey*/NULL, /*channelId*/channelID, /*info*/NULL, /*uid*/301); 
    // session->m_agoraEngine->joinChannel(/*dynamicKey*/NULL, /*channelId*/"w123", /*info*/NULL, /*uid*/301); 


	// //enable external audio source
    // session->m_parameters->setExternalAudioSource(true, /*nSampleRate*/16000, /*nChannels*/1);

    // //init agora done;
	
	g_out_fp = fopen(OUT_PATH, "wb+");
	g_input_fp = fopen(INPUT_PATH, "rb");
	return session;
}

int agora_read_data_from_session(agora_session_t *session, switch_frame_t *read_frame)
{
	switch_size_t len = PCM_16000_16_1_SIZE;
	switch_assert(session);
	len = min(len, read_frame->buflen);
	switch_mutex_lock(session->readbuf_mutex);
	read_frame->datalen = switch_buffer_read(session->readbuf, read_frame->data, len);
	switch_mutex_unlock(session->readbuf_mutex);
	 switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "agora_read_data_from_session %d \n",
	 read_frame->datalen);
	return read_frame->datalen;
	
}

int agora_write_data_to_session(agora_session_t *session, switch_frame_t *read_frame)
{
	switch_assert(session);

	// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "agora_write_data_to_session %d \n",
	// read_frame->datalen);
	fwrite(read_frame->data, read_frame->datalen, 1, g_out_fp);

    //push pcm data to audioFrame send to agora sdk
	agora_context *agora_ctx = (agora_context*)session->agora_ctx;
	//agora_ctx->incoming_data(read_frame->data ,/*nSampleRate*/32000,/*nchannels*/1, /*renderTimeMs*/10);

	char buf[1000 ];
	if(feof(g_input_fp))
        fseek(g_input_fp, 0, SEEK_SET);
    fread(buf, 1, 320 * 2, g_input_fp );
	agora_ctx->incoming_data(buf ,/*nSampleRate*/32000,/*nchannels*/1, /*renderTimeMs*/10);
	//
	return 0;
}

//状态消息上报
// todo
int agora_destory_session(agora_session_t *session)
{
	switch_status_t status;
	//释放
	if (session) {
		if (session->state >= RS_DESTROY) {
			return 0;
		}
		session->state = RS_DESTROY;

		if(g_out_fp){
			fclose(g_out_fp);
			g_out_fp = NULL;
		}


		if(g_input_fp){
			fclose(g_input_fp);
			g_input_fp = NULL;
		}

		//WARN: release agora first in case to session was free but a observer callback was triggered
		//not sure it works( args true means Synchronous )
		if(session->agora_ctx){
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "delete agora context\n");
			delete session->agora_ctx;
			session->agora_ctx = NULL;
		}
		

		switch_buffer_destroy(&session->readbuf);

		switch_core_destroy_memory_pool(&session->pool);
		session = NULL;
	}

	return 0;
}

int agora_release_module() { return 0; }
