#include "agora.h"
#include "IAgoraServerEngine.h"
#include "AgoraServerSdk.h"
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
#define RECEIVE_PATH "/root/receive.pcm"
static FILE *g_fp = NULL;
static FILE *g_out_fp = NULL;
static FILE *g_input_fp = NULL;
static FILE *g_receive_fp = NULL;

static FILE *g_48pcm  = NULL;


#define PCM_16000_16_1_SIZE 640
#define PCM_48000_16_1_SIZE 960
typedef void (*write_data_callback_t )(void *dst, void *src, int len);

class agora_context{
public:
	agora_context(){
		config.idleLimitSec = 300;//300s
		//"channel_profile:(0:COMMUNICATION),(1:broadcast) default is 0/option"
		config.channelProfile = static_cast<agora::linuxsdk::CHANNEL_PROFILE_TYPE>(0);

		config.isVideoOnly = 0;
		config.isAudioOnly = 1;//only audio
		//whether enable mixing 
		config.isMixingEnabled = 0;
		//set video mixing resolution
		config.mixResolution = NULL;
		//mixVideoAudio:(0:seperated Audio,Video) (1:mixed Audio & Video), default is 0 /option
		config.mixedVideoAudio = 0;


		//location of file AgoraCoreService, need to be change while it's position change
		config.appliteDir = "/root/git/freeswitch/src/mod/endpoints/mod_agora/agora_bin";
		config.recordFileRootDir = "./";
		config.cfgFilePath = NULL;

		//input secret when enable decryptionMode/option
		config.secret = NULL;
		//decryption Mode, default is NULL/option
		config.decryptionMode =  NULL;

		//default is random value/option
		config.lowUdpPort = 10002; //what is the work of it?
		config.highUdpPort = 19000;
		//default 5 (Video snapshot interval (second))
		config.captureInterval = 5;

		//default 0 (0:save as file, 1:aac frame, 2:pcm frame, 3:mixed pcm frame) (Can't combine with isMixingEnabled) /option
		config.decodeAudio = static_cast<agora::linuxsdk::AUDIO_FORMAT_TYPE>(3);
		//default 0 (0:save as file, 1:h.264, 2:yuv, 3.jpg buffer, 4,jpg file, 5:jpg file and video file) (Can't combine with isMixingEnabled) /option
		//config.decodeVideo = static_cast<agora::linuxsdk::VIDEO_FORMAT_TYPE>(2);
		
		//remote video stream type(0:STREAM_HIGH,1:STREAM_LOW), default is 0/option
		config.streamType = static_cast<agora::linuxsdk::REMOTE_VIDEO_STREAM_TYPE>(0);
		config.audioChannelNum = 1;
		config.audioSampleRate = 32000;
		//config.upstreamResolution = const_cast<char*>(upstreamResolution.c_str());
		config.proxyServer = NULL;
		//server.updateMixModeSetting(width, height, isMixingEnabled ? !isAudioOnly:false);

	}

	~agora_context(){
		server.stopService();
		server.leaveChannel();
  		server.release();
	}

	bool create_channel(const string &appid, const string &channelKey, const string &channelNanme,
        uint32_t uid){	
		return server.createChannel(appid, channelKey, channelNanme, uid, config);

	}

	void setReceiveAudioCallback(void *data, write_data_callback_t callback){
		server.setReceiveAudioCallback(data, callback);
	}

	int start_service() {
		return server.startService();
	}

	int stop_service(){
		return server.stopService();
	}

	void send_audio(void *data ,int nSampleRate, int nchannels, int renderTimeMs){
		server.sendAudioFrame(data, nSampleRate, nchannels, renderTimeMs);
	}

	AgoraServerSdk server;
  	agora::server::ServerConfig config;
};


void write_frame_callback(void *dst, void *src, int len){

	agora_session_t *session = (agora_session_t *)dst;
	if(session && session->state == JOINED ){
		
		switch_mutex_lock(session->readbuf_mutex);
			//fwrite(src, 1, len ,g_receive_fp);
			/*
			if(g_48pcm == NULL)
				g_48pcm = fopen("/root/media/32k.pcm", "rb");
			if(feof(g_48pcm))
				fseek(g_48pcm, 0, SEEK_SET);
			
			int sampleRate = 48000;
			int buflen = sampleRate * 10 / 1000 * 2;
			char buf[1024];
			fread(buf, 1, buflen, g_48pcm);
			*/

			switch_buffer_write(session->readbuf, src, len);
			//switch_buffer_write(session->readbuf, buf, buflen);
			//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,"recv data %d bytes\n", len);		

		switch_mutex_unlock(session->readbuf_mutex);
	}
	
	return;
}


int agora_init_module(const char *appid) { return 0; }

agora_session_t *agora_init_session(int src_number, char *channelID)
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
	session->agora_ctx = agora_ctx;
	agora_ctx->setReceiveAudioCallback(session, write_frame_callback);
	if( !agora_ctx->create_channel(/*appId*/"fe4b413a89e2440296df19089e518041", /*channelKey*/"",
						 			"w123", /*uid*/src_number)){
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "join channel failed\n");
	}
	else{
		session->state = JOINED;
	}

	agora_ctx->start_service();
 
	g_out_fp = fopen(OUT_PATH, "wb+");
	g_receive_fp = fopen(RECEIVE_PATH, "wb+");
	g_input_fp = fopen(INPUT_PATH, "rb");
	return session;
}

int agora_read_data_from_session(agora_session_t *session, switch_frame_t *read_frame)
{
	switch_size_t len = PCM_48000_16_1_SIZE;
	switch_assert(session);
	len = min(len, read_frame->buflen);
	switch_mutex_lock(session->readbuf_mutex);
		read_frame->datalen = switch_buffer_read(session->readbuf, read_frame->data, len);

	switch_mutex_unlock(session->readbuf_mutex);
	 //switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "agora_read_data_from_session %d \n",
	 //read_frame->datalen);
	return read_frame->datalen;
	
}

int agora_write_data_to_session(agora_session_t *session, switch_frame_t *read_frame)
{
	switch_assert(session);

	// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "agora_write_data_to_session %d \n",
	// read_frame->datalen);
	//fwrite(read_frame->data, read_frame->datalen, 1, g_out_fp);

    //push pcm data to audioFrame send to agora sdk
	agora_context *agora_ctx = (agora_context*)session->agora_ctx;
	agora_ctx->send_audio(read_frame->data ,/*nSampleRate*/32000,/*nchannels*/1, /*renderTimeMs*/10);

	// char buf[1000];
	// if(feof(g_input_fp))
    //     fseek(g_input_fp, 0, SEEK_SET);
    // fread(buf, 1, 320 * 2, g_input_fp );
	// agora_ctx->send_audio(buf ,/*nSampleRate*/32000,/*nchannels*/1, /*renderTimeMs*/10);
	
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

		if(g_receive_fp){
			fclose(g_receive_fp);
			g_receive_fp = NULL;
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
