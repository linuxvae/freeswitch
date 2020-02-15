#include "agora.h"
#include "IAgoraRtcEngine.h"
#include "AudioFrameObserver.h"
#include "IAgoraMediaEngine.h"
#include <stdio.h>

#if !defined(min)
#define min(a, b) ((a) <= (b) ? (a) : (b))
#endif
#if !defined(max)
#define max(a, b) ((a) >= (b) ? (a) : (b))
#endif

#define F_PATH "/root/test.pcm"
#define OUT_PATH "/root/out.pcm"
static FILE *g_fp = NULL;
static FILE *g_out_fp = NULL;
#define PCM_16000_16_1_SIZE 640

static void *SWITCH_THREAD_FUNC read_data_thread(switch_thread_t *thread, void *obj)
{
	unsigned char rdata[PCM_16000_16_1_SIZE] = "";
	switch_size_t rlen = 0;
	agora_session_t *session = (agora_session_t *)obj;
	while (session->state != RS_DESTROY) {
		rlen = fread(rdata, 1, PCM_16000_16_1_SIZE, g_fp);
		if (rlen > 0) {
			switch_mutex_lock(session->readbuf_mutex);
			switch_buffer_write(session->readbuf, rdata, rlen);
			switch_mutex_unlock(session->readbuf_mutex);
		}
		if (feof(g_fp)) {
			fseek(g_fp, 0L, SEEK_SET);
		}
		switch_sleep(19000);
	}
	return NULL;
}

int agora_init_module(const char *appid) { return 0; }

agora_session_t *agora_init_session(char *channelID)
{
	switch_thread_t *thread = NULL;
	switch_threadattr_t *thd_attr = NULL;
	switch_memory_pool_t *pool = NULL;
	agora_session_t *session = NULL;
	switch_core_new_memory_pool(&pool);
	session = switch_core_alloc(pool, sizeof(agora_session_t));
	switch_mutex_init(&session->readbuf_mutex, SWITCH_MUTEX_NESTED, pool);
	switch_buffer_create_dynamic(&session->readbuf, 512, 512, 1024000);
	session->state = INIT;
	session->pool = pool;
    
    //init agora
    session->m_agoraEngine = createAgoraRtcEngine(); 
    //initlize 
    RtcEngineContext ctx;
    ctx.eventHandler = NULL; //here can set status change callback
    ctx.appId = "fe4b413a89e2440296df19089e518041";
    session->m_agoraEngine->initialize(ctx);
    session->mediaEngine.queryInterface(session->m_agoraEngine, agora::AGORA_IID_MEDIA_ENGINE);
    session->m_parameters = new RtcEngineParameters(session->m_agoraEngine);

    //media basic setup 
    session->m_agoraEngine->enableAudio();
    session->m_parameters->muteLocalAudioStream(0);
    session->m_agoraEngine->setAudioProfile((AUDIO_PROFILE_TYPE)0, (AUDIO_SCENARIO_TYPE)0);
    session->m_parameters->enableWebSdkInteroperability(0);
	
	//enable external audio source
    session->m_parameters->setExternalAudioSource(true, /*nSampleRate*/16000, /*nChannels*/1);
    

	//set audioFrame receive parameter and callback observer
	session->m_parameters->setPlaybackAudioFrameParameters(/*sampleRate*/16000, /*channel*/1,
													  /*mode*/RAW_AUDIO_FRAME_OP_MODE_READ_ONLY, /*samplespercall*/16000/50);
    session->audioFrameObserver = new AudioFrameObserver(session);
    session->mediaEngine->registerAudioFrameObserver(session->audioFrameObserver);

	//join channel
    //session->m_agoraEngine->joinChannel(/*dynamicKey*/NULL, /*channelId*/channelID, /*info*/NULL, /*uid*/"fs_test"); 
    session->m_agoraEngine->joinChannel(/*dynamicKey*/NULL, /*channelId*/"w123", /*info*/NULL, /*uid*/"fs_test"); 

    //init agora done;

	// todo
	//if (!g_fp) {
	//	g_fp = fopen(F_PATH, "rb+");
	//}
	//if (!g_out_fp) {
	//	g_out_fp = fopen(OUT_PATH, "wb+");
	//}
	//switch_threadattr_create(&thd_attr, session->pool);
	// switch_threadattr_detach_set(thd_attr, 1);
	//switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
	//if (switch_thread_create(&thread, thd_attr, read_data_thread, session, session->pool) != SWITCH_STATUS_SUCCESS) {
	//	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Could not load  read frame switch_thread_create\n");
	//}
	// end
	//session->thread = thread;
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
	// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "agora_read_data_from_session %d \n",
	// read_frame->datalen);
	return read_frame->datalen;
	//
}
int agora_write_data_to_session(agora_session_t *session, switch_frame_t *read_frame)
{
	switch_assert(session);

	// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "agora_write_data_to_session %d \n",
	// read_frame->datalen);
	//fwrite(read_frame->data, read_frame->datalen, 1, g_out_fp);

    //push pcm data to audioFrame send to agora sdk
    agora::media::IAudioFrameObserver::AudioFrame frame;

    int nSampleRate = 16000;
    frame.bytesPerSample = 2;
    frame.channels = 1;
    frame.renderTimeMs = 20;
    frame.samples = nSampleRate / 50; // 20ms , 1/50s 
    frame.samplesPerSec = nSampleRate;
    frame.type = agora::media::IAudioFrameObserver::AUDIO_FRAME_TYPE::FRAME_TYPE_PCM16;


    frame.buffer = read_frame->data;
    session->mediaEngine->pushAudioFrame(agora::media::MEDIA_SOURCE_TYPE::AUDIO_RECORDING_SOURCE, &frame, true);

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
		switch_thread_join(&status, session->thread);
		switch_buffer_destroy(&session->readbuf);
        
        if(session->m_agoraEngine != NULL) {
            session->m_agoraEngine->release();
            session->m_agoraEngine = NULL;
        }

        if(session->m_parameters) {
            delete session->m_parameters;
            session->m_parameters = NULL;
        }
		
        if(session->audioFrameObserver) {
            delete session->audioFrameObserver;
            session->audioFrameObserver = NULL;
        }

		switch_core_destroy_memory_pool(&session->pool);
		session = NULL;
	}
	if (g_fp) {
		fclose(g_fp);
		g_fp = NULL;
	}
	if (g_out_fp) {
		fclose(g_out_fp);
		g_out_fp = NULL;
	}
	return 0;
}

int agora_release_module() { return 0; }
