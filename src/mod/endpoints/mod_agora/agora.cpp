#include "agora.h"
#include "IAgoraServerEngine.h"
#include "AgoraServerSdk.h"
#include "agora_rtm.h"
#include <stdio.h>
#include <curl/curl.h>
#include <stdlib.h>
#include <jansson.h>


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

static const char* get_uid_url = "https://coco-di1.sit.cmhk.com:28082/iocp-chatroom/meet/user/phone/save";
static const char* join_url = 	 "https://coco-di1.sit.cmhk.com:28082/iocp-chatroom/meet/room/v2/phone/join";
static const char* quit_url = 	 "https://coco-di1.sit.cmhk.com:28082/iocp-chatroom/meet/room/v2/phone/quit";
static const char* update_status = "https://coco-di1.sit.cmhk.com:28082/iocp-chatroom/meet/room/v2/user/Update";
const char *agora_token = "fe4b413a89e2440296df19089e518041";

class agora_context{
public:
	agora_context( const char *token_a):agora_token(token_a){
		rtm_ptr.reset(new AgoraRtm(token_a));
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
        uint32_t uid, recv_callback_t cb1, void *cb1_arg){	
		char user_id[25];
		snprintf(user_id, 25, "%d", uid);
		//媒体
		if(!server.createChannel(appid, channelKey, channelNanme, uid, config)){
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "user %s create channel failed\n", user_id);
			return false;
		}

		//通讯
		if(!rtm_ptr->login(appid.c_str(), user_id)){
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "rtm: user %s login failed\n",user_id);
			return false;
		}
		if(!rtm_ptr->joinChannel(channelNanme, cb1, cb1_arg)){
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "rtm: join channel %s failed\n", channelNanme);
			return false;
		}
		return true;
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

	void rtm_send_msg_to_peer(std::string &peerID, std::string &msg){
		rtm_ptr->sendMessageToPeer(peerID, msg);
	}

	void rtm_send_msg_to_channel(string &msg){
		rtm_ptr->sendMessageToChannel(msg);
	}

	AgoraServerSdk server;
	unique_ptr<AgoraRtm> rtm_ptr;
	agora::server::ServerConfig config;
	const char* agora_token;
	
};

static size_t write_function(void *buff, size_t size, size_t nmemb, void *content){
    size_t realsize = size * nmemb;
    char *p  = *(char ** )content;
    size_t len = p ? strlen(p) : 0;
    *(char **)content = (char *)realloc(p, len + realsize + 1);
    p = *(char **)content;
    if(p == NULL){
        return -1;
    }
    memcpy(p+len, buff, realsize);
    p[len + realsize] = '\0';
    return realsize;
}


//curl request
static int curl_request(const char *url , const char *format_data, char **content_a){
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "request %s with data %s\n", url, format_data);
    static CURL *curl = NULL;
	if(content_a)
		*content_a = NULL;
	char* content = NULL;
	if(!curl){
    	curl = curl_easy_init();//warn need to excute curl_easy_cleanup(curl) to free

		 //设置请求的content-type为json格式
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type:application/json;charset=UTF-8");
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		//设置POST为1 这个动作是post(如果不设置，则默认为GET)、URL和FORM_DATA
        curl_easy_setopt(curl, CURLOPT_POST, 1);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_function);
	}

    if(curl){
		//设置数据与回调
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, format_data);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &content);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        //不验证证书
       //curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);//设定为不验证证书和HOST
       //curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
       //curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 1000); //设置超时时间
        CURLcode code = curl_easy_perform(curl);

 		if(code == CURLE_OK || code == CURLE_FTP_ACCEPT_TIMEOUT){
			 if(content){
				json_error_t error;
				json_t *content_json = json_loads(content, 0, &error);//need to free?
				if(!content_json){
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "json loads content failed\n");
					json_decref(content_json);
					return -1;
				}
				json_t *code_json = json_object_get(content_json, "code");
				if(json_integer_value(code_json)){
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "http failed with response: %s\n", content);
					json_decref(content_json);
					return -1;
				}
				json_decref(content_json);
			 }

			 if(content_a != NULL)
			 	*content_a = content;
			 else
			 	free(content);
			return 0;
        }
    }
	return -1;
}

void *rtm_recv_channel_msg(void *data, void *arg){
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "rtm_recv_channel_msg %s\n", data);

	char *content = (char *)data;
	agora_session_t *session = (agora_session_t *)arg;
	//int audio_enable = 0, video_enable = 0;

	//parse recv_msg
	json_error_t error;
	json_t *content_json = json_loads(content, 0, &error);
	if(!content_json){
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "json loads content failed\n");
		goto end;
	}

	const char *type = json_string_value(json_object_get(content_json, "type"));
	if(!type){
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "rtm_recv_channel_msg type is NULL\n");
		goto end;
	}

	int enable  = json_is_true(json_object_get(content_json ,"enable"));
	const char *from_user = json_string_value(json_object_get(content_json ,"fromUserId"));
	const char *to_user = json_string_value(json_object_get(content_json ,"toUserId"));
	
	char session_uid[20];
	sprintf(session_uid, "%d", session->uid);
	if(to_user && strcasecmp(to_user, session_uid)){
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "msg not for current session uid: %d\n", session->uid);
		goto end;
	}

	//判断dst_user 是否与当前相等

	//打开或者关闭摄像头
	// 	{
	// "type": "audio | video"
	// "enable": "false"
	// "fromUserId": "a的userId"
	// "toUserId": "b的userId"
	// "fromUserName": ""
	//  "msgContent": ""
	// }
	char rtm_ack[200];
	int rtm_ack_index = 0;
	rtm_ack_index = sprintf(rtm_ack, "{\"type\":\"msg\", \"enable\":\"\", \"fromUserId\":\"%d\", \"toUserId\":\"%s\",",
							session->uid, from_user);

	char update_broadcast[200];
	int update_broadcast_index = 0;
	update_broadcast_index = sprintf(update_broadcast, "{\"type\":\"update\", \"enable\":\"\", \"fromUserId\":\"%d\", \"toUserId\":\" \","\
							"\"msgContent\":\"\"", session->uid);

	if(!strcmp(type, "audio")){
		switch_mutex_lock(session->av_enable_mutex);

		//更新后台状态
		char formdata[100];
		sprintf(formdata, "{\"userId\":%d, \"roomId\":\"%s\", \"audio\":%s}", 
				session->uid, session->room_id, enable? "true": "false");
		if(curl_request(update_status, formdata, NULL)){
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,"update %d status failed\n", session->uid);
			switch_mutex_unlock(session->av_enable_mutex);
			goto end;
		}

		session->audio_enable = enable ? 1 : 0;

		//rtm ack
		sprintf(rtm_ack + rtm_ack_index, "\"msgContent\": \"%s\"}",session->audio_enable?" ":"已将成员静音" );

		string dst_user(from_user);
		string msg(rtm_ack);
		session->agora_ctx->rtm_send_msg_to_peer(dst_user, msg);

		switch_mutex_unlock(session->av_enable_mutex);

		//发送通知消息到频道
		string broadcast_msg(rtm_ack);
		session->agora_ctx->rtm_send_msg_to_channel(broadcast_msg);

		//TODO 播放提示告知客户端已经被静音了
		//调用ivr

	}
	else if(!strcmp(type, "video")){
		//TODO 加入视频后完善此块控制
		switch_mutex_lock(session->av_enable_mutex);
		session->video_enable = enable ? 1 : 0;
		switch_mutex_unlock(session->av_enable_mutex);
	}

end:;
	json_decref(content_json);
	return NULL;
}

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


typedef void (*curl_callback_t)(void *buff, size_t size, size_t nmemb);




static int parse_id(char *content){
	//使用json_load出来后进行解析，如果通过，返回结果
	json_error_t error;
	json_t *content_json = json_loads(content, 0, &error);//need to free?
	int ret = -1;
	if(content_json){
		json_t *reseult_json = json_object_get(content_json, "result");
		json_t* id_json = json_object_get(reseult_json, "id");
		if(id_json)
			ret =  json_integer_value(id_json);
	}
	else
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "json loads content failed\n");
end:
	if(content_json)
		json_decref(content_json);
	return ret;
}


agora_session_t *agora_init_session(int src_number, char *room_id, char *channelID)
{

	switch_memory_pool_t *pool = NULL;
	agora_session_t *session = NULL;
	switch_core_new_memory_pool(&pool);
	session = switch_core_alloc(pool, sizeof(agora_session_t));
	switch_mutex_init(&session->readbuf_mutex, SWITCH_MUTEX_NESTED, pool);
	switch_mutex_init(&session->av_enable_mutex, SWITCH_MUTEX_NESTED, pool);
	switch_buffer_create_dynamic(&session->readbuf, 512, 512, 1024000);
	session->state = INIT;
	session->pool = pool;
	session->audio_enable = 1;
	session->video_enable = 0;
	
	agora_context *agora_ctx = new agora_context(agora_token);
	session->agora_ctx = agora_ctx;

	//获取加入房间的id
	char *content = NULL;
	char formdata[100];
	snprintf(formdata, 100, "{\"account\":\"%d\"}", src_number);
	__int64_t id = 0;
	if(!curl_request(get_uid_url, formdata, &content)){
		if(!content || (session->uid = parse_id(content)) == -1){
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "parse id failed\n");
		}

		if(content)
			free(content);
	}

	agora_ctx->setReceiveAudioCallback(session, write_frame_callback);

	//加入房间
	snprintf(formdata, 100, "{\"roomId\":\"%s\", \"userId\":%d, \"audio\":true}", room_id, session->uid);
	if(!curl_request(join_url, formdata, NULL)){
		if( !agora_ctx->create_channel(/*appId*/agora_token, /*channelKey*/"",
						 			room_id, /*uid*/session->uid ,rtm_recv_channel_msg, session) ){
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "join media channel failed\n");
			//TODO leaving room
		}
		agora_ctx->start_service();
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "join channel successfully\n");
		session->state = JOINED;
		snprintf(session->room_id, room_id_len, "%s", room_id);
	}
	else{
		//TODO 释放资源
		return NULL;
	}
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
	switch_mutex_lock(session->av_enable_mutex);
	if(!session->audio_enable){
		switch_mutex_unlock(session->av_enable_mutex);
		return 0;
	}
	switch_mutex_unlock(session->av_enable_mutex);

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
		//退出房间
		char formdata[100];
		snprintf(formdata, 100, "{\"roomId\":\"%s\",\"userId\":%d}", session->room_id, session->uid);
		if(!curl_request(quit_url, formdata, NULL)){
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "quit channel successfully\n");
		}

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
