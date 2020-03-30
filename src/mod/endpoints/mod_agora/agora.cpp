#include "agora.h"
#include "IAgoraServerEngine.h"
#include "AgoraServerSdk.h"
#include <sys/stat.h>
#include "agora_rtm.h"
#include <stdio.h>
#include <curl/curl.h>
#include <stdlib.h>
#include <jansson.h>
#include <time.h>
#include <map>


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
#define PCM_BUFFER_LEN 1000000
typedef void (*write_data_callback_t )(void *dst, void *src, int len);

//一些需要根据实际情况进行更改的路径

//根据使用的是生产还是测试的后台修改请求路径
static string url_prefix = "https://gw-api-hk-di1.sit.cmft.com:8085/";

//声网的密钥
static const char *agora_token			   = "fe4b413a89e2440296df19089e518041";
//用于语音提示的pcm文件的存放路径
static string pcm_path_prefix("/usr/local/freeswitch/sounds/");
//声网库存放的路径
static char * agora_libs_path = "/root/git/freeswitch/src/mod/endpoints/mod_agora/agora_bin"; 

static const char *join_success_pcm 		= "pcm/joinSuccess.pcm";
static const char *disable_audio_pcm 		= "pcm/disableAudio.pcm";
static const char *enable_audio_pcm 		= "pcm/enableAudio.pcm";
static const char *host_disable_audio_pcm 	= "pcm/hostDisableAudio.pcm";
static const char *host_enable_audio_pcm 	= "pcm/hostEnableAudio.pcm";
static const char *finish_meet_pcm 			= "pcm/finishMeet.pcm";
static const char *invalid_opera_pcm 		= "pcm/invalidOpera.pcm";
static const char *invite_code_err_pcm 		= "pcm/inviteCodeErr.pcm";
static const char *silence_pcm 				= "pcm/silence.pcm";

static string get_uid_url	   = url_prefix + "cscontrol/meet/user/phone/save";
static string join_url		   = url_prefix + "cscontrol/meet/room/v2/phone/join";
static string quit_url		   = url_prefix + "cscontrol/meet/room/v2/phone/quit";
static string update_status    = url_prefix + "cscontrol/meet/room/v2/user/Update";
static string invite_code_url  = url_prefix + "cscontrol/meet/room/v2/query/inviteCode";

//pcm file
class pcm_file{
public:
	char data[PCM_BUFFER_LEN];
	int len;
};

//pcm_fils_path存放的内容要和PCM_TYPE的顺序一致
vector<string> pcm_files_path{{pcm_path_prefix + join_success_pcm}, 
							  {pcm_path_prefix + disable_audio_pcm}, 
						  	  {pcm_path_prefix + enable_audio_pcm}, 
							  {pcm_path_prefix + host_disable_audio_pcm}, 
							  {pcm_path_prefix + host_enable_audio_pcm}, 
							  {pcm_path_prefix + finish_meet_pcm},
							  {pcm_path_prefix + invalid_opera_pcm},
							  {pcm_path_prefix + invite_code_err_pcm},
							  {pcm_path_prefix + silence_pcm}};

map<PCM_TYPE, shared_ptr<pcm_file>> pcm_map;
static int pcm_init = 0;

class agora_context{
public:
	agora_context( const char *token_a):agora_token(token_a){
		rtm_ptr.reset(new AgoraRtm(token_a));
		//FIXME 房间没人之后，多久关闭channel，此处必须要这个，只能设置成无限大，这个检测会导致sigterm异
		//常和崩溃，具体原因，暂时不明
		config.idleLimitSec = 2000000000;//
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
		config.appliteDir = agora_libs_path;
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

static size_t curl_ret_msg(void *buff, size_t size, size_t nmemb, void *content){
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
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_ret_msg);
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

int change_session_audio_status(agora_session_t* session, int enable, PCM_TYPE play_pcm){
	
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "session %d audio change from %s to %s\n",
					 session->uid, session->audio_enable? "enable":"disable", enable? "enable":"disable");

	char update_broadcast[200];
	int update_broadcast_index = 0;
	update_broadcast_index = sprintf(update_broadcast, "{\"type\":\"update\", \"enable\":\"\", \"fromUserId\":\"%d\", \"toUserId\":\" \","\
							"\"msgContent\":\"\"}", session->uid);


	switch_mutex_lock(session->av_enable_mutex);
		if(session->audio_enable == enable){
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,"session audio_enable not need to changed\n");
		}
		else{
			//更新后台状态
			char formdata[100];
			sprintf(formdata, "{\"userId\":%d, \"roomId\":\"%s\", \"audio\":%s}", 
					session->uid, session->room_id, enable? "true": "false");
			if(curl_request(update_status.c_str(), formdata, NULL)){
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,"update %d status failed\n", session->uid);
				switch_mutex_unlock(session->av_enable_mutex);
				return -1;
			}

			session->audio_enable = enable ? 1 : 0;

			//发送通知消息到频道
			string broadcast_msg(update_broadcast);
			session->agora_ctx->rtm_send_msg_to_channel(broadcast_msg);
		}

	switch_mutex_unlock(session->av_enable_mutex);

	//播放声音通知客户端
	write_pcm_back(session, play_pcm);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "session %d audio change successfully\n",session->uid);
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
		json_decref(content_json);
		return NULL;
	}

	const char *type = json_string_value(json_object_get(content_json, "type"));
	if(!type){
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "rtm_recv_channel_msg type is NULL\n");
		json_decref(content_json);
		return NULL;
	}

	int enable  = json_is_true(json_object_get(content_json ,"enable"));
	int from_user = json_integer_value(json_object_get(content_json ,"fromUserId"));
	string from_user_str = to_string(from_user);

	int to_user = json_integer_value(json_object_get(content_json ,"toUserId"));
	string to_user_str = to_string(to_user);
	string session_uid = to_string(session->uid);
	if(to_user_str.compare(session_uid)){
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "msg not for current session uid: %d\n", session->uid);
		json_decref(content_json);
		return NULL;
	}

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
	rtm_ack_index = sprintf(rtm_ack, "{\"type\":\"msg\", \"enable\":\"\", \"fromUserId\":%d, \"toUserId\":%s,",
							session->uid, from_user_str.c_str());

	char update_broadcast[200];
	int update_broadcast_index = 0;
	update_broadcast_index = sprintf(update_broadcast, "{\"type\":\"update\", \"enable\":\"\", \"fromUserId\":%d, \"toUserId\":,"\
							"\"msgContent\":\"\"", session->uid);

	if(!strcmp(type, "audio")){

		if(change_session_audio_status(session, enable, enable ? HOST_ENABLE_AUDIO_PCM : HOST_DISABLE_AUDIO_PCM)){
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "change session %d audio failed\n", session->uid);
			json_decref(content_json);
			return NULL;
		}

		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "finish change audio status \n");

		//rtm ack
		sprintf(rtm_ack + rtm_ack_index, "\"msgContent\": \"%s\"}",session->audio_enable? "已将成员解静":"已将成员静音" );
		string msg(rtm_ack);
		session->agora_ctx->rtm_send_msg_to_peer(from_user_str, msg);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "finish send replay rtm\n");

	}
	else if (!strcmp(type, "room")){
		//rtm ack
		sprintf(rtm_ack + rtm_ack_index, "\"msgContent\": \"%s\"}","移除成功");
		string msg(rtm_ack);
		session->agora_ctx->rtm_send_msg_to_peer(from_user_str, msg);

		//收到解散会议的消息，发送语音给客户
		write_pcm_back(session, FINISH_MEET_PCM);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "receive finish\n");
		
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

static int buffer_len = 0;

void agora_pcm_recv_callback(void *dst, void *src, int len){
	buffer_len += len;
	agora_session_t *session = (agora_session_t *)dst;
	//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "incoming msg len:%d, buffer_len:%d\n", len, buffer_len);
	if(session && session->state == JOINED ){
		switch_mutex_lock(session->readbuf_mutex);
			if(session->playbacking){
				switch_mutex_unlock(session->readbuf_mutex);
				return;
			}
			if (!switch_buffer_write(session->readbuf, src, len)){
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "no more space for writing\n");
			}
		switch_mutex_unlock(session->readbuf_mutex);
	}
	return;
}

void agora_set_session_play_pcm(agora_session_t* session, PCM_TYPE type){
	gettimeofday(&session->last_play_read_time, NULL); 
	session->pcm_play_info.play_type = type;
	session->pcm_play_info.buffer_read_offset = 0;
}

switch_size_t agora_read_pcm(pcm_play_ctx_t *play_ctx, void *data, switch_size_t datalen){

	PCM_TYPE type = play_ctx->play_type;
	switch_size_t offset = play_ctx->buffer_read_offset;
	switch_size_t result_len = pcm_map[type]->len - offset;
	if(result_len == 0)
		return 0;
	
	//WARN, datalen的类型为size_t， 在64位机器下是一个64位长度的数
	switch_size_t copy_len = min(datalen, result_len);
	memcpy(data, pcm_map[type]->data + offset, copy_len);
	play_ctx->buffer_read_offset += copy_len;

	return copy_len;
}

void clean_and_write_frame(void *dst, void *src, int len){
	agora_session_t *session = (agora_session_t *)dst;
	if(session && session->state == JOINED ){
			gettimeofday(&session->last_play_read_time, NULL); 
			switch_buffer_zero(session->readbuf);
			switch_buffer_write(session->readbuf, src, len);
	}
	return;
}

int write_pcm_back(agora_session_t *session, PCM_TYPE pcm_type){

	//FIXME 此处需要加锁判断，或者在模块被加载完成的时候就直接初始化
	if(pcm_init == 0){
		//加载pcm文件到内存
		pcm_init = 1;
		int count = 0 ;
		struct stat fileInfo;

		int file_size =  0;
		int index = 0;
		PCM_TYPE pcm_type = (PCM_TYPE)0;
		for(auto& file_path: pcm_files_path){
			if (stat(file_path.c_str(), &fileInfo)<0){
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "stat file %s failed\n", file_path.c_str());
				exit(0);
			}
			else{
				if(fileInfo.st_size > PCM_BUFFER_LEN){
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "file %s size %d larger than buffer %d\n",
									file_path.c_str(), PCM_BUFFER_LEN);
				exit(0);
				}
			}
			shared_ptr<pcm_file> *pcm_file_ptr = new shared_ptr<pcm_file>(new pcm_file());
			(*pcm_file_ptr)->len = fileInfo.st_size;
			FILE *fd = fopen(file_path.c_str(), "rb");
			fread((*pcm_file_ptr)->data, 1, PCM_BUFFER_LEN, fd);
			fclose(fd);
			pcm_map.insert(map<PCM_TYPE, shared_ptr<pcm_file>>::value_type(pcm_type, std::move(*pcm_file_ptr)));
			pcm_type = (PCM_TYPE)((int)pcm_type + 1);
		}

		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "finish pcm file loading initilized, load %d pcm file\n",
						 pcm_map.size());
	}

	if(pcm_type != FINISH_MEET_PCM){
		switch_mutex_lock(session->readbuf_mutex);
		session->playbacking = 1;
		agora_set_session_play_pcm(session, pcm_type);
		switch_mutex_unlock(session->readbuf_mutex);
	}
	else {
		switch_mutex_lock(session->readbuf_mutex);
		session->playbacking = 1;
		session->hangup = 1;
		agora_set_session_play_pcm(session, pcm_type);
		switch_mutex_unlock(session->readbuf_mutex);
	}
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "play info successfully\n");
	return 0;
}


int agora_init_module(const char *appid) { return 0; }


typedef void (*curl_callback_t)(void *buff, size_t size, size_t nmemb);

int agora_handle_dtmf(agora_session_t *session, char digit){

	if(session->state == JOINED){
		if(digit == '#'){
			if(session->dtmf_digit == '0'){//查询状态
				write_pcm_back(session, session->audio_enable? ENABLE_AUDIO_PCM : DISABLE_AUDIO_PCM);
			}
			else if(session->dtmf_digit == '2'){//mute audio
				change_session_audio_status(session, 0, DISABLE_AUDIO_PCM);
			}
			else if(session->dtmf_digit == '1'){//unmute audio
				change_session_audio_status(session, 1, ENABLE_AUDIO_PCM);
			}
			else{
				write_pcm_back(session, INVALID_OPERA_PCM);
			}
			session->dtmf_digit = 0;
		}
		else{
			session->dtmf_digit = digit;
		}
	}
	else{
		if(digit == '#'){
			if( session->dtmf_meet_id.size() > 0 ){
				agora_join_meet(session, session->dtmf_meet_id);
				session->dtmf_meet_id.clear();
			}
			else{
				//play back, 您的输入有误，请重新输入会议邀请码
				write_pcm_back(session, INVITE_CODE_ERR_PCM);
			}
		}
		else{
			if(session->dtmf_meet_id.size() > 50){
				write_pcm_back(session, INVITE_CODE_ERR_PCM);
				session->dtmf_meet_id.clear();
			}
			else 
				session->dtmf_meet_id += digit;
		}
	}
	return 0;
}



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

//return result->parresult_field str, need to be free
static char* parse_result_filed_str(char *content, char *parsed_result_field){
	//使用json_load出来后进行解析，如果通过，返回结果
	json_error_t error;
	json_t *content_json = json_loads(content, 0, &error);//need to free?
	char *field = NULL;
	if(content_json){
		json_t *reseult_json = json_object_get(content_json, "result");
		json_t* filed_json = json_object_get(reseult_json, parsed_result_field);
		if(filed_json){
			const char *temp = json_string_value(filed_json);
			field = new char[strlen(temp) + 1];
			sprintf(field, "%s", temp);
		}
	}
	else
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "json loads content failed\n");
end:
	if(content_json)
		json_decref(content_json);
	return field;
}

//触发点为创建session 以及dtmf输入会议号，底层应该保证了两个动作的同步性
void agora_join_meet(agora_session_t *session, string &invite_code){
		//获取房间邀请码
	if(invite_code.size() < 6 || invite_code.size() > 20 ){
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "meet invite id invalid\n");
		write_pcm_back(session, INVITE_CODE_ERR_PCM);
		return;
	}

	char formdata[100];
	char *room_id = NULL;
	char *content = NULL;
	int ret = 0;
	snprintf(formdata, 100, "{\"inviteCode\":\"%s\"}", invite_code.c_str());

	if(!curl_request(invite_code_url.c_str(), formdata, &content)){
		if(!content || (room_id = parse_result_filed_str(content, "roomId")) == NULL){
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "parse roomId failed\n");
			//play back 您的邀请码不正确请重新输入
			write_pcm_back(session, INVITE_CODE_ERR_PCM);
			ret = 1;

		}
		if(content)
			free(content);
		if(ret)
			return;
	}
	else{
		write_pcm_back(session, INVITE_CODE_ERR_PCM);
		return;
	}


	//获取加入房间的id
	//room_id = "096082593";
	snprintf(formdata, 100, "{\"account\":\"%d\"}", session->src_number);
	__int64_t id = 0;
	if(!curl_request(get_uid_url.c_str(), formdata, &content)){
		if(!content || (session->uid = parse_id(content)) == -1){
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "parse id failed\n");
			//play back 您的邀请码不正确请重新输入
			write_pcm_back(session, INVITE_CODE_ERR_PCM);
			ret = 1;
		}

		if(content)
			free(content);
		if(ret)
			return;
	}
	else{
		write_pcm_back(session, INVITE_CODE_ERR_PCM);
		return;
	}
	agora_context *agora_ctx = session->agora_ctx;
	agora_ctx->setReceiveAudioCallback(session, agora_pcm_recv_callback);

	//加入房间
	snprintf(formdata, 100, "{\"roomId\":\"%s\", \"userId\":%d, \"audio\":true}", room_id, session->uid);
	if(!curl_request(join_url.c_str(), formdata, NULL)){
		if( !agora_ctx->create_channel(/*appId*/agora_token, /*channelKey*/"",
						 			room_id, /*uid*/session->uid ,rtm_recv_channel_msg, session) ){
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "join media channel failed\n");
			write_pcm_back(session, INVITE_CODE_ERR_PCM);
			return;
		}
		agora_ctx->start_service();
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "join channel successfully\n");
		session->state = JOINED;
		snprintf(session->room_id, room_id_len, "%s", room_id);
		//delete room_id; 

		//播放进入会议成功提示
		write_pcm_back(session, JOIN_SUCCESS_PCM);
	}
	else{
		write_pcm_back(session, INVITE_CODE_ERR_PCM);
		return;
	}
}

agora_session_t *agora_init_session(int src_number, string &invite_code)
{
	switch_memory_pool_t *pool = NULL;
	agora_session_t *session = NULL;
	switch_core_new_memory_pool(&pool);
	session = switch_core_alloc(pool, sizeof(agora_session_t));
	switch_mutex_init(&session->readbuf_mutex, SWITCH_MUTEX_NESTED, pool);
	switch_mutex_init(&session->av_enable_mutex, SWITCH_MUTEX_NESTED, pool);
	switch_buffer_create_dynamic(&session->readbuf, 512, 512, 480000);
	session->state = INIT;
	session->pool = pool;
	session->audio_enable = 1;
	session->video_enable = 0;
	session->src_number = src_number;

	agora_context *agora_ctx = new agora_context(agora_token);
	session->agora_ctx = agora_ctx;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "start to join meet\n");
	agora_join_meet(session, invite_code);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "finish agora session init\n");
	return session;
}


struct switch_buffer {
	switch_byte_t *data;
	switch_byte_t *head;
	switch_size_t used;
	switch_size_t actually_used;
	switch_size_t datalen;
	switch_size_t max_len;
	switch_size_t blocksize;
	switch_mutex_t *mutex;
	uint32_t flags;
	uint32_t id;
	int32_t loops;
};

int agora_read_data_from_session(agora_session_t *session, switch_frame_t *read_frame)
{
	switch_size_t len = PCM_48000_16_1_SIZE;
	switch_assert(session);
	len = min(len, read_frame->buflen);
	int hangup = 0;
	switch_mutex_lock(session->readbuf_mutex);

		if( session->playbacking){
			//plyaback的时候，readbuf数据量过多，读取的速度过快，会导致音频变形, 需要设置间隔
			struct timeval now;
			gettimeofday(&now, NULL);
			long interval = (long)now.tv_sec*1000 + (long)now.tv_usec/1000 - 
							(long)session->last_play_read_time.tv_sec*1000- (long)session->last_play_read_time.tv_usec/1000;
			if(interval < 10){
				switch_mutex_unlock(session->readbuf_mutex);
				return 0;
			}
			session->last_play_read_time = now;
			
			//读取音频
			read_frame->datalen = agora_read_pcm(&session->pcm_play_info, read_frame->data, len);

			if(read_frame->datalen == 0){
				//播放完成了
				session->playbacking = 0;
				if(session->state != JOINED){
					//还未进入房间，播放完成后继续播放静音包，否则没数据上去将导致hangup
					agora_set_session_play_pcm(session, SILENCE_PCM);
					session->playbacking = 1;
				}

				if(session->hangup)//如果设置了hangup，播放完了finish meet，要挂断通道
					hangup = 1;
			
			}
		}
		else{
			//加入会议了，从readbuf中取数据
			read_frame->datalen = switch_buffer_read(session->readbuf, read_frame->data, len);
		}

		// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "read_frame head %u, used: %d\n",session->readbuf->head,
		// 					session->readbuf->used);	

	switch_mutex_unlock(session->readbuf_mutex);
	if(hangup){
		agora_channel_hangup(session->agora_private);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "hangup\n");
	}

	return read_frame->datalen;
}

int agora_write_data_to_session(agora_session_t *session, switch_frame_t *write_frame)
{
	switch_assert(session);
	if(session->state != JOINED)
		return 0;

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
	agora_ctx->send_audio(write_frame->data ,/*nSampleRate*/32000,/*nchannels*/1, /*renderTimeMs*/10);

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
		if(!curl_request(quit_url.c_str(), formdata, NULL)){
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "quit channel successfully\n");
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
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "delete agora context\n");
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
