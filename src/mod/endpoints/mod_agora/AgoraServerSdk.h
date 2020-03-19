#pragma once

#include "IAgoraServerEngine.h"
#include "AgoraSdk.h"
#include "base/atomic.h"
#include<string>

using std::string;

typedef void (*write_data_callback_t )(void *dst, void *src, int len);

class AgoraServerSdk : public agora::AgoraSdk, public agora::server::IServerEngineEventHandler {
public:
    AgoraServerSdk():AgoraSdk(),
        agora::server::IServerEngineEventHandler() { m_bActive = true;}
    ~AgoraServerSdk() {}

    bool createChannel(const string &appid, const string &channelKey, const string &name,
            uint32_t uid, agora::server::ServerConfig &config);

    virtual int setVideoMixingLayout(const agora::linuxsdk::VideoMixingLayout &layout);
    virtual int startService();
    virtual int stopService();
    virtual agora::recording::RecordingConfig* getConfigInfo(); 

    inline void setActive(bool active) { m_bActive = active; }

    void sendAudioFrame(void *data, int nSampleRate, int nchannels, int renderTimeMs);

    void setReceiveAudioCallback(void *data, write_data_callback_t callback){
        user_data = data;
        write_data_callback = callback;

    }

    virtual void audioFrameReceived(unsigned int uid, const agora::linuxsdk::AudioFrame *audioFrame) const {
         write_data_callback(user_data, audioFrame->frame.pcm->pcmBuf_, audioFrame->frame.pcm->pcmBufSize_);
         return;
    }

private:
    agora::server::ServerConfig m_sConfig;
    atomic_bool_t m_bActive;

    void *user_data;
	write_data_callback_t write_data_callback;
};



