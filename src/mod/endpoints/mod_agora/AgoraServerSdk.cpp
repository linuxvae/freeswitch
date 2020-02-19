#include"AgoraServerSdk.h"
#include"base/log.h"
#include <stdio.h>
#include <iostream>
#include <string.h>
#include "agora.h"

using std::cout;
using std::endl;
using agora::linuxsdk::VideoFrame;
using agora::linuxsdk::AudioFrame;

bool AgoraServerSdk::createChannel(const string &appid, const string &channelKey, const string &name,
        uint32_t uid, agora::server::ServerConfig &config)
{
    if ((m_engine = agora::server::IServerEngine::createAgoraServerEngine(appid.c_str(), this)) == NULL){
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "create agora server engine failed\n");

        return false;

    }

    if(agora::linuxsdk::ERR_OK != m_engine->joinChannel(channelKey.c_str(), name.c_str(), uid, config)){
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "join channel failed\n");
        return false;
    }

    m_sConfig = config;
    return true;
}

int AgoraServerSdk::setVideoMixingLayout(const agora::linuxsdk::VideoMixingLayout &layout)
{
   int result = -agora::linuxsdk::ERR_INTERNAL_FAILED;
   if(m_engine)
      result = m_engine->setVideoMixingLayout(layout);
   return result;
}

agora::recording::RecordingConfig* AgoraServerSdk::getConfigInfo() {
    return static_cast<agora::recording::RecordingConfig*>(&m_sConfig);
}

void AgoraServerSdk::sendAudioFrame(void *data, int nSampleRate, int nchannels, int renderTimeMs){

    agora::server::IServerEngine* m_server = dynamic_cast<agora::server::IServerEngine*>(m_engine);  
    if(!m_server)
        return;

    agora::linuxsdk::AudioPcmFrame pcmFr(/*frame_ms*/0, /*sample_rates*/nSampleRate, /*samples*/0);
    pcmFr.channels_ = nchannels;
    pcmFr.sample_bits_ = 16;
    pcmFr.frame_ms_ = renderTimeMs;
    pcmFr.samples_ = nSampleRate * pcmFr.frame_ms_ / 1000 * pcmFr.channels_;
	agora::linuxsdk::uint_t bytes = pcmFr.samples_ * (pcmFr.sample_bits_ / 8) * pcmFr.channels_;

    std::string pcmBuf;
    pcmBuf.reserve(bytes);
    char * buf = const_cast<char *>(pcmBuf.data());
    pcmFr.pcmBuf_ = reinterpret_cast<agora::linuxsdk::uchar_t *>(buf);
    pcmFr.pcmBufSize_ = (pcmBuf.capacity() > bytes) ? bytes:static_cast<agora::linuxsdk::uint_t>(pcmBuf.capacity());
    memcpy(buf, data, bytes);

    AudioFrame frame;
    frame.type = agora::linuxsdk::AUDIO_FRAME_RAW_PCM;
    frame.frame.pcm = &pcmFr;
    m_server->audioFrameSent(&frame);
}

int AgoraServerSdk::startService() {
  if(m_bActive)
    return -1;

  if (agora::AgoraSdk::startService()) { 
      m_bActive = true;
      return 1;
  } else
      return -1;

}

int AgoraServerSdk::stopService() {
  if(!m_bActive)
    return -1;

  if (agora::AgoraSdk::stopService()) { 
    m_bActive = false;
    return 1;
  } else
      return -1;
}

