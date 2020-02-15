#pragma once

#include <IAgoraMediaEngine.h>
#include <stdio.h>
#include <agora.h>

class AudioFrameObserver : public agora::media::IAudioFrameObserver
{
public:
    AudioFrameObserver();

    AudioFrameObserver(agora_session_t * session_ptr): session(session_ptr){};

	virtual bool onRecordAudioFrame(AudioFrame& audioFrame) ;
	virtual bool onPlaybackAudioFrame(AudioFrame& audioFrame) ;

	virtual bool onMixedAudioFrame(AudioFrame& audioFrame);
	
	virtual bool onPlaybackAudioFrameBeforeMixing(unsigned int uid, AudioFrame& audioFrame) ;
	
private:
    agora_session_t *session;
};
