#pragma once

#include "IAgoraMediaEngine.h"
#include <stdio.h>

typedef void (*write_data_callback_t )(void *dst, void *src, int len);


class AudioFrameObserver : public agora::media::IAudioFrameObserver
{
public:
    AudioFrameObserver();

    AudioFrameObserver(write_data_callback_t callback, void *userdata): write_data_callback(callback), 
																		user_data(userdata){};


	virtual bool onRecordAudioFrame(AudioFrame& audioFrame) ;
	virtual bool onPlaybackAudioFrame(AudioFrame& audioFrame) ;

	virtual bool onMixedAudioFrame(AudioFrame& audioFrame);
	
	virtual bool onPlaybackAudioFrameBeforeMixing(unsigned int uid, AudioFrame& audioFrame) ;
	
private:
    void *user_data;
	write_data_callback_t write_data_callback;
};
