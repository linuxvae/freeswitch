#pragma once
#include "AudioFrameObserver.h"

bool AudioFrameObserver::onRecordAudioFrame(AudioFrame& audioFrame) 
{
	//printf("%s: samples=%d, channel=%d, fs=%d\n", __FUNCTION__, audioFrame.samples, audioFrame.channels, audioFrame.samplesPerSec);
return true;
}

bool AudioFrameObserver::onPlaybackAudioFrame(AudioFrame& audioFrame) 
{
	//printf("%s: bytesPerSamples=%d, channel=%d, renderTime=%d, samples=%d,  samplePerSec=%d\n", __FUNCTION__, 
	//		audioFrame.bytesPerSample, audioFrame.channels, audioFrame.renderTimeMs, audioFrame.samples, audioFrame.samplesPerSec);
    //FILE *fd = fopen("record.pcm", "ab+");
    //fwrite(audioFrame.buffer, audioFrame.samples * audioFrame.channels *  audioFrame.bytesPerSample,1, fd);
    //fputs((char *)audioFrame.buffer, fd);
    //fclose(fd);


    //copy audio frame to session->buff 
	switch_assert(session);
    switch_buffer_write(session->readbuf, audioFrame.buffer, audioFrame.samples * audioFrame.bytesPerSample * audioFrame.channels);
	return true;
}

bool AudioFrameObserver::onMixedAudioFrame(AudioFrame& audioFrame)
{
	//printf("%s: samples=%d, channel=%d, fs=%d\n", __FUNCTION__, audioFrame.samples, audioFrame.channels, audioFrame.samplesPerSec);
	return true;
}

bool AudioFrameObserver::onPlaybackAudioFrameBeforeMixing(unsigned int uid, AudioFrame& audioFrame) 
{
//	printf("%s: uid=%u, samples=%d, channel=%d, fs=%d\n", __FUNCTION__, uid, audioFrame.samples, audioFrame.channels, audioFrame.samplesPerSec);
	return true;
}
