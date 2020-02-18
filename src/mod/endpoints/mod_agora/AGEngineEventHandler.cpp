#include "AGEngineEventHandler.h"
#include <cstring>
#include <iostream>
#include <switch.h>
#include <switch_types.h>
#include <switch_core.h>

AGEngineEventHandler::AGEngineEventHandler()
{

}

AGEngineEventHandler::~AGEngineEventHandler()
{
}



void AGEngineEventHandler::onJoinChannelSuccess(const char* channel, uid_t uid, int elapsed)
{
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,"join channel %sd successfully\n", channel);

}

void AGEngineEventHandler::onRejoinChannelSuccess(const char* channel, uid_t uid, int elapsed)
{

}

void AGEngineEventHandler::onWarning(int warn, const char* msg)
{
    	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,"agora sdk warning occurs:%s\n", msg);

}

void AGEngineEventHandler::onError(int err, const char* msg)
{
    	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,"agora sdk error occurs:%s\n", msg);
}

void AGEngineEventHandler::onAudioQuality(uid_t uid, int quality, unsigned short delay, unsigned short lost)
{

} 

void AGEngineEventHandler::onLeaveChannel(const RtcStats& stat)
{

}

void AGEngineEventHandler::onRtcStats(const RtcStats& stat)
{

}

void AGEngineEventHandler::onUserJoined(uid_t uid, int elapsed)
{

}

void AGEngineEventHandler::onUserOffline(uid_t uid, USER_OFFLINE_REASON_TYPE reason)
{

}

void AGEngineEventHandler::onUserMuteAudio(uid_t uid, bool muted)
{

}

void AGEngineEventHandler::onUserMuteVideo(uid_t uid, bool muted)
{

}

void AGEngineEventHandler::onCameraReady()
{

}

void AGEngineEventHandler::onConnectionLost()
{
   
}

void AGEngineEventHandler::onConnectionInterrupted()
{
    
}

void AGEngineEventHandler::onUserEnableVideo(uid_t uid, bool enabled)
{
    
}

