#pragma once
#include <iostream>
#include <memory>
#include <vector>
#include <string>
#include <thread>
#include <sstream>
#include <unistd.h>
#include <pthread.h>
#include <vector>
#include <map>
#include <algorithm>
#include "agora.h"

#include "IAgoraRtmService.h"

using namespace std;

enum RTM_LOGIN_STATUS{LOGOUT = 0, LOGINING = 1, LOGINED =2};

class AgoraRtm;

class RtmEventObserver{
public:
    RtmEventObserver(AgoraRtm *ptr):rtm_ptr(ptr){}

    void OnLoginStatusChanged(RTM_LOGIN_STATUS status);

    AgoraRtm *rtm_ptr;
};


class RtmEventHandler: public agora::rtm::IRtmServiceEventHandler {
  public:
    RtmEventHandler();
    RtmEventHandler( RtmEventObserver *observer);
    ~RtmEventHandler();

    virtual void onLoginSuccess() override;

    virtual void onLoginFailure(agora::rtm::LOGIN_ERR_CODE errorCode) override ;

    virtual void onLogout(agora::rtm::LOGOUT_ERR_CODE errorCode) override;

    virtual void onConnectionStateChanged(agora::rtm::CONNECTION_STATE state,
                        agora::rtm::CONNECTION_CHANGE_REASON reason) override ;

    virtual void onSendMessageResult(long long messageId,
                        agora::rtm::PEER_MESSAGE_ERR_CODE state) override;

    virtual void onMessageReceivedFromPeer(const char *peerId,
                        const agora::rtm::IMessage *message) override;


    shared_ptr<RtmEventObserver> event_observer;

};

class ChannelEventHandler: public agora::rtm::IChannelEventHandler {
  public:
    ChannelEventHandler();
    ChannelEventHandler(string channel,recv_callback_t cb, void *cb_arg) ;
    ~ChannelEventHandler() ;

    virtual void onJoinSuccess() override ;

    virtual void onJoinFailure(agora::rtm::JOIN_CHANNEL_ERR errorCode) override;

    virtual void onLeave(agora::rtm::LEAVE_CHANNEL_ERR errorCode) override;

    virtual void onMessageReceived(const char* userId,
                        const agora::rtm::IMessage *msg) override;

    virtual void onMemberJoined(agora::rtm::IChannelMember *member) override ;

    virtual void onMemberLeft(agora::rtm::IChannelMember *member) override;

    virtual void onGetMembers(agora::rtm::IChannelMember **members,
                    int userCount,
                    agora::rtm::GET_MEMBERS_ERR errorCode) override ;

    virtual void onSendMessageResult(long long messageId,
                    agora::rtm::CHANNEL_MESSAGE_ERR_CODE state) override;
    

    recv_callback_t recv_msg_cb;
    void *recv_msg_cb_arg;

    private:
        string channel_;
};

class AgoraRtm {
  public:
    AgoraRtm();
    AgoraRtm(const char *token);
    ~AgoraRtm();

  public:
    bool login(const char *token, const char* user_id);

    void logout();

    bool joinChannel(const std::string& channel, recv_callback_t cb, void *data);

    void sendMessageToPeer(std::string peerID, std::string msg);

    void sendMessageToChannel(string &msg);

    void setLoginStatus(RTM_LOGIN_STATUS status);

    RTM_LOGIN_STATUS getLoginStatus();

    //FIXME need to set it as atomic
    RTM_LOGIN_STATUS login_status = LOGOUT;
  private:
      std::unique_ptr<agora::rtm::IRtmServiceEventHandler> eventHandler_;
      std::unique_ptr<ChannelEventHandler> channelEvent_;
      agora::rtm::IChannel * channelHandler = NULL;
      std::shared_ptr<agora::rtm::IRtmService> rtmService_;
      
};




























