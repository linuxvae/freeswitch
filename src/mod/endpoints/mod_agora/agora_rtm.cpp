#include"agora_rtm.h"


void RtmEventObserver::OnLoginStatusChanged(RTM_LOGIN_STATUS status){
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "on login state changed: state = %d, reason= %d\n",
                    rtm_ptr->getLoginStatus(), status);
    rtm_ptr->setLoginStatus(status);
}


RtmEventHandler::RtmEventHandler(){}
RtmEventHandler::RtmEventHandler( RtmEventObserver *observer){
      event_observer.reset(observer);
}
RtmEventHandler::~RtmEventHandler() {}

void RtmEventHandler::onLoginSuccess()  {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,"Login Success\n");
    event_observer->OnLoginStatusChanged(LOGINED);
}

void RtmEventHandler::onLoginFailure(agora::rtm::LOGIN_ERR_CODE errorCode)  {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,"on login failure: errorCode = %d\n", errorCode);
    event_observer->OnLoginStatusChanged(LOGOUT);
}

void RtmEventHandler::onLogout(agora::rtm::LOGOUT_ERR_CODE errorCode)  {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,"on login out\n");
    event_observer->OnLoginStatusChanged(LOGOUT);

}

void RtmEventHandler::onConnectionStateChanged(agora::rtm::CONNECTION_STATE state,
                    agora::rtm::CONNECTION_CHANGE_REASON reason)  {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "on connection state changed: state = %d, reason= %d\n",
                     state, reason);
}

void RtmEventHandler::onSendMessageResult(long long messageId,
                    agora::rtm::PEER_MESSAGE_ERR_CODE state)  {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "on send message messageId:%d state: %d\n", 
                    messageId, state);
}

void RtmEventHandler::onMessageReceivedFromPeer(const char *peerId,
                    const agora::rtm::IMessage *message)  {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "recv user:%s msg:%s\n", 
                    peerId, message);
}

recv_callback_t recv_msg_from_peer_cb = NULL;
void *recv_msg_from_peer_cb_arg = NULL;





ChannelEventHandler::ChannelEventHandler(string channel, recv_callback_t cb, void *cb_arg) {
    channel_ = channel; 
    recv_msg_cb = cb;
    recv_msg_cb_arg = cb_arg;
}
ChannelEventHandler::~ChannelEventHandler() {}

void ChannelEventHandler::onJoinSuccess()  {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,"on join channel success\n");
}

void ChannelEventHandler::onJoinFailure(agora::rtm::JOIN_CHANNEL_ERR errorCode) {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,"on join channel failure: errorCode = %d\n", errorCode);
}

void ChannelEventHandler::onLeave(agora::rtm::LEAVE_CHANNEL_ERR errorCode)  {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,"on leave channel: errorCode = %d\n", errorCode);
}

void ChannelEventHandler::onMessageReceived(const char* userId,
                    const agora::rtm::IMessage *msg)  {
    recv_msg_cb((void *)msg->getText(), recv_msg_cb_arg);
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, " receive message from channel: %s, user:%s message:%s\n" ,
                    channel_.c_str(), userId ,msg->getText());
}

void ChannelEventHandler::onMemberJoined(agora::rtm::IChannelMember *member)  {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, " member: %s, joined channel:%s\n" ,
                    member->getUserId(), member->getChannelId());
}

void ChannelEventHandler::onMemberLeft(agora::rtm::IChannelMember *member)  {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, " member: %s, lefted channel:%s\n" ,
                    member->getUserId(), member->getChannelId());
}

void ChannelEventHandler::onGetMembers(agora::rtm::IChannelMember **members,
                int userCount,
                agora::rtm::GET_MEMBERS_ERR errorCode)  {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, " list all members for channel:%s,"\
                    "total members num:%s\n" ,channel_.c_str(), userCount);
}

void ChannelEventHandler::onSendMessageResult(long long messageId,
                agora::rtm::CHANNEL_MESSAGE_ERR_CODE state)  {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, " send messageId:%lld,  state:%d\n" ,
                    messageId, state);
}



AgoraRtm::AgoraRtm(){}
AgoraRtm::AgoraRtm(const char *token){
    RtmEventObserver *event_observer = new RtmEventObserver(this);
    eventHandler_.reset(new RtmEventHandler(event_observer));
    agora::rtm::IRtmService* p_rs = agora::rtm::createRtmService();
    rtmService_.reset(p_rs, [](agora::rtm::IRtmService* p) {
        if(!p){
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "IRtmService* p is NULL\n");
        }
        else
            p->release();                                                           
    });                                                                         

    if (!rtmService_) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "rtm service created failure\n");
    }

    if (rtmService_->initialize(token, eventHandler_.get())) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "rtm service initialize failure! appid invalid?\n");
    }
}
AgoraRtm::~AgoraRtm() {
   // rtmService_->release();
}

bool AgoraRtm::login(const char *token, const char* user_id) {
    if(this->login_status == LOGINED){
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,  "login successfullt!\n");
        return;
    }

    this->login_status = LOGINING;
    if (rtmService_->login(token, user_id)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,  "login failed!\n");
        return false;
    }
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,  "login successfully!\n");
    return true;
}

void AgoraRtm::logout() {
    if(this->login_status != LOGOUT){
          rtmService_->logout();
    }
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,  "log out!\n");
}

bool AgoraRtm::joinChannel(const std::string& channel, recv_callback_t cb, void *data){
    if(this->login_status == LOGOUT){
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "not login yet\n");
        return false;
    }

    if(this->login_status == LOGINING)
    for(int i = 0; i< 10; ++i){
        if(this->login_status != LOGINING)
            break;
        //keep wait for 100ms for 10 times;
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "rtm: keep wait for login status change\n");
        usleep(100000);
    }

    if(this->login_status != LOGINED){
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "not login yet\n");
        return false;
    }

    channelEvent_.reset(new ChannelEventHandler(channel, cb, data));  
    channelHandler =
        rtmService_->createChannel(channel.c_str(), channelEvent_.get());
    if (!channelHandler) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "create channel failed!\n");
        return false;
    }
    channelHandler->join();
    return true;
}

void AgoraRtm::sendMessageToPeer(std::string peerID, std::string msg) {
    agora::rtm::IMessage* rtmMessage = rtmService_->createMessage();
    rtmMessage->setText(msg.c_str());
    int ret = rtmService_->sendMessageToPeer(peerID.c_str(),
                                    rtmMessage);
    rtmMessage->release();
    if (ret) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "send message to peer failed! return code: \n");
    }
}

void AgoraRtm::sendMessageToChannel(string &msg) {
    agora::rtm::IMessage* rtmMessage = rtmService_->createMessage();
    rtmMessage->setText(msg.c_str());
    channelHandler->sendMessage(rtmMessage);
    rtmMessage->release();
}

void AgoraRtm::setLoginStatus(RTM_LOGIN_STATUS status){
    this->login_status = status;
}

RTM_LOGIN_STATUS AgoraRtm::getLoginStatus(){
        return this->login_status;
}
