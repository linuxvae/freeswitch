#include <switch.h>
#include <switch_types.h>
#include "agora_video.h"

void avc_parser_helper_init(avc_parse_helper *helper)
{
	memset(helper, 0, sizeof(avc_parse_helper));
	helper->send = SWITCH_FALSE;
	helper->get_sps_pps =  SWITCH_FALSE;

	switch_buffer_create_dynamic(&helper->nal_buf, 10240, 10240, 0);
	switch_buffer_create_dynamic(&helper->fua_buf,  10240, 10240, 0);
	switch_buffer_create_dynamic(&helper->sps, 10240, 10240, 0);
	switch_buffer_create_dynamic(&helper->pps, 10240, 10240, 0);

}

void avc_parser_helper_destroy(avc_parse_helper *helper)
{
	if (helper->nal_buf) 
		switch_buffer_destroy(&helper->nal_buf);
	if (helper->fua_buf)  
		switch_buffer_destroy(&helper->fua_buf);
	if (helper->sps) 
		switch_buffer_destroy(&helper->sps);
	if (helper->pps) 
		switch_buffer_destroy(&helper->pps);
}

//解析hh264中的聚合包，和切片包，将相应的数据存放在helper中
switch_status_t agora_avc_parse(avc_parse_helper *helper, switch_frame_t *frame)
{
	uint8_t* packet = (uint8_t*)frame->packet;
	// uint32_t len = frame->packetlen;
	switch_rtp_hdr_t *raw_rtp = (switch_rtp_hdr_t *)packet;
	switch_byte_t *payload = (switch_byte_t *)frame->data;
	int datalen = frame->datalen;
	int nalType = payload[0] & 0x1f;
	uint32_t size = 0;
	uint16_t rtp_seq = 0;
	uint32_t rtp_ts = 0;
	static const char start_code[]={0x00, 0x00, 0x00, 0x01};//NAL start code
	helper->send = SWITCH_FALSE;

	// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE,
	// 	"read: %-4u: %02x %02x ts:%u seq:%u %s\n",
	// 	len, payload[0], payload[1], rtp_ts, rtp_seq, raw_rtp->m ? " mark" : "");

	if (switch_test_flag(frame, SFF_RAW_RTP) && !switch_test_flag(frame, SFF_RAW_RTP_PARSE_FRAME)) {
		rtp_seq = ntohs(raw_rtp->seq);
		rtp_ts = ntohl(raw_rtp->ts);

		if (helper->last_seq && helper->last_seq + 1 != rtp_seq) {

			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "possible video rtp packet loss? seq: %u - %u - 1 = %d ts: %u - %u = %d\n",
				ntohs(raw_rtp->seq), helper->last_seq, (int)(rtp_seq - helper->last_seq - 1),
				ntohl(raw_rtp->ts), helper->last_recv_ts, (int)(rtp_ts - helper->last_recv_ts));

			//丢包后为什么要马上重置sps?
			if (nalType != 7) {
				// if (helper->sps) {
				// 	amf0_data_free(helper->sps);
				// 	helper->sps = NULL;
				// }
				helper->last_recv_ts = rtp_ts;
				helper->last_mark = raw_rtp->m;
				helper->last_seq = rtp_seq;

				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "waiting for sps and pps\n");
				switch_buffer_zero(helper->nal_buf);
				switch_buffer_zero(helper->fua_buf);
				helper->send = SWITCH_FALSE;
				return SWITCH_STATUS_SUCCESS;
			}
		}
	}

	//last_recv_ts与当前帧不等为何要清空fua_buf?
	if (helper->last_recv_ts != frame->timestamp) {
		switch_buffer_zero(helper->nal_buf);
		switch_buffer_zero(helper->fua_buf);
	}

	helper->last_recv_ts = frame->timestamp;
	helper->last_mark = frame->m;
	helper->last_seq = rtp_seq;

	switch (nalType) {
	case 7: //sps
		//TODO parse weight 和 height，并告知外部，sps已经发生了改变，需要重新初始化codec_ctx
		switch_buffer_write(helper->nal_buf, start_code, 4);
		size = htonl(datalen);
		switch_buffer_write(helper->nal_buf, payload, datalen);
		break;
	case 8: //pps
		switch_buffer_write(helper->nal_buf, start_code, 4);
		size = htonl(datalen);
		switch_buffer_write(helper->nal_buf, payload, datalen);
		break;
	case 1: //Non IDR
		switch_buffer_write(helper->nal_buf, start_code, 4);
		size = htonl(datalen);
		switch_buffer_write(helper->nal_buf, payload, datalen);
		break;
	case 5: //IDR
		switch_buffer_write(helper->nal_buf, start_code, 4);
		size = htonl(datalen);
		switch_buffer_write(helper->nal_buf, payload, datalen);
		break;
	case 28: //FU-A
		{
			uint8_t *q = payload;
			uint8_t h264_start_bit = q[1] & 0x80;
			uint8_t h264_end_bit   = q[1] & 0x40;
			uint8_t h264_type      = q[1] & 0x1F;
			uint8_t h264_nri       = (q[0] & 0x60) >> 5;
			uint8_t h264_key       = (h264_nri << 5) | h264_type;

			if (h264_start_bit) {
				/* write NAL unit code */
				switch_buffer_write(helper->fua_buf, start_code, 4);
				switch_buffer_write(helper->fua_buf, &h264_key, sizeof(h264_key));
			}

			//过滤FU-A的两个BYTE的头
			switch_buffer_write(helper->fua_buf, q + 2, datalen - 2);

			//最后一个FU-A, 要将FU-A写入到buf中
			if (h264_end_bit) {
				const void * nal_data;
				uint32_t used = switch_buffer_inuse(helper->fua_buf);
				switch_buffer_peek_zerocopy(helper->fua_buf, &nal_data);	
				switch_buffer_write(helper->nal_buf, nal_data, used);
				switch_buffer_zero(helper->fua_buf);
			}
		}
		break;
	case 24:
		 {// for aggregated SPS and PPSs
			uint8_t *q = payload + 1;
			uint16_t nalu_size = 0;
			int nt = 0;
			int nidx = 0;
			while (nidx < datalen - 1) {
				/* get NALU size */
				nalu_size = (q[nidx] << 8) | (q[nidx + 1]);

				nidx += 2;

				if (nalu_size == 0) {
					nidx++;
					continue;
				}

				/* write NALU data */
				nt = q[nidx] & 0x1f;
				switch (nt) {
				case 1: //Non IDR
					switch_buffer_write(helper->nal_buf, start_code, 4);
					switch_buffer_write(helper->nal_buf, q + nidx, nalu_size);
					break;
				case 5:	// IDR
					switch_buffer_write(helper->nal_buf, start_code, 4);
					switch_buffer_write(helper->nal_buf, q + nidx, nalu_size);
					break;
				case 7: //sps
					switch_buffer_write(helper->nal_buf, start_code, 4);
					switch_buffer_write(helper->nal_buf, q + nidx, nalu_size);
					break;
				case 8: //pps
					switch_buffer_write(helper->nal_buf, start_code, 4);
					switch_buffer_write(helper->nal_buf, q + nidx, nalu_size);
					break;
				default:
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unsupported NAL %d in STAP-A\n", nt);
					break;
				}
				nidx += nalu_size;
			}
		}
		break;

	case 6:
		break;

	default:
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Unsupported NAL %d\n", nalType);
		break;
	}

	if (frame->m && switch_buffer_inuse(helper->nal_buf) > 0) {
		helper->send = SWITCH_TRUE;
	}

	return SWITCH_STATUS_SUCCESS;
}




video_trans_ctx::video_trans_ctx(){
	av_register_all();
	initilized = 1;
	video_codec = avcodec_find_decoder(CODEC_ID_H264);  
	code_ctx = avcodec_alloc_context3(video_codec);  

	if (!video_codec){  
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,"find video codec H264 failed\n");
		return ;  
	} 


	//初始化参数，下面的参数应该由具体的业务决定  
	code_ctx->time_base.num = 1;  
	code_ctx->frame_number = 1; //每包一个视频帧  
	code_ctx->codec_type = AVMEDIA_TYPE_VIDEO;  
	code_ctx->bit_rate = 0;  
	code_ctx->time_base.den = 30;//帧率  
	code_ctx->width = 1280;//视频宽  
	code_ctx->height = 720;//视频高  

	if(avcodec_open2(code_ctx, video_codec, NULL) >= 0)  
		pFrame = av_frame_alloc();// Allocate video frame  
	else{
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,"open codec h264 failed\n");
		return;  
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "initilized video_trans_ctx successfully\n");

}


video_trans_ctx::~video_trans_ctx(){

}

//nee to free yuv_buf
void video_trans_ctx::h264_to_yuv(u_int8_t *h264_buf, int data_len, u_int8_t **yuv_buf, int &yuv_len, int &width, int &height){
	AVPacket packet = {0};  
	int frameFinished = 2048;//随便填的数字  
	yuv_len = 0;

	u_int8_t* h264_buf_complete = new u_int8_t[4 + data_len];
	memcpy(h264_buf_complete, h264_buf, data_len);

	packet.data = h264_buf_complete;//这里填入一个指向完整H264数据帧的指针  
	packet.size = data_len;		//这个填入H264数据帧的大小  

	avcodec_decode_video2(code_ctx, pFrame, &frameFinished, &packet);  
	//delete  h264_buf_complete;

	if(frameFinished){//成功解码 
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "decode successfully %d \n");

		int picSize = code_ctx->height * code_ctx->width;  
		int newSize = yuv_len = picSize * 1.5;  

		//申请内存  
		unsigned char *buf = new unsigned char[newSize];  

		height =code_ctx->height;  
		width = code_ctx->width;  	

		//写入数据  
		int a=0,i;   
		for (i=0; i<height; i++){   
			memcpy(buf+a, pFrame->data[0] + i * pFrame->linesize[0], width);   
			a += width;   
		}   
		for (i=0; i<height/2; i++) {   
			memcpy(buf+a, pFrame->data[1] + i * pFrame->linesize[1], width/2);   
			a += width/2;   
		}   
		for (i=0; i<height/2; i++){   
			memcpy(buf+a, pFrame->data[2] + i * pFrame->linesize[2], width/2);   
			a += width/2;
		}
		*yuv_buf =  buf; 
}