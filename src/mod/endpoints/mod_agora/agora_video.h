#pragma once
#include <switch.h>
#include <switch_types.h>
/* AMF */
//#include "io.h"
//#include "types.h"

#ifdef __cplusplus                                                                                                                                                                                        
extern "C" {                                                                                                                                                                                              
#endif                                                                                                                                                                                                    
#include <libswscale/swscale.h>                                                                                                                                                                           
#include <libavformat/avformat.h>                                                                                                                                                                         
#include <libavcodec/avcodec.h>                                                                                                                                                                           
#include <libavutil/opt.h>                                                                                                                                                                                
#include <libavutil/time.h>                                                                                                                                                                               
#include <libavutil/avutil.h>                                                                                                                                                                             
#include <libavutil/imgutils.h>                                                                                                                                                                           
#include <libavutil/hwcontext.h>                                                                                                                                                                          
#include <libavutil/error.h>                                                                                                                                                                              
#ifdef __cplusplus                                                                                                                                                                                        
}                                                                                                                                                                                                         
#endif

class avc_parse_helper{
public:

	switch_bool_t   send;
	uint32_t        last_recv_ts;
	uint8_t         last_mark;
	uint16_t        last_seq;

	//need to be allocate and free
	switch_buffer_t		*nal_buf; //nal buf
	switch_buffer_t 	*fua_buf; //fu_a buf
	switch_buffer_t     *sps;	  //sps
	switch_buffer_t     *pps;	  //pps

	switch_bool_t 		get_sps_pps;
	switch_bool_t  	    sps_pps_changed;
};
switch_status_t agora_avc_parse(avc_parse_helper *helper, switch_frame_t *frame);
void avc_parser_helper_init(avc_parse_helper *helper);
void avc_parser_helper_destroy(avc_parse_helper *helper);



class video_trans_ctx{
private:
	AVCodecContext *code_ctx;
	AVCodec *video_codec;
	AVFrame *pFrame;
	int initilized;

public:
	video_trans_ctx();
	~video_trans_ctx();
	//nee to free yuv_buf
	void h264_to_yuv(u_int8_t *h264_buf, int data_len, u_int8_t **yuv_buf, int &yuv_len, int &width, int &height);
};