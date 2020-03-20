#pragma once
 
#include <stdio.h>
#ifdef _MSC_VER
typedef signed char     int8_t;
typedef unsigned char   uint8_t;
typedef short           int16_t;
typedef unsigned short  uint16_t;
typedef int             int32_t;
typedef unsigned        uint32_t;
#else
#include <stdint.h>
#endif //
 
#ifdef __cplusplus
extern "C" {
 
#endif
 
 
#define NAL_SPS     0x07 /* Sequence Parameter Set */
#define NAL_AUD     0x09 /* Access Unit Delimiter */
#define NAL_END_SEQ 0x0a /* End of Sequence */
 
 
#if defined(__i386__) || defined(__x86_64__)
#  define IS_NAL_SPS(buf)     (*(const uint32_t *)(buf) == 0x07010000U)
#  define IS_NAL_AUD(buf)     (*(const uint32_t *)(buf) == 0x09010000U)
#  define IS_NAL_END_SEQ(buf) (*(const uint32_t *)(buf) == 0x0a010000U)
#else
#  define IS_NAL_SPS(buf)     ((buf)[0] == 0 && (buf)[1] == 0 && (buf)[2] == 1 && (buf)[3] == NAL_SPS)
#  define IS_NAL_AUD(buf)     ((buf)[0] == 0 && (buf)[1] == 0 && (buf)[2] == 1 && (buf)[3] == NAL_AUD)
#  define IS_NAL_END_SEQ(buf) ((buf)[0] == 0 && (buf)[1] == 0 && (buf)[2] == 1 && (buf)[3] == NAL_END_SEQ)
#endif
 
 
    typedef struct mpeg_rational_s {
 
        int num;
        int den;
 
    } mpeg_rational_t;
 
    typedef struct video_size_s {
 
        uint16_t        width;
        uint16_t        height;
        mpeg_rational_t pixel_aspect;
 
    } video_size_t;
 
    typedef struct {
 
        uint16_t        width;
        uint16_t        height;
        mpeg_rational_t pixel_aspect;
        uint8_t   profile;
        uint8_t   level;
 
    } h264_sps_data_t;
 
    struct video_size_s;
 
 
    /*
     * input: start of NAL SPS ( 00 00 01 07 or 00 00 00 01 67 0r 67)
     */
    int h264_parse_sps(const uint8_t *buf, int len, h264_sps_data_t *sps);
 
#ifdef __cplusplus
}
 
#endif
 