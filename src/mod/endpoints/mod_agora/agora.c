#include "agora.h"
#include <stdio.h>

#if !defined(min)
#define min(a, b) ((a) <= (b) ? (a) : (b))
#endif
#if !defined(max)
#define max(a, b) ((a) >= (b) ? (a) : (b))
#endif

#define F_PATH "/root/test.pcm"
#define OUT_PATH "/root/out.pcm"
static FILE *g_fp = NULL;
static FILE *g_out_fp = NULL;

static void *SWITCH_THREAD_FUNC read_data_thread(switch_thread_t *thread, void *obj)
{
	unsigned char rdata[172]="";
	switch_size_t rlen = 0;
	agora_session_t *session = (agora_session_t *)obj;
	while (session->state != RS_DESTROY) {
		rlen = fread(rdata, 172, 1, g_fp);
		if (rlen > 0) {
			switch_mutex_lock(session->readbuf_mutex);
			switch_buffer_write(session->readbuf, rdata, rlen);
			switch_mutex_unlock(session->readbuf_mutex);
		}
		switch_sleep(20000);
	}
	return NULL;
}
int agora_init_module(const char *appid) { return 0; }
agora_session_t *agora_init_session(char *channelID)
{
	switch_thread_t *thread = NULL;
	switch_threadattr_t *thd_attr = NULL;
	switch_memory_pool_t *pool = NULL;
	agora_session_t *session = NULL;
	switch_core_new_memory_pool(&pool);
	session = switch_core_alloc(pool, sizeof(agora_session_t));
	switch_mutex_init(&session->readbuf_mutex, SWITCH_MUTEX_NESTED, pool);
	switch_buffer_create_dynamic(&session->readbuf, 512, 512, 1024000);
	session->state = INIT;
	session->pool = pool;
	// todo
	if (!g_fp) {
		g_fp = fopen(F_PATH, "r");
	}
	if (!g_out_fp) {
		g_out_fp = fopen(OUT_PATH, "wb+");
	}
	switch_threadattr_create(&thd_attr, session->pool);
	// switch_threadattr_detach_set(thd_attr, 1);
	switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
	if (switch_thread_create(&thread, thd_attr, read_data_thread, session, session->pool) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Could not load  read frame switch_thread_create\n");
	}
	// end
	session->thread = thread;
	return session;
}

int agora_read_data_from_session(agora_session_t *session, switch_frame_t *read_frame)
{

	switch_size_t len = 172;
	switch_assert(session);
	len = min(len, read_frame->buflen);
	switch_mutex_lock(session->readbuf_mutex);
	read_frame->datalen = switch_buffer_read(session->readbuf, read_frame->data, len);
	switch_mutex_unlock(session->readbuf_mutex);
	return read_frame->datalen;
	//
}
int agora_write_data_to_session(agora_session_t *session, switch_frame_t *read_frame)
{
	switch_assert(session);
	fwrite(read_frame->data, read_frame->datalen, 1, g_out_fp);
	return 0;
}
//状态消息上报
// todo
int agora_destory_session(agora_session_t *session)
{
	switch_status_t status;
	if (session) {
		//释放

		session->state = RS_DESTROY;
		switch_thread_join(&status, session->thread);
	}
	if (g_fp) {
		fclose(g_fp);
		g_fp = NULL;
	}
	if (g_out_fp) {
		fclose(g_out_fp);
		g_out_fp = NULL;
	}
	switch_buffer_destroy(&session->readbuf);
	switch_core_destroy_memory_pool(&session->pool);
	return 0;
}

int agora_release_module() { return 0; }
