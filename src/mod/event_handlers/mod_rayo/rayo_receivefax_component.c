/*
 * mod_rayo for FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2013, Grasshopper
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is mod_rayo for FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * The Initial Developer of the Original Code is Grasshopper
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 * Chris Rienzo <chris.rienzo@grasshopper.com>
 *
 * rayo_receivefax_component.c -- Rayo receivefax component implementation
 *
 */
#include "rayo_components.h"
#include "rayo_elements.h"

/**
 * settings
 */
static struct {
	const char *file_prefix;
} globals;

struct receivefax_component {
	/** component base class */
	struct rayo_component base;
	/** true if HTTP PUT needs to be done after fax is received */
	int http_put_after_receive;
	/** fax stored on local filesystem */
	const char *local_filename;
	/** fax final target (may be same as local filename) */
	const char *filename;
	/** Flag to stop fax */
	int stop;
};

#define RECEIVEFAX_FINISH "finish", RAYO_FAX_COMPLETE_NS

#define RECEIVEFAX_COMPONENT(x) ((struct receivefax_component *)x)

/**
 * Start execution of call receivefax component
 * @param call the call to receive fax from
 * @param msg the original request
 * @param session_data the call's session
 */
static iks *start_receivefax_component(struct rayo_actor *call, struct rayo_message *msg, void *session_data)
{
	iks *iq = msg->payload;
	switch_core_session_t *session = (switch_core_session_t *)session_data;
	struct receivefax_component *receivefax_component = NULL;
	iks *receivefax = iks_find(iq, "receivefax");
	iks *response = NULL;
	switch_event_t *execute_event = NULL;
	switch_channel_t *channel = switch_core_session_get_channel(session);
	switch_memory_pool_t *pool;
	int file_no;

	/* validate attributes */
	if (!VALIDATE_RAYO_RECEIVEFAX(receivefax)) {
		return iks_new_error(iq, STANZA_ERROR_BAD_REQUEST);
	}

	/* fax is only allowed if the call is not currently joined */
	if (rayo_call_is_joined(RAYO_CALL(call))) {
		return iks_new_error_detailed(iq, STANZA_ERROR_UNEXPECTED_REQUEST, "can't receive fax on a joined call");
	}

	if (!rayo_call_set_faxing(RAYO_CALL(call), 1)) {
		return iks_new_error_detailed(iq, STANZA_ERROR_UNEXPECTED_REQUEST, "fax already in progress");
	}

	/* create receivefax component */
	switch_core_new_memory_pool(&pool);
	receivefax_component = switch_core_alloc(pool, sizeof(*receivefax_component));
	rayo_component_init((struct rayo_component *)receivefax_component, pool, RAT_CALL_COMPONENT, "receivefax", NULL, call, iks_find_attrib(iq, "from"));
	file_no = rayo_actor_seq_next(call);
	receivefax_component->filename = switch_core_sprintf(pool, "%s%s%s-%d",
		globals.file_prefix, SWITCH_PATH_SEPARATOR, switch_core_session_get_uuid(session), file_no);
	if (!strncmp(receivefax_component->filename, "http://", 7) || strncmp(receivefax_component->filename, "https://", 8)) {
		/* This is an HTTP URL, need to PUT after fax is received */
		receivefax_component->local_filename = switch_core_sprintf(pool, "%s%s%s-%d",
			SWITCH_GLOBAL_dirs.temp_dir, SWITCH_PATH_SEPARATOR, switch_core_session_get_uuid(session), file_no);
		receivefax_component->http_put_after_receive = 1;
	} else {
		/* assume file.. */
		receivefax_component->local_filename = receivefax_component->filename;
	}

	/* add channel variable so that fax component can be located from fax events */
	switch_channel_set_variable(channel, "rayo_fax_jid", RAYO_JID(receivefax_component));

	/* clear fax result variables */
	switch_channel_set_variable(channel, "fax_success", NULL);
	switch_channel_set_variable(channel, "fax_result_code", NULL);
	switch_channel_set_variable(channel, "fax_result_text", NULL);
	switch_channel_set_variable(channel, "fax_document_transferred_pages", NULL);
	switch_channel_set_variable(channel, "fax_document_total_pages", NULL);
	switch_channel_set_variable(channel, "fax_image_resolution", NULL);
	switch_channel_set_variable(channel, "fax_image_size", NULL);
	switch_channel_set_variable(channel, "fax_bad_rows", NULL);
	switch_channel_set_variable(channel, "fax_transfer_rate", NULL);
	switch_channel_set_variable(channel, "fax_ecm_used", NULL);
	switch_channel_set_variable(channel, "fax_local_station_id", NULL);
	switch_channel_set_variable(channel, "fax_remote_station_id", NULL);

	/* clear fax interrupt variable */
	switch_channel_set_variable(switch_core_session_get_channel(session), "rayo_read_frame_interrupt", NULL);

	/* execute rxfax APP */
	if (switch_event_create(&execute_event, SWITCH_EVENT_COMMAND) == SWITCH_STATUS_SUCCESS) {
		switch_event_add_header_string(execute_event, SWITCH_STACK_BOTTOM, "call-command", "execute");
		switch_event_add_header_string(execute_event, SWITCH_STACK_BOTTOM, "execute-app-name", "rxfax");
		switch_event_add_header_string(execute_event, SWITCH_STACK_BOTTOM, "execute-app-arg", receivefax_component->local_filename);
		switch_event_add_header_string(execute_event, SWITCH_STACK_BOTTOM, "event-lock", "true");
		if (!switch_channel_test_flag(channel, CF_PROXY_MODE)) {
			switch_channel_set_flag(channel, CF_BLOCK_BROADCAST_UNTIL_MEDIA);
		}

		if (switch_core_session_queue_private_event(session, &execute_event, SWITCH_FALSE) != SWITCH_STATUS_SUCCESS) {
			response = iks_new_error_detailed(iq, STANZA_ERROR_INTERNAL_SERVER_ERROR, "failed to rxfax (queue event failed)");
			if (execute_event) {
				switch_event_destroy(&execute_event);
			}
			RAYO_UNLOCK(receivefax_component);
		} else {
			/* component starting... */
			rayo_component_send_start(RAYO_COMPONENT(receivefax_component), iq);
		}
	} else {
		response = iks_new_error_detailed(iq, STANZA_ERROR_INTERNAL_SERVER_ERROR, "failed to create rxfax event");
		RAYO_UNLOCK(receivefax_component);
	}

	return response;
}

/**
 * Stop execution of receivefax component
 */
static iks *stop_receivefax_component(struct rayo_actor *component, struct rayo_message *msg, void *data)
{
	iks *iq = msg->payload;
	switch_core_session_t *session = switch_core_session_locate(RAYO_COMPONENT(component)->parent->id);
	if (session) {
		/* fail on read frame until component is destroyed */
		switch_channel_set_variable(switch_core_session_get_channel(session), "rayo_read_frame_interrupt", RAYO_JID(component));
		switch_core_session_rwunlock(session);
	}
	RECEIVEFAX_COMPONENT(component)->stop = 1;
	return iks_new_iq_result(iq);
}

/**
 * Add fax metadata to result
 * @param event source of metadata
 * @param name of metadata
 * @param result to add metadata to
 */
static void insert_fax_metadata(switch_event_t *event, const char *name, iks *result)
{
	char actual_name[256];
	const char *value;
	snprintf(actual_name, sizeof(actual_name), "variable_%s", name);
	actual_name[sizeof(actual_name) - 1] = '\0';
	value = switch_event_get_header(event, actual_name);
	if (!zstr(value)) {
		iks *metadata = iks_insert(result, "metadata");
		iks_insert_attrib(metadata, "xmlns", RAYO_FAX_COMPLETE_NS);
		iks_insert_attrib(metadata, "name", name);
		iks_insert_attrib(metadata, "value", value);
	}
}

/**
 * Handle rxfax execute event
 * @param event received from FreeSWITCH core.  It will be destroyed by the core after this function returns.
 */
static void on_execute_event(switch_event_t *event)
{
	const char *application = switch_event_get_header(event, "Application");
	if (!zstr(application) && !strcmp(application, "rxfax")) {
		/* TODO */
	}
}

/**
 * Handle rxfax completion event from FreeSWITCH core
 * @param event received from FreeSWITCH core.  It will be destroyed by the core after this function returns.
 */
static void on_execute_complete_event(switch_event_t *event)
{
	const char *application = switch_event_get_header(event, "Application");
	if (!zstr(application) && !strcmp(application, "rxfax")) {
		const char *uuid = switch_event_get_header(event, "Unique-ID");
		const char *fax_jid = switch_event_get_header(event, "variable_rayo_fax_jid");
		struct rayo_actor *component;
		if (!zstr(fax_jid) && (component = RAYO_LOCATE(fax_jid))) {
			const char *url = RECEIVEFAX_COMPONENT(component)->filename;
			iks *result;
			iks *complete;
			iks *fax;
			switch_core_session_t *session;
			switch_log_printf(SWITCH_CHANNEL_UUID_LOG(uuid), SWITCH_LOG_DEBUG, "Got result for %s\n", fax_jid);

			/* clean up channel */
			session = switch_core_session_locate(uuid);
			if (session) {
				switch_channel_set_variable(switch_core_session_get_channel(session), "rayo_read_frame_interrupt", NULL);
				switch_core_session_rwunlock(session);
			}

			/* flag faxing as done */
			rayo_call_set_faxing(RAYO_CALL(RAYO_COMPONENT(component)->parent), 0);

			/* successful fax? */
			if (switch_true(switch_event_get_header(event, "variable_fax_success"))) {
				result = rayo_component_create_complete_event(RAYO_COMPONENT(component), RECEIVEFAX_FINISH);
			} else if (RECEIVEFAX_COMPONENT(component)->stop) {
				result = rayo_component_create_complete_event(RAYO_COMPONENT(component), COMPONENT_COMPLETE_STOP);
			} else {
				result = rayo_component_create_complete_event(RAYO_COMPONENT(component), COMPONENT_COMPLETE_ERROR);
			}
			complete = iks_find(result, "complete");

			/* add fax document information */
			{
				const char *pages = switch_event_get_header(event, "variable_fax_document_transferred_pages");
				if (!zstr(pages) && switch_is_number(pages) && atoi(pages) > 0) {
					const char *resolution = switch_event_get_header(event, "variable_fax_file_image_resolution");
					const char *size = switch_event_get_header(event, "variable_fax_image_size");

					fax = iks_insert(complete, "fax");
					iks_insert_attrib(fax, "xmlns", RAYO_FAX_COMPLETE_NS);

					if (strlen(url) > strlen(SWITCH_PATH_SEPARATOR) && !strncmp(url, SWITCH_PATH_SEPARATOR, strlen(SWITCH_PATH_SEPARATOR))) {
						/* convert absolute path to file:// URI */
						iks_insert_attrib_printf(fax, "url", "file://%s", url);
					} else {
						/* is already a URI (hopefully) */
						iks_insert_attrib(fax, "url", url);
					}

					if (!zstr(resolution)) {
						iks_insert_attrib(fax, "resolution", resolution);
					}
					if (!zstr(size)) {
						iks_insert_attrib(fax, "size", size);
					}
					iks_insert_attrib(fax, "pages", pages);
				}

				/* TODO transfer HTTP document and delete local copy */
			}

			/* add metadata from event */
			insert_fax_metadata(event, "fax_success", complete);
			insert_fax_metadata(event, "fax_result_code", complete);
			insert_fax_metadata(event, "fax_result_text", complete);
			insert_fax_metadata(event, "fax_document_transferred_pages", complete);
			insert_fax_metadata(event, "fax_document_total_pages", complete);
			insert_fax_metadata(event, "fax_image_resolution", complete);
			insert_fax_metadata(event, "fax_image_size", complete);
			insert_fax_metadata(event, "fax_bad_rows", complete);
			insert_fax_metadata(event, "fax_transfer_rate", complete);
			insert_fax_metadata(event, "fax_ecm_used", complete);
			insert_fax_metadata(event, "fax_local_station_id", complete);
			insert_fax_metadata(event, "fax_remote_station_id", complete);

			rayo_component_send_complete_event(RAYO_COMPONENT(component), result);

			RAYO_UNLOCK(component);
		}
	}
}

/**
 * Process module XML configuration
 * @param pool memory pool to allocate from
 * @param config_file to use
 * @return SWITCH_STATUS_SUCCESS on successful configuration
 */
static switch_status_t do_config(switch_memory_pool_t *pool, const char *config_file)
{
	switch_xml_t cfg, xml;

	/* set defaults */
	globals.file_prefix = switch_core_sprintf(pool, "%s%s", SWITCH_GLOBAL_dirs.recordings_dir, SWITCH_PATH_SEPARATOR);

	if (!(xml = switch_xml_open_cfg(config_file, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "open of %s failed\n", config_file);
		return SWITCH_STATUS_TERM;
	}

	/* get params */
	{
		switch_xml_t settings = switch_xml_child(cfg, "receivefax");
		if (settings) {
			switch_xml_t param;
			for (param = switch_xml_child(settings, "param"); param; param = param->next) {
				const char *var = switch_xml_attr_soft(param, "name");
				const char *val = switch_xml_attr_soft(param, "value");
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "param: %s = %s\n", var, val);
				if (!strcasecmp(var, "file-prefix")) {
					if (!zstr(val)) {
						globals.file_prefix = switch_core_strdup(pool, val);
					}
				} else {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Unsupported param: %s\n", var);
				}
			}
		}
	}

	switch_xml_free(xml);

	return SWITCH_STATUS_SUCCESS;
}

/**
 * Initialize receivefax component
 * @param module_interface
 * @param pool memory pool to allocate from
 * @param config_file to use
 * @return SWITCH_STATUS_SUCCESS if successful
 */
switch_status_t rayo_receivefax_component_load(switch_loadable_module_interface_t **module_interface, switch_memory_pool_t *pool, const char *config_file)
{
	if (do_config(pool, config_file) != SWITCH_STATUS_SUCCESS) {
		return SWITCH_STATUS_TERM;
	}

	switch_event_bind("rayo_receivefax_component", SWITCH_EVENT_CHANNEL_EXECUTE_COMPLETE, NULL, on_execute_complete_event, NULL);
	switch_event_bind("rayo_receivefax_component", SWITCH_EVENT_CHANNEL_EXECUTE, NULL, on_execute_event, NULL);

	rayo_actor_command_handler_add(RAT_CALL, "", "set:"RAYO_FAX_NS":receivefax", start_receivefax_component);
	rayo_actor_command_handler_add(RAT_CALL_COMPONENT, "receivefax", "set:"RAYO_EXT_NS":stop", stop_receivefax_component);

	return SWITCH_STATUS_SUCCESS;
}

/**
 * Shutdown receivefax component
 * @return SWITCH_STATUS_SUCCESS if successful
 */
switch_status_t rayo_receivefax_component_shutdown(void)
{
	switch_event_unbind_callback(on_execute_event);
	switch_event_unbind_callback(on_execute_complete_event);

	return SWITCH_STATUS_SUCCESS;
}

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet
 */
