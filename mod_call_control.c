/*
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2014, Anthony Minessale II <anthm@freeswitch.org>
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
 * The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * The Initial Developer of the Original Code is
 * Anthony Minessale II <anthm@freeswitch.org>
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Stefan Yohansson <sy.fen0@gmail.com>
 * Anthony Minessale II <anthm@freeswitch.org>
 * Neal Horman <neal at wanlink dot com>
 *
 *
 * mod_call_control.c -- Bidirectional communication with external applications without socket through internal REST API and external webhook
 *
 */
#include <switch.h>
#include <switch_curl.h>
#include "ks.h"

#define MAX_FAIL_COUNT 10

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_call_control_shutdown);
SWITCH_MODULE_RUNTIME_FUNCTION(mod_call_control_runtime);
SWITCH_MODULE_LOAD_FUNCTION(mod_call_control_load);

SWITCH_MODULE_DEFINITION(mod_call_control, mod_call_control_load, mod_call_control_shutdown, NULL);

static struct {
	char *webhook_allowed_events;
	char *cc_api_host;
	char *cc_api_external;
	int cc_api_port;
	switch_hash_t *tasks_hash;
	switch_mutex_t *hash_mutex;
} globals;

static switch_xml_config_int_options_t config_opt_cc_api_port = { SWITCH_TRUE, 1, SWITCH_TRUE, 65535 };

static switch_xml_config_item_t instructions[] = {
	SWITCH_CONFIG_ITEM("webhook-allowed-events", SWITCH_CONFIG_STRING, CONFIG_RELOADABLE, &globals.webhook_allowed_events, "ALL", NULL, NULL, NULL),
	SWITCH_CONFIG_ITEM("cc-api-host", SWITCH_CONFIG_STRING, CONFIG_RELOADABLE, &globals.cc_api_host, "localhost", NULL, NULL, NULL),
	SWITCH_CONFIG_ITEM("cc-api-external", SWITCH_CONFIG_STRING, CONFIG_RELOADABLE, &globals.cc_api_external, "http://localhost:8055", NULL, NULL, NULL),
	SWITCH_CONFIG_ITEM("cc-api-port", SWITCH_CONFIG_INT, CONFIG_RELOADABLE, &globals.cc_api_port, (void *) 8055, &config_opt_cc_api_port, NULL, NULL),
	SWITCH_CONFIG_ITEM_END()
};

struct cc_task {
	char *webhook_uri;
	char *uuid;
	char *uuid_secret;
	switch_core_session_t *session;
	switch_mutex_t *mutex;
	switch_memory_pool_t *pool;
	int fail_count;
	int running;
};
typedef struct cc_task cc_task_t;

struct response_data {
	char *data;
	size_t size;
};

static switch_status_t do_config(switch_bool_t reload)
{
	memset(&globals, 0, sizeof(globals));

	if (switch_xml_config_parse_module_settings("call_control.conf", reload, instructions) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Could not open call_control.conf\n");
		return SWITCH_STATUS_FALSE;
	}

	return SWITCH_STATUS_SUCCESS;
}

static void webhook_event_handler(switch_event_t *event)
{
	cc_task_t *task = NULL;
	const char *uuid = NULL;
	const char *event_name = NULL;
	switch_CURL *curl = NULL;
	switch_curl_slist_t *headers = NULL;
	char url[1024];
	char errbuf[CURL_ERROR_SIZE];
	CURLcode res;
	long rescode;
	ks_json_t *json_res = NULL;
	ks_json_t *json_event = NULL;
	ks_pool_t *ks_pool = NULL;
	char *json_str = NULL;
	char *req = NULL;
	struct response_data rd = { 0 };
	char *allowed_events[1024] = { 0 };
	int allowed_events_count = 0;

	switch_assert(event);

	uuid = switch_event_get_header(event, "Unique-ID");
	event_name = switch_event_name(event->event_id);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Event name %s\n", event_name);
	if (zstr(uuid)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "No Unique-ID in the event, ignoring...\n");
		goto done;
	}

	if (zstr(event_name)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "No event_name in the event, ignoring...\n");
		goto done;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "[%s] [%s] Looking for task\n", uuid, event_name);
	
	switch_mutex_lock(globals.hash_mutex);
	if ((task = switch_core_hash_find(globals.tasks_hash, uuid))) {
		int should_dispatch = 0;
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "[%s] [%s] Found the task\n", uuid, event_name);

		switch_mutex_lock(task->mutex);
		if (!task->running) {
			switch_mutex_unlock(task->mutex);
			switch_mutex_unlock(globals.hash_mutex);
			goto done;
		}

		allowed_events_count = switch_separate_string(globals.webhook_allowed_events, ',', allowed_events, (sizeof(allowed_events) / sizeof(allowed_events[0])));
		for (int i = 0; i < allowed_events_count; i++) {
			if (!strcasecmp(event_name, allowed_events[i]) || !strcasecmp("ALL", allowed_events[i])) {
				should_dispatch = 1;
				break;
			}
		}

		if (should_dispatch) {
			ks_pool_open(&ks_pool);
			json_event = ks_json_pcreate_object(ks_pool);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "[%s] [%s] Event can be dispatched\n", uuid, event_name);

			if (switch_event_serialize_json_obj(event, &json_event) == SWITCH_STATUS_SUCCESS) {
				json_res = ks_json_pcreate_object(ks_pool);
				ks_json_add_string_to_object(json_res, "api", globals.cc_api_external);
				ks_json_add_string_to_object(json_res, "uuid", task->uuid);
				ks_json_add_string_to_object(json_res, "uuid_secret", task->uuid_secret);
				ks_json_add_item_to_object(json_res, "event", json_event);

				json_str = ks_json_pprint_unformatted(ks_pool, json_res);

				curl = switch_curl_easy_init();

				headers = switch_curl_slist_append(headers, "Accept: application/json");
				headers = switch_curl_slist_append(headers, "Accept-Charset: utf-8");
				headers = switch_curl_slist_append(headers, "Content-Type: application/json");

				switch_curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5);
				switch_curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);

				if (!strncasecmp(url, "https", 5)) {
					switch_curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
					switch_curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
				}

				switch_curl_easy_setopt(curl, CURLOPT_URL, task->webhook_uri);
				switch_curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
				switch_curl_easy_setopt(curl, CURLOPT_USERAGENT, "mod_call_control/1");
				switch_curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
				switch_curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
				//switch_curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&rd);

				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "[%s] [%s] Dispatching to webhook %s\n", uuid, event_name, task->webhook_uri);
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "[%s] [%s] Dispatching json %s\n", uuid, event_name, json_str);
				if ((res = switch_curl_easy_perform(curl))) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Curl Result %d, Error: %s\n", res, errbuf);
				} else {
					switch_curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &rescode);

					if (rescode != 200) {
						//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[%s] [%s] Event delivery failed with HTTP code %ld, %s\n", uuid, event_name, rescode, rd.data);
						task->fail_count = task->fail_count + 1;
						if (task->fail_count >= MAX_FAIL_COUNT && task->running == 1) {
							switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[%s] [%s] Reached max retries to reach webhook %s, stopping task...\n", uuid, event_name, task->webhook_uri);
							task->running = 0;
						}
					}
				}
			} else {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "[%s] [%s] Cannot serialize event to json, ignoring...\n", uuid, event_name);
			}
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "[%s] [%s] Event not allowed in whitelist, ignoring...\n", uuid, event_name);
		}
		switch_mutex_unlock(task->mutex);
	}
	switch_mutex_unlock(globals.hash_mutex);

 done:
	if (ks_pool)
		ks_pool_close(&ks_pool);

	switch_safe_free(rd.data);
	switch_safe_free(req);
	return;
}

SWITCH_STANDARD_API(call_control_function)
{
	cc_task_t *task = NULL;
	switch_memory_pool_t *task_pool;
	char *argv[1024] = { 0 };
	int argc = 0;
	char *mycmd = NULL;
	switch_status_t status = SWITCH_STATUS_SUCCESS;

	static const char usage_string[] = "USAGE:\n"
		"--------------------------------------------------------------------------------\n"
		"call_control start <uuid> <webhook>\n"
		"call_control stop <uuid> <webhook>\n"
		"call_control status\n"
		"call_control list [debug]\n"
		"--------------------------------------------------------------------------------\n";

	if (zstr(cmd)) {
		stream->write_function(stream, "%s", usage_string);
		goto done;
	}

	if (!(mycmd = strdup(cmd))) {
		status = SWITCH_STATUS_MEMERR;
		goto done;
	}

	if (!(argc = switch_separate_string(mycmd, ' ', argv, (sizeof(argv) / sizeof(argv[0])))) || !argv[0]) {
		stream->write_function(stream, "%s", usage_string);
		goto done;
	}

	if (argc < 2) {
		stream->write_function(stream, "%s", usage_string);
		goto done;
	}

	if (!zstr(argv[0]) && !zstr(argv[1])) {
		if (!strcasecmp(argv[0], "start")) {
			switch_core_session_t *session = NULL;
			ks_uuid_t uuid_secret;

			if ((session = switch_core_session_locate(argv[1]))) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Found session to start call control on it\n");
				switch_mutex_lock(globals.hash_mutex);
				if ((task = switch_core_hash_find(globals.tasks_hash, argv[1]))) {
					stream->write_function(stream, "-ERR Call Control is already started for this UUID\n");
					switch_mutex_unlock(globals.hash_mutex);
					goto done;
				}
				switch_mutex_unlock(globals.hash_mutex);

				switch_core_new_memory_pool(&task_pool);
				ks_uuid(&uuid_secret);

				task = (cc_task_t *) switch_core_alloc(task_pool, sizeof(*task));
				task->pool = task_pool;
				switch_mutex_init(&task->mutex, SWITCH_MUTEX_NESTED, task->pool);
				task->webhook_uri = NULL;
				task->uuid = switch_core_strdup(task->pool, argv[1]);
				task->uuid_secret = ks_uuid_str(NULL, &uuid_secret);
				task->session = session;
				task->running = 1;
				task->fail_count = 0;

				if (argc > 1 && !zstr(argv[2])) {
					task->webhook_uri = switch_core_strdup(task->pool, argv[2]);
				}

				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Adding task to the hash\n");
				switch_mutex_lock(globals.hash_mutex);
				switch_core_hash_insert(globals.tasks_hash, task->uuid, task);
				switch_mutex_unlock(globals.hash_mutex);

				switch_core_session_rwunlock(session);
			} else {
				stream->write_function(stream, "-ERR UUID not found\n");
				goto done;
			}
		} else if (!strcasecmp(argv[0], "stop")) {
			switch_mutex_lock(globals.hash_mutex);
			if ((task = switch_core_hash_find(globals.tasks_hash, argv[1]))) {
				stream->write_function(stream, "-ERR Call Control is already started for this UUID\n");
				switch_mutex_unlock(globals.hash_mutex);
				goto done;
			}
			switch_mutex_unlock(globals.hash_mutex);

			switch_mutex_lock(task->mutex);
			if (task->running == 1) {
				task->running = 0;
			}
			switch_mutex_unlock(task->mutex);

			switch_core_destroy_memory_pool(&task->pool);
			switch_mutex_lock(globals.hash_mutex);
			switch_core_hash_delete(globals.tasks_hash, task->uuid);
			switch_mutex_unlock(globals.hash_mutex);

			goto done;
		} else {
			stream->write_function(stream, "%s", usage_string);
			goto done;
		}
	} else {
		stream->write_function(stream, "%s", usage_string);
		goto done;
	}

 done:
	switch_safe_free(mycmd);
	return status;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_call_control_load)
{
	switch_status_t status = SWITCH_STATUS_SUCCESS;
	switch_api_interface_t *api_interface;

	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	status = do_config(SWITCH_FALSE);
	if (status == SWITCH_STATUS_FALSE) {
		goto done;
	}

	switch_mutex_init(&globals.hash_mutex, SWITCH_MUTEX_NESTED, pool);
	switch_core_hash_init(&globals.tasks_hash);

	if (switch_event_bind(modname, SWITCH_EVENT_ALL, SWITCH_EVENT_SUBCLASS_ANY, webhook_event_handler, NULL) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't bind!\n");
		status = SWITCH_STATUS_FALSE;
		goto done;
	}

	SWITCH_ADD_API(api_interface, "call_control", "Call Control API", call_control_function, "<command> <uuid> <webhook>");
	switch_console_set_complete("add call_control start <uuid> <webhook>");
	switch_console_set_complete("add call_control stop <uuid> <webhook>");

 done:
	return status;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_call_control_shutdown)
{
	switch_event_unbind_callback(webhook_event_handler);

	switch_mutex_lock(globals.hash_mutex);
	switch_core_hash_destroy(&globals.tasks_hash);
	switch_mutex_unlock(globals.hash_mutex);

	switch_xml_config_cleanup(instructions);
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
