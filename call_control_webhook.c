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
 *
 *
 * mod_call_control.c -- Bidirectional communication with external applications without socket through internal REST API and external webhook
 *
 */
#include "mod_call_control.h"
#include "call_control_webhook.h"

void webhook_event_handler(switch_event_t *event)
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

					task->fail_count = task->fail_count + 1;
				} else {
					switch_curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &rescode);

					if (rescode != 200) {
						//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[%s] [%s] Event delivery failed with HTTP code %ld, %s\n", uuid, event_name, rescode, rd.data);
						task->fail_count = task->fail_count + 1;
					}
				}
			} else {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "[%s] [%s] Cannot serialize event to json, ignoring...\n", uuid, event_name);
			}
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "[%s] [%s] Event not allowed in whitelist, ignoring...\n", uuid, event_name);
		}

		if (task->fail_count >= MAX_FAIL_COUNT && task->running == 1) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "[%s] [%s] Reached max retries to reach webhook %s, stopping task...\n", uuid, event_name, task->webhook_uri);
			task->running = 0;
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

switch_status_t start_session_webhook(switch_core_session_t *session, char *webhook_url)
{
	cc_task_t *task = NULL;
	const char *session_uuid = NULL;
	switch_memory_pool_t *task_pool;
	ks_uuid_t uuid_secret;

	if (!session || zstr(webhook_url)) {
		return SWITCH_STATUS_FALSE;
	}

	session_uuid = switch_core_session_get_uuid(session);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Found session to start call control on it\n");
	switch_mutex_lock(globals.hash_mutex);
	if ((task = switch_core_hash_find(globals.tasks_hash, session_uuid))) {
		switch_mutex_unlock(globals.hash_mutex);
		return SWITCH_STATUS_FALSE;
	}
	switch_mutex_unlock(globals.hash_mutex);

	switch_core_new_memory_pool(&task_pool);
	ks_uuid(&uuid_secret);

	task = (cc_task_t *) switch_core_alloc(task_pool, sizeof(*task));
	task->pool = task_pool;
	switch_mutex_init(&task->mutex, SWITCH_MUTEX_NESTED, task->pool);
	task->webhook_uri = NULL;
	task->uuid = switch_core_strdup(task->pool, session_uuid);
	task->uuid_secret = ks_uuid_str(NULL, &uuid_secret);
	task->session = session;
	task->running = 1;
	task->fail_count = 0;

	if (!zstr(webhook_url)) {
		task->webhook_uri = switch_core_strdup(task->pool, webhook_url);
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Adding task to the hash\n");
	switch_mutex_lock(globals.hash_mutex);
	switch_core_hash_insert(globals.tasks_hash, task->uuid, task);
	switch_mutex_unlock(globals.hash_mutex);

	return SWITCH_STATUS_SUCCESS;
}

switch_status_t stop_session_webhook(switch_core_session_t *session)
{
	cc_task_t *task = NULL;
	const char *session_uuid = NULL;

	if (!session) {
		return SWITCH_STATUS_FALSE;
	}

	session_uuid = switch_core_session_get_uuid(session);

	switch_mutex_lock(globals.hash_mutex);
	if ((task = switch_core_hash_find(globals.tasks_hash, session_uuid))) {
		switch_mutex_unlock(globals.hash_mutex);
		return SWITCH_STATUS_FALSE;
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

	return SWITCH_STATUS_SUCCESS;
}

void webhooks_status(switch_stream_handle_t *stream)
{
	switch_hash_index_t *hi;
	void *val;
	const void *vvar;
	cc_task_t *task = NULL;
	const char *line = "=================================================================================================\n";

	switch_mutex_lock(globals.hash_mutex);
	// @TODO: fix line tabs here
	stream->write_function(stream, "%25s\t%s\t  %40s\t%s\n", "UUID", "Webhook URL", "Fail Count", "Running");
	stream->write_function(stream, line);
	for (hi = switch_core_hash_first(globals.tasks_hash); hi; hi = switch_core_hash_next(&hi)) {
		switch_core_hash_this(hi, &vvar, NULL, &val);
		task = (cc_task_t *) val;

		stream->write_function(stream, "%25s\t%s\t  %d\t%s\n", task->uuid, task->webhook_uri, task->fail_count, task->running ? "Yes" : "No");
	}
	stream->write_function(stream, line);
	switch_mutex_unlock(globals.hash_mutex);
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
