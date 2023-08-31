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
#include "call_control_api.h"

static bool safe_strcmp(const char *a, const char *b)
{
	if (!a && !b)
		return true;
	if (!a || !b)
		return false;
	return strcmp(a, b) == 0;
}

static onion_connection_status execute_api(void *_, onion_request *req,
                                           onion_response *res)
{
	onion_connection_status fres = OCS_PROCESSED;
	const onion_block *dreq = onion_request_get_data(req);
	onion_dict *jreq = NULL;
	cc_task_t *task = NULL;
	onion_dict *jres = onion_dict_new();
	onion_block *jresb = onion_dict_to_json(jres);
	switch_stream_handle_t stream = { 0 };
	char *command, *args, *task_uuid, *secret;

	SWITCH_STANDARD_STREAM(stream);

	if (dreq)
		jreq = onion_dict_from_json(onion_block_data(dreq));
	if (jreq) {
		command = onion_low_strdup(onion_dict_rget(jreq, "params", "command", NULL));
		args = onion_low_strdup(onion_dict_rget(jreq, "params", "args", NULL));
		task_uuid = onion_low_strdup(onion_dict_rget(jreq, "params", "task_uuid", NULL));
		secret = onion_low_strdup(onion_dict_rget(jreq, "params", "secret", NULL));

		//debug
		//onion_dict_print_dot(jreq);

		/// Check is the proper call.
		if (!safe_strcmp(onion_dict_get(jreq, "jsonrpc"), "2.0")) {
			onion_response_write0(res,
			                      "{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32700, \"message\": \"Parse error\"}, \"id\": null}");
			goto done;
		}

		// verify allowed methods
		if (
				!safe_strcmp(onion_dict_get(jreq, "method"), "api") ||
				!safe_strcmp(onion_dict_get(jreq, "method"), "bgapi") ||
				!safe_strcmp(onion_dict_get(jreq, "method"), "status") ||
				!safe_strcmp(onion_dict_get(jreq, "method"), "run") ||
				!safe_strcmp(onion_dict_get(jreq, "method"), "stop")
				) {
			onion_response_printf(res,
			                      "{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32601, \"message\": \"Method not found\"}, \"id\": \"%s\"}",
			                      onion_dict_get(jreq, "id")
			);
			goto done;
		}

		// verify token matches the session
		if ((task = switch_core_hash_find(globals.tasks_hash, task_uuid))) {
			if (!strcasecmp(task->uuid_secret, secret)) {
				onion_response_printf(res,
				                      "{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32001, \"message\": \"Secret didn't match\"}, \"id\": \"%s\"}",
				                      onion_dict_get(jreq, "id")
				);
				goto done;
			}

			// list allowed commands here
			if (strcasecmp("uuid_", command) < 0) {
				onion_response_printf(res,
				                      "{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32002, \"message\": \"Command not allowed\"}, \"id\": \"%s\"}",
				                      onion_dict_get(jreq, "id")
				);
				goto done;
			}

			// execute
			if (safe_strcmp(onion_dict_get(jreq, "method"), "api")) {
				char fg_command[256] = { 0 };

				if (zstr(args)) {
					switch_snprintf(fg_command, sizeof(fg_command), "%s %s", command, task->uuid);
				} else {
					switch_snprintf(fg_command, sizeof(fg_command), "%s %s %s", command, task->uuid, args);
				}
				switch_api_execute("api", fg_command, task->session, &stream);
			} else if (safe_strcmp(onion_dict_get(jreq, "method"), "bgapi")) {
				char bg_command[256] = { 0 };

				if (zstr(args)) {
					switch_snprintf(bg_command, sizeof(bg_command), "%s %s", command, task->uuid);
				} else {
					switch_snprintf(bg_command, sizeof(bg_command), "%s %s %s", command, task->uuid, args);
				}
				switch_api_execute("bgapi", bg_command, task->session, &stream);
			}

			/// Prepare message
			onion_dict_add(jres, "jsonrpc", "2.0", 0);
			onion_dict_add(jres, "result", stream.data, OD_DUP_VALUE);
			onion_dict_add(jres, "id", onion_dict_get(jreq, "id"), 0);

			/// Write
			onion_response_write(res, onion_block_data(jresb), onion_block_size(jresb));
		}

		goto done;
	} else {
		onion_response_write0(res,
		                      "This is a JSON rpc service. Please send jsonrpc requests.");


	}

	done:
	/// Clean up.
	switch_safe_free(stream.data);
	onion_block_free(jresb);
	onion_dict_free(jres);
	onion_low_free(command);
	onion_low_free(args);
	onion_dict_free(jreq);
	return fres;
}

static void *SWITCH_THREAD_FUNC onion_thread(switch_thread_t *thread, void *obj)
{
	cc_api_server_t *api_server = (cc_api_server_t *) obj;
	onion_listen(api_server->server);
	return NULL;
}

switch_status_t start_api(char *host, char *port)
{
	switch_thread_data_t *td;
	switch_memory_pool_t *api_pool;
	cc_api_server_t *api_server = NULL;
	onion_url *url;

	switch_core_new_memory_pool(&api_pool);

	td = switch_core_alloc(api_pool, sizeof(*td));

	api_server = (cc_api_server_t *) switch_core_alloc(api_pool, sizeof(*api_server));
	api_server->server = onion_new(O_THREADED);
	url = onion_root_url(api_server->server);
	onion_set_hostname(api_server->server, host);
	onion_set_port(api_server->server, port);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
	onion_url_add(url, "", execute_api);
#pragma GCC diagnostic pop
	globals.api_server = api_server;

	td->alloc = 0;
	td->func = onion_thread;
	td->obj = api_server;
	td->pool = api_pool;

	switch_thread_pool_launch_thread(&td);

	return SWITCH_STATUS_SUCCESS;
}

switch_status_t stop_api()
{
	onion_listen_stop(globals.api_server->server);
	onion_free(globals.api_server->server);
	switch_core_destroy_memory_pool(&globals.api_server->pool);
	globals.api_server = NULL;
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
