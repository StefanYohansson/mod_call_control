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
#include "call_control_api.h"

globals_t globals;

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_call_control_shutdown);
SWITCH_MODULE_RUNTIME_FUNCTION(mod_call_control_runtime);
SWITCH_MODULE_LOAD_FUNCTION(mod_call_control_load);

SWITCH_MODULE_DEFINITION(mod_call_control, mod_call_control_load, mod_call_control_shutdown, NULL
);

static switch_xml_config_int_options_t config_opt_cc_api_port = {SWITCH_TRUE, 1, SWITCH_TRUE, 65535};

static switch_xml_config_item_t instructions[] = {
		SWITCH_CONFIG_ITEM("webhook-allowed-events", SWITCH_CONFIG_STRING, CONFIG_RELOADABLE,
		                   &globals.webhook_allowed_events, "ALL", NULL, NULL, NULL),
		SWITCH_CONFIG_ITEM("cc-api-host", SWITCH_CONFIG_STRING, CONFIG_RELOADABLE, &globals.cc_api_host, "localhost", NULL,
		                   NULL, NULL),
		SWITCH_CONFIG_ITEM("cc-api-external", SWITCH_CONFIG_STRING, CONFIG_RELOADABLE, &globals.cc_api_external,
		                   "http://localhost:8055", NULL, NULL, NULL),
		SWITCH_CONFIG_ITEM("cc-api-port", SWITCH_CONFIG_INT, CONFIG_RELOADABLE, &globals.cc_api_port, (void *) 8055,
		                   &config_opt_cc_api_port, NULL, NULL),
		SWITCH_CONFIG_ITEM_END()
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

SWITCH_STANDARD_APP(call_control_app_function)
{
	start_session_webhook(session, (char *) data);
}

SWITCH_STANDARD_API(call_control_function)
{
	char *argv[1024] = { 0 };
	int argc = 0;
	char *mycmd = NULL;
	switch_status_t status = SWITCH_STATUS_SUCCESS;

	static const char usage_string[] = "USAGE:\n"
	"--------------------------------------------------------------------------------\n"
	"call_control start <uuid> <webhook>\n"
	"call_control stop <uuid>\n"
	"call_control status all\n"
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

			if ((session = switch_core_session_locate(argv[1]))) {
				char *webhook_url = NULL;

				if (argc > 1 && !zstr(argv[2])) {
					webhook_url = argv[2];
				}
				if (start_session_webhook(session, webhook_url) == SWITCH_STATUS_FALSE) {
					stream->write_function(stream, "-ERR Cannot start for this session\n");
				} else {
					stream->write_function(stream, "+OK Call Control started for uuid\n");
				}

				switch_core_session_rwunlock(session);
			} else {
				stream->write_function(stream, "-ERR UUID not found\n");
				goto done;
			}
		} else if (!strcasecmp(argv[0], "stop")) {
			switch_core_session_t *session = NULL;
			if ((session = switch_core_session_locate(argv[1]))) {
				if (stop_session_webhook(session) == SWITCH_STATUS_FALSE) {
					stream->write_function(stream, "-ERR Cannot stop for this session\n");
				} else {
					stream->write_function(stream, "+OK Call Control stopped for uuid\n");
				}
				switch_core_session_rwunlock(session);
				goto done;
			} else {
				stream->write_function(stream, "-ERR UUID not found\n");
				goto done;
			}
		} else if (!strcasecmp(argv[0], "status")) {
			webhooks_status(stream);
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
	switch_application_interface_t *app_interface;

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

	if (start_api(globals.cc_api_host, globals.cc_api_port) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't start API!\n");
		status = SWITCH_STATUS_FALSE;
		goto done;
	}

	SWITCH_ADD_API(api_interface, "call_control", "Call Control API", call_control_function, "<command> <uuid> <webhook>");
	SWITCH_ADD_APP(app_interface, "call_control", "Start Call Control for current session", "", call_control_app_function, "<webhook>", SAF_NONE);
	switch_console_set_complete("add call_control start <uuid> <webhook>");
	switch_console_set_complete("add call_control stop <uuid>");
	switch_console_set_complete("add call_control status all");

	done:
	return status;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_call_control_shutdown)
{
	switch_event_unbind_callback(webhook_event_handler);

	stop_api();

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
