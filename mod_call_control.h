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

#ifndef MOD_CALL_CONTROL_H
#define MOD_CALL_CONTROL_H

#include <switch.h>
#include <switch_curl.h>
#include "ks.h"
#include <onion/onion.h>

#define MAX_FAIL_COUNT 10
#define CC_SQLITE_DB_NAME "call_control"

struct cc_api_server {
	onion *server;
	switch_memory_pool_t *pool;
};
typedef struct cc_api_server cc_api_server_t;

typedef struct {
	char *webhook_allowed_events;
	char *cc_api_host;
	char *cc_api_external;
	char *cc_api_port;
	char *odbc_dsn;
	char *dbname;
	cc_api_server_t *api_server;
	switch_hash_t *tasks_hash;
	switch_mutex_t *hash_mutex;
	switch_mutex_t *mutex;
	switch_bool_t global_database_lock;
} globals_t;

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

extern globals_t globals;

#endif
