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
 * Stefan Yohansson <stefan.yohansson@agnesit.tech>
 *
 *
 * mod_call_control.c -- Bidirectional communication with external applications without socket through internal REST API and external webhook
 *
 */

#ifndef CALL_CONTROL_WEBHOOK_H
#define CALL_CONTROL_WEBHOOK_H

#include <switch.h>
#include <switch_curl.h>
#include <switch_core_db.h>

switch_status_t init_webhook();
void webhook_event_handler(switch_event_t *event);
switch_bool_t has_session_webhook_alive(switch_core_session_t *session);
switch_status_t start_session_webhook(switch_core_session_t *session, char *webhook_url);
switch_status_t stop_session_webhook(switch_core_session_t *session);
void webhooks_status(switch_stream_handle_t *stream);

#endif
