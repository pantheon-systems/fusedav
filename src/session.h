#ifndef foosessionhfoo
#define foosessionhfoo

/***
  This file is part of fusedav.

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
***/

#include <stdbool.h>
#include <curl/curl.h>

extern int num_filesystem_server_nodes;

int session_config_init(char *base, char *ca_cert, char *client_cert, bool grace);
CURL *session_request_init(const char *path, const char *query_string, bool temporary_handle);
void session_config_free(void);
bool process_status(const char *fcn_name, CURL *session, const CURLcode res, 
        const long response_code, const long elapsed_time, const int iter, 
        const char *path, bool tmp_session);
const char *get_base_url(void);
char *escape_except_slashes(CURL *session, const char *path);
void delete_tmp_session(CURL *session);
void aggregate_log_print_server(unsigned int log_level, unsigned int section, const char *name, time_t *previous_time,
    const char *description1, unsigned long *count1, unsigned long value1,
    const char *description2, long *count2, long value2);
void aggregate_log_print_local(unsigned int log_level, unsigned int section, const char *name, time_t *previous_time,
    const char *description1, unsigned long *count1, unsigned long value1,
    const char *description2, long *count2, long value2);

typedef enum { STATE_HEALTHY, STATE_SAINT_MODE, STATE_ATTEMPTING_TO_EXIT_SAINT_MODE, NUM_STATES } state_t;
typedef enum { CLUSTER_FAILURE, SAINT_MODE_DURATION_EXPIRED, CLUSTER_SUCCESS, NUM_EVENTS } event_t;

void action_s1_e1 (void);
void action_s1_e2 (void);
void action_s1_e3 (void);
void action_s2_e1 (void);
void action_s2_e2 (void);
void action_s2_e3 (void);
void action_s3_e1 (void);
void action_s3_e2 (void);
void action_s3_e3 (void);

void try_release_request_outstanding(void);
void trigger_saint_mode_expired_if_needed(void);
void trigger_saint_event(event_t);
state_t get_saint_state(void);
bool use_saint_mode(void);
void timed_curl_easy_perform(CURL *session, CURLcode *res, long *response_code, long *elapsed_time);
const char *get_filesystem_cluster(void);
const char *get_nodeaddr(void);
const char *curl_errorbuffer(CURLcode res);

#endif
