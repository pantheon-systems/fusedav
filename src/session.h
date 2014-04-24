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

int session_config_init(char *base, char *ca_cert, char *client_cert);
CURL *session_request_init(const char *path, const char *query_string, bool temporary_handle, bool new_slist, bool maintenance_mode);
void session_config_free(void);
const char *get_base_url(void);
char *escape_except_slashes(CURL *session, const char *path);
void session_temp_handle_destroy(CURL *session);
void log_filesystem_nodes(const char *fcn_name, const CURLcode res, const long response_code, const int iter, const char *path);
void aggregate_log_print_server(unsigned int log_level, unsigned int section, const char *name, time_t *previous_time,
    const char *description1, unsigned long *count1, unsigned long value1,
    const char *description2, long *count2, long value2);
void aggregate_log_print_local(unsigned int log_level, unsigned int section, const char *name, time_t *previous_time,
    const char *description1, unsigned long *count1, unsigned long value1,
    const char *description2, long *count2, long value2);

void set_saint_mode(void);
bool use_saint_mode(bool maintenance_mode);

#endif
