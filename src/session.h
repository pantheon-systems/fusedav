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

#include <curl/curl.h>

int session_config_init(char *base, char *ca_cert, char *client_cert, char *filesystem_domain, char *filesystem_port);
CURL *session_request_init(const char *path, const char *query_string);
CURL *session_get_handle(void);
void session_config_free(void);
const char *get_base_url(void);
char *escape_except_slashes(CURL *session, const char *path);
int retry_curl_easy_perform(CURL *session);

#endif
