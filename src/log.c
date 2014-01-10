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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <systemd/sd-journal.h>
#include <stdio.h>
#include <unistd.h>
#include <syscall.h>
#include <assert.h>
#include <stdlib.h>

#include "log.h"
#include "log_sections.h"

#define SITE_ID_SIZE 64
#define SITE_ENV_SIZE 16
#define BINDING_ID_SIZE 32
static unsigned int global_log_level = 5;
static unsigned int section_log_levels[SECTIONS] = {0};
static char log_prefix_abbrev[9] = {0};
static char site_id[SITE_ID_SIZE] = {0};
static char site_env[SITE_ENV_SIZE] = {0};
// binding id is exactly BINDING_ID_SIZE, so we use it and make room for the null terminator
static char binding_id[BINDING_ID_SIZE + 1] = {0};

static const char *errlevel[] = {"EMERG:  ", "ALERT:  ", "CRIT:   ", "ERR:    ", "WARN:   ", "NOTICE: ", "INFO:   ", "DEBUG:  "};

/* function returning the max between two numbers */
static int min(int num1, int num2) 
{
   /* local variable declaration */
   int result;
 
   if (num1 < num2)
      result = num1;
   else
      result = num2;
 
   return result; 
}

/* The log_prefix comes from fusedav.conf; the base_url from curl and fuse. */
void log_init(unsigned int log_level, const char *log_level_by_section,
        const char *log_prefix, const char *base_url) {
            
    unsigned int vlen;
    const char *base_dir = NULL;
    char *start;
    char *end;

    global_log_level = log_level;

    // @TODO once we have the new titan with log_prefix, remove base_dir code
    base_dir = strstr(log_prefix, "/sites");

    // a default, in case there is no binding id
    strcpy(binding_id, "(null)");

    if (log_prefix == NULL) {
        strncpy(log_prefix_abbrev, "(null)", 8);
    }
    else if(base_dir != NULL) {
        if (strlen(base_dir) > 15) {
            // The abbreviated binding id ...
            strncpy(log_prefix_abbrev, base_dir + 7, 8);
         }
        // But of course, if base_dir is too short, but at least 8, copy the first 8. We have no idea
        // what this will look like.
        else if (strlen(base_dir) > 8) {
            strncpy(log_prefix_abbrev, base_dir, 8);
        }
        // But of course, if it doesn't have 8 chars, just copy in what it does have
        else if (strlen(base_dir) > 0) {
            strcpy(log_prefix_abbrev, base_dir);
        }
        else {
            strncpy(log_prefix_abbrev, "(null)", 8);
        }
    }
    else if (strlen(log_prefix) > 0) {
        strncpy(log_prefix_abbrev, log_prefix, 8);
        strncpy(binding_id, log_prefix, BINDING_ID_SIZE);
    }
    // But of course, if it's an empty string, just set site id to (null)
    else {
        strncpy(log_prefix_abbrev, "(null)", 8);
    }

    // Get the site id and env
    // If there is no base url, we'll fill with a marker ("(null)")
    if (base_url == NULL) {
        start = NULL;
    }
    else {
        // Get the site_id from the base url
        start = strstr(base_url, "/sites/");
        if (start) start += strlen("/sites/"); // move past /sites/
    }
    
    if (start == NULL) {
        strcpy(site_id, "(null)");
        strcpy(site_env, "(null)");
    }
    else {
        // site id goes up to /environments/
        end = strstr(start, "/environments/");
        // if /environments/ is not in the base_url, best effort to get something
        if (end == NULL) {
            strncpy(site_id, start, SITE_ID_SIZE);
            strcpy(site_env, "(null)");
        }
        else {
            // site id is now everything up to /environments/, but don't overrun the string
            strncpy(site_id, start, min(end - start, SITE_ID_SIZE)); // up to /environments
            // Try to find the environment; it is just past /environments/, so set start there
            start = end + strlen("/environments/"); // Move past /environments/
            // There should be a slash after the env name, so find it
            end = strchr(start, '/');
            // If there is a slash, use it to limit the string
            if (end) {
                strncpy(site_env, start, min(end - start, SITE_ENV_SIZE));
            }
            // But if there is no slash, best effort
            else {
                strncpy(site_env, start, SITE_ENV_SIZE);
            }
        }
    }
        
    // JB @TODO Until both fusedav and titan are on the new versions reading the config file,
    // vstr will be NULL, so check and take evasive measures. Later, we should be able to
    // remove this check
    if (log_level_by_section == NULL) return;

    // If we see a section whose value is greater than vlen, its value will be 0 by default.
    // Zero means use the global log level
    vlen = strlen(log_level_by_section);
    for (unsigned int idx = 0; idx < vlen; idx++) {
        section_log_levels[idx] = log_level_by_section[idx] - '0'; // Looking for an integer 0-7
    }
}

// Are we logging this message?
int logging(unsigned int log_level, unsigned int section) {
    unsigned int local_log_level = global_log_level;
    
    // If the section verbosity is not 0 for this section, use it as the verbosity level;
    // otherwise, just use the global_log_level
    if (section < SECTIONS && section_log_levels[section]) {
        local_log_level = section_log_levels[section];
    }

    return log_level <= local_log_level;
}

#define max_msg_sz 80
int log_print(unsigned int log_level, unsigned int section, const char *format, ...) {
    int ret = 0;
    va_list ap;
    char *formatwithtid;
    char msg[max_msg_sz - 1];

    if (logging(log_level, section)) {
        va_start(ap, format);
        ret = vsnprintf(msg, max_msg_sz, format, ap);
        asprintf(&formatwithtid, "[tid=%lu] [bid=%s] %s", syscall(SYS_gettid), log_prefix_abbrev, errlevel[log_level]);
        assert(formatwithtid);
        ret = sd_journal_send("MESSAGE=%s%s", formatwithtid, msg,
                              "PRIORITY=%d", log_level,
                              "BINDING_ID=%s", binding_id,
                              "SITE_ID=%s", site_id,
                              "SITE_ENV=%s", site_env,
                              "TID=%lu", syscall(SYS_gettid),
                              "PACKAGE_VERSION=%s", PACKAGE_VERSION,
                              NULL);
        free(formatwithtid);
        va_end(ap);
    }

    return ret;
}
