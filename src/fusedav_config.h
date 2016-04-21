#ifndef foofusedavconfighfoo
#define foofusedavconfighfoo

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
#include <glib.h>
#include <fuse.h>

#include "statcache.h"

// Access with struct fusedav_config *config = fuse_get_context()->private_data;

// We have separated all fusedav options (below) from fuse options (gid, uid, umask...)
// All fusedav options are configured by our mechanism; all fuse options by fuse
// via the Options line in the .mount file. 'conf' is the exception.
// We can still access config via the above mechanism, but it might be more logical just
// to expose it in some other way now.

// We populate these entries during configuration, and use them in our fusedav code
struct fusedav_config {
    char *uri;
    bool progressive_propfind;
    bool refresh_dir_for_file_stat;
    bool grace;
    bool singlethread;
    bool nodaemon;
    char *cache_uri;
    char *username;
    char *password;
    char *ca_certificate;
    char *client_certificate;
    char *cache_path;
    char *run_as_uid;
    char *run_as_gid;
    int  log_level;
    char *log_level_by_section;
    char *log_prefix;
    int  max_file_size;
    char *statsd_host;
    char *statsd_port;
    char *conf;
    stat_cache_t *cache;
    struct stat_cache_supplemental cache_supplemental;
};

void configure_fusedav(struct fusedav_config *config, struct fuse_args *args, char **mountpoint, GError **gerr);
const char *get_user_agent(void);
#endif
