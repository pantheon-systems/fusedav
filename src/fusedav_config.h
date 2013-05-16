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
struct fusedav_config {
    char *uri;
    // [ProtocolAndPerformance]
    bool progressive_propfind;
    bool refresh_dir_for_file_stat;
    bool grace;
    bool singlethread;
    char *cache_uri;
    // [Authenticate]
    char *username;
    char *password;
    char *ca_certificate;
    char *client_certificate;
    // [LogAndProcess]
    bool nodaemon;
    char *cache_path;
    char *run_as_uid;
    char *run_as_gid;
    int  verbosity;
    char *section_verbosity;
    // Other
    char *config_file;
    stat_cache_t *cache;
    struct stat_cache_supplemental cache_supplemental;
    // To be removed when titan and fusedav are in sync
    bool dummy1;
    int  dummy2;
    char *dummy3;
};

void parse_configs(struct fusedav_config *config, GError **gerr);

#endif
