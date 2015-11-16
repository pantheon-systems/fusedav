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

#include <fuse.h>
#include <jemalloc/jemalloc.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

#include "util.h"
#include "log.h"
#include "log_sections.h"
#include "stats.h"
#include "statcache.h"

#define MAX_LINE_LEN 256

struct statistics stats;

// print the line, maybe to the log, maybe to a stats file, maybe to both
// log = true means print to log; fd >= 0 means print to stats file
static void print_line(bool log, int fd, unsigned int log_level, unsigned int section, char *output) {
    if (log) {
        log_print(log_level, section, output);
    }
    if (fd >= 0) {
        strncat(output, "\n", MAX_LINE_LEN);
        write(fd, output, strlen(output));
    }
}

static void malloc_stats_output(void *cbopaque, const char *s) {
    char stripped[MAX_LINE_LEN];
    size_t len;
    int fd = (long)cbopaque;
    bool log = (fd < 0);

    len = strlen(s);
    if (len >= MAX_LINE_LEN) {
        log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "Skipping line over %d characters.", MAX_LINE_LEN);
        return;
    }

    // Ignore up to one leading space.
    if (s[0] == '\n')
        strncpy(stripped, s + 1, len);
    else
        strncpy(stripped, s, len);

    // Ignore up to two trailing spaces.
    if (stripped[len - 2] == '\n')
        stripped[len - 2] = '\0';
    if (stripped[len - 1] == '\n')
        stripped[len - 1] = '\0';
    stripped[len] = '\0';

    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, stripped);

}

#define STAT_PATH_SIZE 80
// xxsm, xsm, sm, med, lg, xlg * 2 (one for get, one for put)
#define latency_items 13
void dump_stats(bool log, const char *cache_path) {
    struct latency_s {
        unsigned long count;
        unsigned long timing;
        const char *name;
    };
    struct latency_s latency[latency_items];
    char str[MAX_LINE_LEN];
    int fd = -1;

    log_print(LOG_DEBUG, SECTION_FUSEDAV_OUTPUT, "dump_stats: Enter %s :: logging -- %d", cache_path, log);
    if (!log) {
        /* The path to the cache stats directory looks like this.
         * /srv/bindings/11e4ce335f8240a88b4d5c88a00af3c8/cache/stats/20131203211358
         */
        char stat_path[STAT_PATH_SIZE];
        const char *stats_dir = "stats";
        char fname[STAT_PATH_SIZE];
        time_t tm;
        unsigned int stat_path_remaining;

        // If we have no cache path, we can't write, so punt
        if (!cache_path) {
            log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "dump_stats: error: no cache path to create stats directory");
            return;
        }

        /* We're being pretty loose with errors here. If we fail, the job just
         * doesn't get done, but the damage is minimal.
         */
        snprintf(stat_path, STAT_PATH_SIZE, "%s/%s", cache_path, stats_dir);
        log_print(LOG_DEBUG, SECTION_FUSEDAV_OUTPUT, "dump_stats: directory %s", stat_path);
        if (mkdir(stat_path, 0770) == -1) {
            if (errno != EEXIST) {
                // just return on error. If we can't create the directory, there's no point
                // in trying to write the data
                log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "dump_stats: error creating stats directory %s :: %d %s", stat_path, errno, strerror(errno));
                return;
            }
        }
        // Create a filename whose name is the date
        tm = time(NULL);
        strftime(fname, STAT_PATH_SIZE, "%Y%m%d%H%M%S", gmtime(&tm));
        // the 'n' in strncat is the max number of chars it will append.
        // So subtract the current size of stat_path from its max size to use as 'n' in strncat
        stat_path_remaining = STAT_PATH_SIZE - strlen(stat_path) - 1;
        if (stat_path_remaining < 2) {
            log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "dump_stats: a. not enough space left in stat_path  %s", stat_path);
        }
        else {
            strncat(stat_path, "/", stat_path_remaining);
        }
        stat_path_remaining = STAT_PATH_SIZE - strlen(stat_path) - 1;
        if (stat_path_remaining < (strlen(fname) + 1)) {
            log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "dump_stats: b. not enough space left in stat_path  %s", stat_path);
        }
        else {
            strncat(stat_path, fname, stat_path_remaining);
        }
        stat_path[STAT_PATH_SIZE - 1] = '\0'; // Just make sure it's null terminated
        log_print(LOG_DEBUG, SECTION_FUSEDAV_OUTPUT, "dump_stats: file %s", stat_path);
        fd = open(stat_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
        if (fd < 0) {
            log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "dump_stats: error creating stats file %s :: %d %s", stat_path, errno, strerror(errno));
            return; // If we can't open the file, no point in continuing
        }
    }

    mallctl("prof.dump", NULL, NULL, NULL, 0);

    snprintf(str, MAX_LINE_LEN, "Caught SIGUSR2. Printing status.");
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);

    // Use cbopaque to pass in fd, if there is one
    malloc_stats_print(malloc_stats_output, (void *)(long)fd, "");

    snprintf(str, MAX_LINE_LEN, "Operations:");
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  chmod:            %u", FETCH(dav_chmod));
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  chown:            %u", FETCH(dav_chown));
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  create:           %u", FETCH(dav_create));
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  fsync:            %u", FETCH(dav_fsync));
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  flush:            %u", FETCH(dav_flush));
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  ftruncate:        %u", FETCH(dav_ftruncate));
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  fgetattr:         %u", FETCH(dav_fgetattr));
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  getattr:          %u", FETCH(dav_getattr));
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  mkdir:            %u", FETCH(dav_mkdir));
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  mknod:            %u", FETCH(dav_mknod));
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  open:             %u", FETCH(dav_open));
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  read:             %u", FETCH(dav_read));
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  readdir:          %u", FETCH(dav_readdir));
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  release:          %u", FETCH(dav_release));
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  rename:           %u", FETCH(dav_rename));
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  rmdir:            %u", FETCH(dav_rmdir));
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  unlink:           %u", FETCH(dav_unlink));
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  utimens:          %u", FETCH(dav_utimens));
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  write:            %u", FETCH(dav_write));
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);

    snprintf(str, MAX_LINE_LEN, "  cprop:            %u", FETCH(propfind_complete_cache));
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  pprop:            %u", FETCH(propfind_progressive_cache));
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  nprop:            %u", FETCH(propfind_negative_cache));
    print_line(log, fd, LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, str);


    snprintf(str, MAX_LINE_LEN, "  cache_file:       %u", FETCH(filecache_cache_file));
    print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  pdata_set:        %u", FETCH(filecache_pdata_set));
    print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  create_file:      %u", FETCH(filecache_create_file));
    print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  pdata_get:        %u", FETCH(filecache_pdata_get));
    print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  fresh_fd:         %u", FETCH(filecache_fresh_fd));
    print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  open:             %u", FETCH(filecache_open));
    print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  read:             %u", FETCH(filecache_read));
    print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  write:            %u", FETCH(filecache_write));
    print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  close:            %u", FETCH(filecache_close));
    print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  return_etag:      %u", FETCH(filecache_return_etag));
    print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  sync:             %u", FETCH(filecache_sync));
    print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  truncate:         %u", FETCH(filecache_truncate));
    print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  delete:           %u", FETCH(filecache_delete));
    print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  pdata_move:       %u", FETCH(filecache_pdata_move));
    print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  orphans:          %u", FETCH(filecache_orphans));
    print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  cleanup:          %u", FETCH(filecache_cleanup));
    print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  get_fd:           %u", FETCH(filecache_get_fd));
    print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  set_error:        %u", FETCH(filecache_set_error));
    print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  forensic:         %u", FETCH(filecache_forensic_haven));
    print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  init:             %u", FETCH(filecache_init));
    print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  path2key:         %u", FETCH(filecache_path2key));
    print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  key2path:         %u", FETCH(filecache_key2path));
    print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);

    latency[0].count = FETCH(filecache_get_304_count);
    latency[1].count = FETCH(filecache_get_xxsm_count);
    latency[2].count = FETCH(filecache_get_xsm_count);
    latency[3].count = FETCH(filecache_get_sm_count);
    latency[4].count = FETCH(filecache_get_med_count);
    latency[5].count = FETCH(filecache_get_lg_count);
    latency[6].count = FETCH(filecache_get_xlg_count);
    latency[7].count = FETCH(filecache_put_xxsm_count);
    latency[8].count = FETCH(filecache_put_xsm_count);
    latency[9].count = FETCH(filecache_put_sm_count);
    latency[10].count = FETCH(filecache_put_med_count);
    latency[11].count = FETCH(filecache_put_lg_count);
    latency[12].count = FETCH(filecache_put_xlg_count);
    latency[0].timing = FETCH(filecache_get_304_count);
    latency[1].timing = FETCH(filecache_get_xxsm_timing);
    latency[2].timing = FETCH(filecache_get_xsm_timing);
    latency[3].timing = FETCH(filecache_get_sm_timing);
    latency[4].timing = FETCH(filecache_get_med_timing);
    latency[5].timing = FETCH(filecache_get_lg_timing);
    latency[6].timing = FETCH(filecache_get_xlg_timing);
    latency[7].timing = FETCH(filecache_put_xxsm_timing);
    latency[8].timing = FETCH(filecache_put_xsm_timing);
    latency[9].timing = FETCH(filecache_put_sm_timing);
    latency[10].timing = FETCH(filecache_put_med_timing);
    latency[11].timing = FETCH(filecache_put_lg_timing);
    latency[12].timing = FETCH(filecache_put_xlg_timing);
    latency[0].name = "get_304";
    latency[1].name = "get_xxsm";
    latency[2].name = "get_xsm";
    latency[3].name = "get_sm";
    latency[4].name = "get_med";
    latency[5].name = "get_lg";
    latency[6].name = "get_xlg";
    latency[7].name = "put_xxsm";
    latency[8].name = "put_xsm";
    latency[9].name = "put_sm";
    latency[10].name = "put_med";
    latency[11].name = "put_lg";
    latency[12].name = "put_xlg";

    // Since the names are of variable lengths, the values don't line up.
    // Figure out a way to align
    for (int idx = 0; idx < latency_items; idx++) {
        snprintf(str, MAX_LINE_LEN, "  %s_count:     %lu", latency[idx].name, latency[idx].count);
        print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
        snprintf(str, MAX_LINE_LEN, "  %s_timing:    %lu", latency[idx].name, latency[idx].timing);
        print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
        snprintf(str, MAX_LINE_LEN, "  %s_avelat:    %lu", latency[idx].name, latency[idx].count > 0 ? (latency[idx].timing / latency[idx].count) : 0);
        print_line(log, fd, LOG_NOTICE, SECTION_FILECACHE_OUTPUT, str);
    }

    snprintf(str, MAX_LINE_LEN, "Stat Cache Operations:");
    print_line(log, fd, LOG_NOTICE, SECTION_STATCACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  local_gen:        %u", FETCH(statcache_local_gen));
    print_line(log, fd, LOG_NOTICE, SECTION_STATCACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  path2key:         %u", FETCH(statcache_path2key));
    print_line(log, fd, LOG_NOTICE, SECTION_STATCACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  key2path:         %u", FETCH(statcache_key2path));
    print_line(log, fd, LOG_NOTICE, SECTION_STATCACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  open:             %u", FETCH(statcache_open));
    print_line(log, fd, LOG_NOTICE, SECTION_STATCACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  close:            %u", FETCH(statcache_close));
    print_line(log, fd, LOG_NOTICE, SECTION_STATCACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  value_get:        %u", FETCH(statcache_value_get));
    print_line(log, fd, LOG_NOTICE, SECTION_STATCACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  updated_ch:       %u", FETCH(statcache_updated_ch));
    print_line(log, fd, LOG_NOTICE, SECTION_STATCACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  read_updated:     %u", FETCH(statcache_read_updated));
    print_line(log, fd, LOG_NOTICE, SECTION_STATCACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  value_set:        %u", FETCH(statcache_value_set));
    print_line(log, fd, LOG_NOTICE, SECTION_STATCACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  delete:           %u", FETCH(statcache_delete));
    print_line(log, fd, LOG_NOTICE, SECTION_STATCACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  del_parent:       %u", FETCH(statcache_del_parent));
    print_line(log, fd, LOG_NOTICE, SECTION_STATCACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  iter_free:        %u", FETCH(statcache_iter_free));
    print_line(log, fd, LOG_NOTICE, SECTION_STATCACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  iter_init:        %u", FETCH(statcache_iter_init));
    print_line(log, fd, LOG_NOTICE, SECTION_STATCACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  iter_current:     %u", FETCH(statcache_iter_current));
    print_line(log, fd, LOG_NOTICE, SECTION_STATCACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  iter_next:        %u", FETCH(statcache_iter_next));
    print_line(log, fd, LOG_NOTICE, SECTION_STATCACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  enumerate:        %u", FETCH(statcache_enumerate));
    print_line(log, fd, LOG_NOTICE, SECTION_STATCACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  has_child:        %u", FETCH(statcache_has_child));
    print_line(log, fd, LOG_NOTICE, SECTION_STATCACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  delete_older:     %u", FETCH(statcache_delete_older));
    print_line(log, fd, LOG_NOTICE, SECTION_STATCACHE_OUTPUT, str);
    snprintf(str, MAX_LINE_LEN, "  prune:            %u", FETCH(statcache_prune));
    print_line(log, fd, LOG_NOTICE, SECTION_STATCACHE_OUTPUT, str);
}

void print_stats(void) {
    bool log = true;
    dump_stats(log, NULL);
}

void binding_busyness_stats(void) {
    unsigned long count = 0;
    const unsigned long large_busyness = 144000; // roughly 10 small get/puts per minute plus propfinds
    const unsigned long medium_busyness = 14400; // 1 get/put per minute

    // Weight the items by resource intensiveness (Just a swag at this point)
    count += FETCH(propfind_negative_cache);
    count += (FETCH(propfind_progressive_cache) * 2);
    count += (FETCH(propfind_complete_cache) * 8);
    count += FETCH(filecache_get_304_count);
    count += (FETCH(filecache_get_xxsm_count) * 2);
    count += (FETCH(filecache_get_xsm_count) * 2);
    count += (FETCH(filecache_get_sm_count) * 3);
    count += (FETCH(filecache_get_med_count) * 4);
    count += (FETCH(filecache_get_lg_count) * 6);
    count += (FETCH(filecache_get_xlg_count) * 8);
    count += (FETCH(filecache_put_xxsm_count) * 2);
    count += (FETCH(filecache_put_xsm_count) * 2);
    count += (FETCH(filecache_put_sm_count) * 3);
    count += (FETCH(filecache_put_med_count) * 4);
    count += (FETCH(filecache_put_lg_count) * 6);
    count += (FETCH(filecache_put_xlg_count) * 8);
    if (count > large_busyness) {
        log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "site_stats: large site by binding by busyness %lu (> %lu)",
            count, large_busyness);
    }
    else if (count > medium_busyness) {
        log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "site_stats: medium site by binding by busyness %lu (%lu - %lu)",
            count, medium_busyness, large_busyness);
    }
    else {
        log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "site_stats: small site by binding busyness %lu (< %lu)",
            count, medium_busyness);
    }
    // busyiness stats are only valid over a defined interval, so clear them since a new interval starts
    CLEAR(propfind_negative_cache);
    CLEAR(propfind_progressive_cache);
    CLEAR(propfind_complete_cache);
    CLEAR(filecache_get_304_count);
    CLEAR(filecache_get_xxsm_count);
    CLEAR(filecache_get_xsm_count);
    CLEAR(filecache_get_sm_count);
    CLEAR(filecache_get_med_count);
    CLEAR(filecache_get_lg_count);
    CLEAR(filecache_get_xlg_count);
    CLEAR(filecache_put_xxsm_count);
    CLEAR(filecache_put_xsm_count);
    CLEAR(filecache_put_sm_count);
    CLEAR(filecache_put_med_count);
    CLEAR(filecache_put_lg_count);
    CLEAR(filecache_put_xlg_count);
}
