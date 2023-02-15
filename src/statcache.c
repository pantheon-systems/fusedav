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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>

#include "statcache.h"
#include "fusedav.h"
#include "log.h"
#include "log_sections.h"
#include "bloom-filter.h"
#include "util.h"
#include "stats.h"
#include "fusedav-statsd.h"

// The version of the data stored in the stat cache
const uint64_t STAT_CACHE_DATA_VERSION = 2;
static uint64_t data_version = 0;

static pthread_mutex_t counter_mutex = PTHREAD_MUTEX_INITIALIZER;
// Define and initialize pfsamplerate, which will be used across files
const float pfsamplerate = 0.1;

struct stat_cache_entry {
    const char *key;
    const struct stat_cache_value *value;
};

// GError mechanism. The only gerrors we return from statcache are leveldb errors
static G_DEFINE_QUARK(LDB, leveldb)

unsigned long stat_cache_get_local_generation(void) {
    static unsigned long counter = 0;
    unsigned long ret;

    BUMP(statcache_local_gen);

    pthread_mutex_lock(&counter_mutex);
    if (counter == 0) {
        // Top 40 bits for the timestamp. Bottom 24 bits for the counter.
        // Will be safe for at least a couple hundred years.
        counter = time(NULL);
        //log_print(LOG_DEBUG, SECTION_STATCACHE_DEFAULT, "Pre-shift counter: %lu", counter);
        counter <<= 24;
        //log_print(LOG_DEBUG, SECTION_STATCACHE_DEFAULT, "Initialized counter: %lu", counter);
    }
    ret = ++counter;
    pthread_mutex_unlock(&counter_mutex);
    log_print(LOG_DEBUG, SECTION_STATCACHE_DEFAULT, "stat_cache_get_local_generation: %lu", ret);
    return ret;
}

int print_stat(struct stat *stbuf, const char *title, const char *path) {
    log_print(LOG_DEBUG, SECTION_STATCACHE_OUTPUT, "stat: %s :: %s", title, path);
    log_print(LOG_DEBUG, SECTION_STATCACHE_OUTPUT, "  .st_mode=%04o", stbuf->st_mode);
    log_print(LOG_DEBUG, SECTION_STATCACHE_OUTPUT, "  .st_nlink=%ld", stbuf->st_nlink);
    log_print(LOG_DEBUG, SECTION_STATCACHE_OUTPUT, "  .st_uid=%d", stbuf->st_uid);
    log_print(LOG_DEBUG, SECTION_STATCACHE_OUTPUT, "  .st_gid=%d", stbuf->st_gid);
    log_print(LOG_DEBUG, SECTION_STATCACHE_OUTPUT, "  .st_size=%ld", stbuf->st_size);
    log_print(LOG_DEBUG, SECTION_STATCACHE_OUTPUT, "  .st_blksize=%ld", stbuf->st_blksize);
    log_print(LOG_DEBUG, SECTION_STATCACHE_OUTPUT, "  .st_blocks=%ld", stbuf->st_blocks);
    log_print(LOG_DEBUG, SECTION_STATCACHE_OUTPUT, "  .st_atime=%ld", stbuf->st_atime);
    log_print(LOG_DEBUG, SECTION_STATCACHE_OUTPUT, "  .st_mtime=%ld", stbuf->st_mtime);
    log_print(LOG_DEBUG, SECTION_STATCACHE_OUTPUT, "  .st_ctime=%ld", stbuf->st_ctime);
    return E_SC_SUCCESS;
}

void stat_cache_value_free(struct stat_cache_value *value) {
    leveldb_free(value);
}

// Allocates a new string.
static char *path2key(const char *path, bool prefix) {
    char *key = NULL;
    unsigned int depth = 0;
    size_t pos = 0;
    bool slash_found = false;
    size_t last_slash_pos = 0;

    BUMP(statcache_path2key);

    if (prefix)
        ++depth;

    while (path[pos]) {
        if (path[pos] == '/') {
            ++depth;
            last_slash_pos = pos;
            slash_found = true;
        }
        ++pos;
    }

    // If we indicated a prefix, and found a slash in the trailing position,
    // we counted it for depth, but shouldn't have. So decrement the depth.
    // Also, since we already have a slash on the end, don't add another one.
    // This should only be the case for the root directory
    if (prefix && slash_found && last_slash_pos == pos - 1) {
        depth--;
        asprintf(&key, "%u%s", depth, path);
    }
    // If we have a prefix and the string doesn't already end in a slash, add one
    else if (prefix) {
        asprintf(&key, "%u%s/", depth, path);
    }
    else {
        asprintf(&key, "%u%s", depth, path);
    }

    log_print(LOG_DEBUG, SECTION_STATCACHE_DEFAULT, "path2key: %s, %i, %s", path, prefix, key);

    return key;
}

// Does *not* allocate a new string.
static const char *key2path(const char *key) {
    size_t pos = 0;

    BUMP(statcache_key2path);

    while (key[pos]) {
        if (key[pos] == '/')
            return key + pos;
        ++pos;
    }
    return NULL;
}

// As we change the size and content of the data we store in the stat cache, we
// track which version this instantiation is using.
// As the cache gets deleted and recreated over time, earlier version of data
// get deleted, and new versions inserted
// Get the data version out of the cache
static uint64_t stat_cache_data_version_get(stat_cache_t *cache, GError **gerr){
    const char *funcname = "stat_cache_data_version_get";
    leveldb_readoptions_t *options;
    const char *key = "data_version";
    char *errptr = NULL;
    uint64_t *value = NULL;
    uint64_t ret;
    size_t vallen;

    options = leveldb_readoptions_create();
    leveldb_readoptions_set_fill_cache(options, false);
    value = (uint64_t *) leveldb_get(cache, options, key, strlen(key) + 1, &vallen, &errptr);
    leveldb_readoptions_destroy(options);

    if (errptr != NULL || inject_error(statcache_error_data_version_get)) {
        g_set_error (gerr, leveldb_quark(), E_SC_LDBERR, "%s: leveldb_get error: %s", funcname, errptr ? errptr : "inject-error");
        free(errptr);
        free(value);
        log_print(LOG_ALERT, SECTION_STATCACHE_CACHE, "%s: leveldb_get error, kill fusedav process", funcname);
        kill(getpid(), SIGTERM);
        return 0;
    }

    if (value == NULL) {
        log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "%s: no data version detected for %s.", funcname, key);
        return 0;
    }

    ret = *value;

    log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "%s: returning data version %lu for %s.", funcname, ret, key);

    free(value);
    return ret;
}

static void stat_cache_data_version_set(stat_cache_t *cache, const uint64_t data_ver, GError **gerr){
    const char *funcname = "stat_cache_data_version_set";
    leveldb_writeoptions_t *options;
    const char *key = "data_version";
    char *errptr = NULL;

    options = leveldb_writeoptions_create();
    leveldb_put(cache, options, key, strlen(key) + 1, (const char *) &data_ver, sizeof(uint64_t), &errptr);
    leveldb_writeoptions_destroy(options);

    if (errptr != NULL || inject_error(statcache_error_data_version_set)) {
        g_set_error (gerr, leveldb_quark(), E_SC_LDBERR, "%s: leveldb_set error: %s", funcname, errptr ? errptr : "inject-error");
        free(errptr);
        log_print(LOG_ALERT, SECTION_STATCACHE_CACHE, "%s: leveldb_set error, kill fusedav process", funcname);
        kill(getpid(), SIGTERM);
        return;
    }

    log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "%s: put data version %lu.", funcname, data_ver);

    return;
}

static stat_cache_t *gcache; // Save off pointer to cache for stat_cache_walk

void stat_cache_open(stat_cache_t **cache, struct stat_cache_supplemental *supplemental, char *cache_path, GError **gerr) {
    const char *funcname = "stat_cache_open";
    char *errptr = NULL;
    char storage_path[PATH_MAX];
    bool exists;
    GError *subgerr = NULL;

    BUMP(statcache_open);

    // Check that a directory is set.
    if (!cache_path || inject_error(statcache_error_cachepath)) {
        g_set_error (gerr, leveldb_quark(), EINVAL, "%s: no cache path specified.", funcname);
        return;
    }

    snprintf(storage_path, PATH_MAX, "%s/leveldb", cache_path);

    // Note if the cache does or doesn't exist
    // This will be used to help set the version of the data in the cache
    if (access(storage_path, F_OK) == -1) {
        // Cache does not exist, will be created.
        exists = false;
    }
    else {
        exists = true;
    }

    supplemental->options = leveldb_options_create();

    // Initialize LevelDB's LRU cache.
    supplemental->lru = NULL;
    //supplemental->lru = leveldb_cache_create_lru(5 * 1048576); // 5MB
    //leveldb_options_set_cache(supplemental->options, supplemental->lru);

    // Create the database if missing.
    leveldb_options_set_create_if_missing(supplemental->options, true);
    leveldb_options_set_error_if_exists(supplemental->options, false);

    // Use a fusedav logger.
    leveldb_options_set_info_log(supplemental->options, NULL);

    *cache = leveldb_open(supplemental->options, storage_path, &errptr);
    gcache = *cache; // save off pointer to cache for stat_cache_walk
    if (errptr || inject_error(statcache_error_openldb)) {
        g_set_error (gerr, leveldb_quark(), E_SC_LDBERR, "%s: Error opening db; %s.", funcname, errptr ? errptr : "inject-error");
        free(errptr);
        return;
    }

    // If this cache already has a data_version entry, use it.
    // If this cache is newly created, it is empty and all new data will be of the latest version
    // If this is cache already exists and doesn't have a data_version entry, it must have been created with
    // an earlier version of fusedav which didn't have a data version, so assume version 1.
    if (exists) {
        // Get the version of the data in the cache
        // If it doesn't exist, assume 1.0, the original version
        log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "%s: Cache exists, getting data version", funcname);
        data_version = stat_cache_data_version_get(*cache, &subgerr);
        if (subgerr) {
            g_propagate_prefixed_error(gerr, subgerr, "%s: ", funcname);
            return;
        }
        if (data_version == 0) {
            data_version = 1;
            log_print(LOG_NOTICE, SECTION_STATCACHE_CACHE, 
                    "%s: No data version entry detected, using %d", funcname, data_version);
        }
    }
    else {
        // If the cache is empty, then all data inserted will be the version indicated
        // by this version of fusedav
        log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "%s: Cache does not exist, using new data version %d", funcname);
        data_version = STAT_CACHE_DATA_VERSION;
    }

    log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "%s: Using data version %d", funcname, data_version);

    stat_cache_data_version_set(*cache, data_version, &subgerr);
    if (subgerr) {
        g_propagate_prefixed_error(gerr, subgerr, "%s: ", funcname);
        return;
    }

    return;
}

void stat_cache_close(stat_cache_t *cache, struct stat_cache_supplemental supplemental) {

    BUMP(statcache_close);

    if (cache != NULL) {
        leveldb_close(cache);
        log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "stat_cache_close: closed leveldb");
    }
    if (supplemental.options != NULL) {
        leveldb_options_destroy(supplemental.options);
        log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "stat_cache_close: leveldb_options_destroy");
    }
    if (supplemental.lru != NULL) {
        leveldb_cache_destroy(supplemental.lru);
        log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "stat_cache_close: leveldb_cache_destroy");
    }
    return;
}

struct stat_cache_value *stat_cache_value_get(stat_cache_t *cache, const char *path, bool skip_freshness_check, GError **gerr) {
    struct stat_cache_value *value = NULL;
    GError *tmpgerr = NULL;
    char *key;
    leveldb_readoptions_t *options;
    size_t vallen;
    char *errptr = NULL;

    BUMP(statcache_value_get);

    key = path2key(path, false);

    log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "stat_cache_value_get: key %s", key);

    options = leveldb_readoptions_create();
    leveldb_readoptions_set_fill_cache(options, false);
    value = (struct stat_cache_value *) leveldb_get(cache, options, key, strlen(key) + 1, &vallen, &errptr);
    leveldb_readoptions_destroy(options);
    free(key);

    if (errptr != NULL || inject_error(statcache_error_getldb)) {
        g_set_error (gerr, leveldb_quark(), E_SC_LDBERR, "stat_cache_value_get: leveldb_get error: %s", errptr ? errptr : "inject-error");
        free(errptr);
        free(value);
        log_print(LOG_ALERT, SECTION_STATCACHE_CACHE, "stat_cache_value_get: leveldb_get error, kill fusedav process");
        kill(getpid(), SIGTERM);
        return NULL;
    }

    /*  We can miss in the cache... */
    if (value == NULL) {
        log_print(LOG_INFO, SECTION_STATCACHE_CACHE, "stat_cache_value_get: miss on path: %s", path);
        stats_counter("statcache_miss", 1, pfsamplerate);
        return NULL;
    }
    // If this is a negative entry, we need to return the value so the entry can be processed
    else if (value->st.st_mode == 0) {
        log_print(LOG_INFO, SECTION_STATCACHE_CACHE, "stat_cache_value_get: negative entry on path: %s", path);
        stats_counter("statcache_negative_entry", 1, pfsamplerate);
        print_stat(&value->st, "stat_cache_value_get", path);
        return value;
    }

    if (vallen != sizeof(struct stat_cache_value)) {
        g_set_error (gerr, leveldb_quark(), E_SC_LDBERR, "stat_cache_value_get: Length %lu is not expected length %lu.", vallen, sizeof(struct stat_cache_value));
        free(errptr);
        free(value);
        return NULL;
    }

    /*  If we're doing a freshness check, we can return fresh or stale ... */
    if (!skip_freshness_check) {
        time_t current_time = time(NULL);
        time_t time_since;

        // First, check against the stat item itself.
        //log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "Current time: %lu", current_time);
        // How long has it been since the item was updated
        time_since = current_time - value->updated;

        // Keep stats for each second 0-6, then bucket everything over 6
        stats_histo("sc_value_get", time_since, 6, pfsamplerate);
        if (time_since > STAT_CACHE_NEGATIVE_TTL) {
            char *directory;
            time_t directory_updated;

            log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "stat_cache_value_get: Stat entry %s is %lu seconds old.", 
                    path, time_since);

            // If that's too old, check the last update of the directory.
            directory = path_parent(path);
            if (directory == NULL) {
                log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "stat_cache_value_get: Stat entry for directory %s is NULL.", path);
                free(value);
                stats_counter("statcache_stale", 1, pfsamplerate);
                return NULL;
            }

            directory_updated = stat_cache_read_updated_children(cache, directory, &tmpgerr);
            if (tmpgerr) {
                g_propagate_prefixed_error(gerr, tmpgerr, "stat_cache_value_get: ");
                stats_counter("statcache_stale", 1, pfsamplerate);
                return NULL;
            }
            time_since = current_time - directory_updated;
            // Keep stats for each second 0-6, then bucket everything over 6
            stats_histo("sc_dir_update", time_since, 6, pfsamplerate);
            log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "stat_cache_value_get: Directory contents for %s are %lu seconds old.", 
                    directory, time_since);
            free(directory);
            if (time_since > STAT_CACHE_NEGATIVE_TTL) {
                log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, 
                        "stat_cache_value_get: Parent directory for %s is too old (%lu seconds).", 
                        path, time_since);
                free(value);
                stats_counter("statcache_stale", 1, pfsamplerate);
                return NULL;
            } else {
                stats_counter("statcache_fresh_dir", 1, pfsamplerate);
            }
        } else {
            stats_counter("statcache_fresh_file", 1, pfsamplerate);
        }
    }

    /* Hack alert!
     * Remove this code by 1 Jan 2015!
     * On doing a complete PROPFIND, the DAV:reponse we were resetting stat values
     * but not setting st_blocks, which remained zero. This got stored in the statcache.
     * Now and until the file modified, that zero value remains. This breaks programs
     * like "du" which rely on st_blocks. That bug is fixed in this set of commits in props.c,
     * but we need to fixup files which already have the issue.
     * At some point this code should become irrelevant if we rewrite all cache entries.
     */
    if (value->st.st_blocks == 0 && value->st.st_size > 0) {
        value->st.st_blocks = (value->st.st_size+511)/512;
    }

    /*  If we neither miss nor return stale, we 'hit'. E.g. 'fresh' is also a 'hit' */
    stats_counter("statcache_hit", 1, pfsamplerate);
    return value;
}

void stat_cache_updated_children(stat_cache_t *cache, const char *path, time_t timestamp, GError **gerr) {
    leveldb_writeoptions_t *options;
    char *key = NULL;
    char *errptr = NULL;

    BUMP(statcache_updated_ch);

    asprintf(&key, "updated_children:%s", path);

    options = leveldb_writeoptions_create();
    if (timestamp == 0)
        leveldb_delete(cache, options, key, strlen(key) + 1, &errptr);
    else
        leveldb_put(cache, options, key, strlen(key) + 1, (char *) &timestamp, sizeof(time_t), &errptr);
    leveldb_writeoptions_destroy(options);

    free(key);

    if (errptr != NULL || inject_error(statcache_error_childrenldb)) {
        g_set_error (gerr, leveldb_quark(), E_SC_LDBERR, "stat_cache_updated_children: leveldb_set error: %s", errptr ? errptr : "inject-error");
        free(errptr);
        log_print(LOG_ALERT, SECTION_STATCACHE_CACHE, "stat_cache_updated_children: leveldb_set error, kill fusedav process");
        kill(getpid(), SIGTERM);
        return;
    }

    return;
}

time_t stat_cache_read_updated_children(stat_cache_t *cache, const char *path, GError **gerr) {
    leveldb_readoptions_t *options;
    char *key = NULL;
    char *errptr = NULL;
    time_t *value = NULL;
    time_t ret;
    size_t vallen;

    BUMP(statcache_read_updated);

    asprintf(&key, "updated_children:%s", path);

    options = leveldb_readoptions_create();
    leveldb_readoptions_set_fill_cache(options, false);
    value = (time_t *) leveldb_get(cache, options, key, strlen(key) + 1, &vallen, &errptr);
    leveldb_readoptions_destroy(options);

    free(key);

    if (errptr != NULL || inject_error(statcache_error_readchildrenldb)) {
        g_set_error (gerr, leveldb_quark(), E_SC_LDBERR, "stat_cache_read_updated_children: leveldb_get error: %s", errptr ? errptr : "inject-error");
        free(errptr);
        free(value);
        log_print(LOG_ALERT, SECTION_STATCACHE_CACHE, "stat_cache_read_updated_children: leveldb_get error, kill fusedav process");
        kill(getpid(), SIGTERM);
        return 0;
    }

    if (value == NULL) return 0;

    ret = *value;

    log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "Children for directory %s were updated at timestamp %lu.", path, ret);

    free(value);
    return ret;
}

// Use atime to store the next time we want a propfind
time_t stat_cache_next_propfind(struct stat_cache_value value, const char *path) {
    static const char *funcname = "stat_cache_negative_entry";
    // Allow propfinds in first 5 seconds of creation of negative entry,
    // since modules often check for (non-)existence of file before creating it
    const time_t probation_delay = 5;
    time_t curtime;
    curtime = time(NULL);
    if (value.st.st_ctime + probation_delay > curtime) {
        log_print(LOG_INFO, SECTION_FUSEDAV_STAT, "%s: still within probation period %s; ctime: %lu; probation: %lu", 
                funcname, path, value.st.st_ctime, curtime);
        return curtime;
    } else {
        log_print(LOG_INFO, SECTION_FUSEDAV_STAT, "%s: outside probation period %s; ctime: %lu; probation: %lu; atime: %lu", 
                funcname, path, value.st.st_ctime, curtime, value.st.st_atime);
        return value.st.st_atime;
    }
}

// A negative entry is an item in the cache which represents a miss,
// so we can cache its non-existence and regulate how often
// we make a propfind request to the server to check if it has
// come into existence.
bool stat_cache_is_negative_entry(struct stat_cache_value value) {
    // The struct stat st gets zero'ed out when we put a negative entry in the cache.
    // If an extant item is put in the cache, at st_mode will be non-zero.
    // So use st_mode as our check for non-existence
    if (value.st.st_mode == 0) return true;
    else return false;
}

// We use st_mode == 0 to denote that the entry is a negative (non-existing) one
void stat_cache_negative_set(struct stat_cache_value *value) {
    value->st.st_mode = 0;
}

// We need to know if this access was from a propfind in order to
// correctly note when to next call propfind on a negative entry
void stat_cache_from_propfind(struct stat_cache_value *value, bool bvalue) {
    value->from_propfind = bvalue;
}

// Determine the next fibs value (if we've reached it)
// curvalue is always a fib
static int next_fibs(const int curvalue, const int idx) {
    // A negative entry will gradually wait longer and longer to retry until
    // about 10 minutes (610 seconds); then every 610 seconds thereafter
    static const int fibs[] = {0, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610};
    static const int fibs_len = sizeof(fibs) / sizeof(int);

    // If we're at the last element already, return that last indexed value
    // (It should never be greater than fibs_len - 1; just being careful)
    if (idx >= fibs_len - 1) return fibs[fibs_len - 1];

    // If an exact match, return the next indexed value
    if (curvalue == fibs[idx]) return fibs[idx + 1];

    // The sentinel
    return -1;
}

// Create or update a negative entry in the stat cache for a deleted or non-existent object
static void stat_cache_negative_entry(stat_cache_t *cache, const char *path, struct stat_cache_value *value, GError **gerr) {
    static const char *funcname = "stat_cache_negative_entry";
    struct stat_cache_value *existing = NULL;
    time_t curtime;
    GError *subgerr = NULL ;

    curtime = time(NULL);
    existing = stat_cache_value_get(cache, path, true, &subgerr);
    if (subgerr) {
        g_propagate_prefixed_error(gerr, subgerr, "%s: failed on stat_cache_get for %s", funcname, path);
        return;
    }

    if (existing) {
        log_print(LOG_INFO, SECTION_FUSEDAV_STAT, "%s: incrementing entry %s", funcname, path);
        // Keep mtime constant, equal to the time when the negative entry was created
        // atime then is incremented by the next fib
        if (stat_cache_is_negative_entry(*existing)) {
            log_print(LOG_INFO, SECTION_FUSEDAV_STAT, "%s: negative entry %s", funcname, path);
            if (value->from_propfind) {
                int curfib;
                int nextfib;
                int idx = 0;
                curfib = existing->st.st_atime - existing->st.st_mtime;
                nextfib = next_fibs(curfib, idx);
                while (nextfib == -1) {
                    idx++;
                    nextfib = next_fibs(curfib, idx);
                }

                // Reset mtime to the current atime, and atime to the nextfib increment
                value->st.st_mtime = existing->st.st_atime;
                value->st.st_atime += existing->st.st_atime + nextfib;
                // Make sure to pass through the existing ctime
                value->st.st_ctime = existing->st.st_ctime;
                log_print(LOG_INFO, SECTION_FUSEDAV_STAT, "%s: negative entry from propfind %s", funcname, path);
                log_print(LOG_DEBUG, SECTION_FUSEDAV_STAT, 
                        "%s: %s: negative entry from propfind; mode: %lu; atime: %lu; mtime: %lu", 
                        funcname, path, value->st.st_mode, value->st.st_atime, value->st.st_mtime);
            }
            else {
                // Just copy the st from existing to value
                value->st = existing->st;
                log_print(LOG_INFO, SECTION_FUSEDAV_STAT, 
                        "%s: %s: negative entry not from propfind; mode: %lu; atime: %lu; mtime: %lu", 
                        funcname, path, value->st.st_mode, value->st.st_atime, value->st.st_mtime);
            }
        } else {
            // We are creating a negative entry from a formerly positive one.
            // Likely the times have been zeroed out, so reset them
            value->st.st_mtime = curtime;
            value->st.st_ctime = curtime;
            value->st.st_atime = curtime + 1; // the next fib
        }
        free(existing);
    }
    else {
        // Access was attempted on a path which doesn't exist. Create a new negative entry
        log_print(LOG_INFO, SECTION_FUSEDAV_STAT, "%s: creating entry %s", funcname, path);
        value->st.st_mtime = curtime;
        value->st.st_ctime = curtime;
        value->st.st_atime = curtime + 1; // the next fib
    }

    // Check for error and return
    if (subgerr) {
        g_propagate_prefixed_error(gerr, subgerr, "%s: failed setting new negative entry for %s", funcname, path);
    }

    log_print(LOG_DEBUG, SECTION_FUSEDAV_STAT, "%s: %s: mode: %lu; atime: %lu; mtime: %lu", 
            funcname, path, value->st.st_mode, value->st.st_atime, value->st.st_mtime);

    return;
}

void stat_cache_value_set(stat_cache_t *cache, const char *path, struct stat_cache_value *value, GError **gerr) {
    static const char *funcname = "stat_cache_value_set";
    leveldb_writeoptions_t *options;
    GError *subgerr = NULL ;
    char *errptr = NULL;
    char *key;

    if (path == NULL) {
        log_print(LOG_NOTICE, SECTION_STATCACHE_CACHE, "%s: input path is null", funcname);
        return;
    }

    BUMP(statcache_value_set);

    assert(value);

    if (stat_cache_is_negative_entry(*value)) {
        // Update value with negative entry values
        stat_cache_negative_entry(cache, path, value, &subgerr);
        if (subgerr) {
            g_propagate_prefixed_error(gerr, subgerr, "%s: failed on stat_cache_negative_entry for %s", funcname, path);
            return;
        }
        log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "%s: negative_entry; %s (mode %04o: atime %lu: mtime %lu)",
            funcname, path, value->st.st_mode, value->st.st_atime, value->st.st_mtime);
    }

    value->updated = time(NULL);
    value->local_generation = stat_cache_get_local_generation();

    key = path2key(path, false);
    log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "%s: %s (mode %04o: size: %d; updated %lu: loc_gen %lu: atime %lu: mtime %lu)",
        funcname, key, value->st.st_mode, value->st.st_size, value->updated, value->local_generation, value->st.st_atime, 
        value->st.st_mtime);

    options = leveldb_writeoptions_create();
    leveldb_put(cache, options, key, strlen(key) + 1, (char *) value, sizeof(struct stat_cache_value), &errptr);
    leveldb_writeoptions_destroy(options);

    free(key);

    if (errptr != NULL || inject_error(statcache_error_setldb)) {
        g_set_error (gerr, leveldb_quark(), E_SC_LDBERR, "%s: leveldb_set error: %s", funcname, errptr ? errptr : "inject-error");
        free(errptr);
        log_print(LOG_ALERT, SECTION_STATCACHE_CACHE, "%s: leveldb_set error, kill fusedav process", funcname);
        kill(getpid(), SIGTERM);
        return;
    }

    return;
}

void stat_cache_delete(stat_cache_t *cache, const char *path, GError **gerr) {
    leveldb_writeoptions_t *options;
    char *key;
    char *errptr = NULL;

    BUMP(statcache_delete);

    key = path2key(path, false);

    log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "stat_cache_delete: %s", key);

    options = leveldb_writeoptions_create();
    leveldb_delete(cache, options, key, strlen(key) + 1, &errptr);
    leveldb_writeoptions_destroy(options);
    free(key);

    if (errptr != NULL || inject_error(statcache_error_deleteldb)) {
        g_set_error (gerr, leveldb_quark(), E_SC_LDBERR, "stat_cache_delete: leveldb_delete error: %s", errptr ? errptr : "inject-error");
        free(errptr);
        return;
    }

    log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "stat_cache_delete: exit %s", path);

    return;
}

void stat_cache_delete_parent(stat_cache_t *cache, const char *path, GError **gerr) {
    char *p;
    GError *tmpgerr = NULL;
    struct stat_cache_value value;

    BUMP(statcache_del_parent);

    // Zero-out structure; some fields we don't populate but want to be 0, e.g. st_atim.tv_nsec
    memset(&value, 0, sizeof(struct stat_cache_value));

    log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "stat_cache_delete_parent: %s", path);
    if ((p = path_parent(path))) {

        log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "stat_cache_delete_parent: deleting parent %s", p);

        stat_cache_negative_set(&value);
        stat_cache_value_set(cache, path, &value, &tmpgerr);
        if (tmpgerr) {
            g_propagate_prefixed_error(gerr, tmpgerr, "stat_cache_delete_parent: ");
        }
        else {
            stat_cache_updated_children(cache, p, time(NULL) - STAT_CACHE_NEGATIVE_TTL - 1, &tmpgerr);
            if (tmpgerr) {
                g_propagate_prefixed_error(gerr, tmpgerr, "stat_cache_delete_parent: ");
            }
        }
        free(p);
    }
    else {
        log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "stat_cache_delete_parent: not deleting parent, deleting child %s", path);
        stat_cache_negative_set(&value);
        stat_cache_value_set(cache, path, &value, &tmpgerr);
        if (tmpgerr) {
            g_propagate_prefixed_error(gerr, tmpgerr, "stat_cache_delete_parent: no parent path");
        }
        else {
            stat_cache_updated_children(cache, path, time(NULL) - STAT_CACHE_NEGATIVE_TTL - 1, &tmpgerr);
            if (tmpgerr) {
                g_propagate_prefixed_error(gerr, tmpgerr, "stat_cache_delete_parent: no parent path");
            }
        }
    }
    return;
}

static void stat_cache_iterator_free(struct stat_cache_iterator *iter) {

    BUMP(statcache_iter_free);

    leveldb_iter_destroy(iter->ldb_iter);
    leveldb_readoptions_destroy(iter->ldb_options);
    free(iter->key_prefix);
    free(iter);
}

static struct stat_cache_iterator *stat_cache_iter_init(stat_cache_t *cache, const char *path_prefix) {
    struct stat_cache_iterator *iter = NULL;

    BUMP(statcache_iter_init);

    iter = malloc(sizeof(struct stat_cache_iterator));
    iter->key_prefix = path2key(path_prefix, true); // Handles allocating the duplicate.
    iter->key_prefix_len = strlen(iter->key_prefix) + 1;

    log_print(LOG_DEBUG, SECTION_STATCACHE_ITER, "creating leveldb iterator for prefix %s", iter->key_prefix);
    iter->ldb_options = leveldb_readoptions_create();
    leveldb_readoptions_set_fill_cache(iter->ldb_options, false);
    iter->ldb_iter = leveldb_create_iterator(cache, iter->ldb_options);

    leveldb_iter_seek(iter->ldb_iter, iter->key_prefix, iter->key_prefix_len);

    return iter;
}

static struct stat_cache_entry *stat_cache_iter_current(struct stat_cache_iterator *iter) {
    struct stat_cache_entry *entry;
    const struct stat_cache_value *value;
    const char *key;
    size_t klen, vlen;

    BUMP(statcache_iter_current);

    assert(iter);

    // If we've gone beyond the end of the dataset, quit.
    if (!leveldb_iter_valid(iter->ldb_iter)) {
        return NULL;
    }

    key = leveldb_iter_key(iter->ldb_iter, &klen);
    log_print(LOG_DEBUG, SECTION_STATCACHE_ITER, "fetched key: %s", key);

    // If we've gone beyond the end of the prefix range, quit.
    // Use (iter->key_prefix_len - 1) to exclude the NULL at the prefix end.
    if (strncmp(key, iter->key_prefix, iter->key_prefix_len - 1) != 0) {
        log_print(LOG_DEBUG, SECTION_STATCACHE_ITER, "Key %s does not match prefix %s for %lu characters. Ending iteration.", key, iter->key_prefix, iter->key_prefix_len);
        return NULL;
    }

    value = (const struct stat_cache_value *) leveldb_iter_value(iter->ldb_iter, &vlen);

    entry = malloc(sizeof(struct stat_cache_entry));
    entry->key = key;
    entry->value = value;
    log_print(LOG_DEBUG, SECTION_STATCACHE_ITER, "iter_current: key = %s; value = %s", key, value);
    return entry;
}

static void stat_cache_iter_next(struct stat_cache_iterator *iter) {

    BUMP(statcache_iter_next);

    leveldb_iter_next(iter->ldb_iter);
}

/*
static void stat_cache_list_all(stat_cache_t *cache, const char *path) {
    leveldb_iterator_t *iter = NULL;
    leveldb_readoptions_t *options;
    const struct stat_cache_value *itervalue;
    struct stat_cache_value *value;
    size_t klen, vlen;
    const char *iterkey;
    char *key = path2key(path, true);

    options = leveldb_readoptions_create();
    iter = leveldb_create_iterator(cache, options);
    leveldb_readoptions_destroy(options);

    leveldb_iter_seek(iter, key, strlen(key) + 1);
    free(key);

    while (leveldb_iter_valid(iter)) {
        //log_print(LOG_DEBUG, SECTION_STATCACHE_DEFAULT, "Listing key: %s", leveldb_iter_key(iter, &klen));

        itervalue = (const struct stat_cache_value *) leveldb_iter_value(iter, &vlen);
        if (S_ISDIR(itervalue->st.st_mode)) {
            iterkey = leveldb_iter_key(iter, &klen);
            log_print(LOG_DEBUG, SECTION_STATCACHE_DEFAULT, "Listing directory: %s", iterkey);

            value = stat_cache_value_get(cache, key2path(iterkey));
            if (value) {
                log_print(LOG_DEBUG, SECTION_STATCACHE_DEFAULT, "Direct get mode: %04o", value->st.st_mode);
                free(value);
            }
        }

        leveldb_iter_next(iter);
    }

    leveldb_iter_destroy(iter);
}
*/

int stat_cache_enumerate(stat_cache_t *cache, const char *path_prefix, void (*f) (const char *path_prefix, const char *filename, void *user), void *user, bool force) {
    struct stat_cache_iterator *iter;
    struct stat_cache_entry *entry;
    unsigned found_entries = 0;

    BUMP(statcache_enumerate);

    log_print(LOG_DEBUG, SECTION_STATCACHE_ITER, "stat_cache_enumerate(%s)", path_prefix);

    //stat_cache_list_all(cache, path_prefix);
    if (!force) {
        time_t timestamp;
        time_t current_time;
        // Pass NULL for gerr; not tracking error, just zero return
        timestamp = stat_cache_read_updated_children(cache, path_prefix, NULL);

        if (timestamp == 0) {
            return -STAT_CACHE_NO_DATA;
        }

        // Check for cache values which are too old; but timestamp = 0 needs to trigger below
        current_time = time(NULL);
        if (current_time - timestamp > STAT_CACHE_NEGATIVE_TTL) {
            log_print(LOG_DEBUG, SECTION_STATCACHE_ITER, "cache value too old: %s %u", path_prefix, (unsigned)timestamp);
            return -STAT_CACHE_OLD_DATA;
        }
    }

    iter = stat_cache_iter_init(cache, path_prefix);
    log_print(LOG_DEBUG, SECTION_STATCACHE_ITER, "iterator initialized with prefix: %s", iter->key_prefix);

    while ((entry = stat_cache_iter_current(iter))) {
        log_print(LOG_DEBUG, SECTION_STATCACHE_ITER, "key: %s", entry->key);
        log_print(LOG_DEBUG, SECTION_STATCACHE_ITER, "fn: %s", entry->key + (iter->key_prefix_len - 1));
        // Ignore negative (non-existent) entries, those tagged with st_mode == 0
        if (entry->value->st.st_mode != 0) {
            f(path_prefix, entry->key + (iter->key_prefix_len - 1), user);
            ++found_entries;
        }
        free(entry);
        stat_cache_iter_next(iter);
    }
    stat_cache_iterator_free(iter);
    log_print(LOG_DEBUG, SECTION_STATCACHE_ITER, "Done iterating: %u items.", found_entries);

    if (found_entries == 0)
        return -STAT_CACHE_NO_DATA;

    return E_SC_SUCCESS;
}

// log_dirent_count is based on stat_cache_enumerate and ignores cache freshness.
unsigned log_dirent_count(stat_cache_t *cache, const char *path_prefix) {
    struct stat_cache_iterator *iter;
    struct stat_cache_entry *entry;
    unsigned found_entries = 0;

    // BUMP(statcache_enumerate);

    // log_print(LOG_DEBUG, SECTION_STATCACHE_ITER, "count_dir_entries(%s)", path_prefix);

    //stat_cache_list_all(cache, path_prefix);
    // if (!force) {
    //     time_t timestamp;
    //     time_t current_time;
    //     // Pass NULL for gerr; not tracking error, just zero return
    //     timestamp = stat_cache_read_updated_children(cache, path_prefix, NULL);

    //     if (timestamp == 0) {
    //         return -STAT_CACHE_NO_DATA;
    //     }

    //     // Check for cache values which are too old; but timestamp = 0 needs to trigger below
    //     current_time = time(NULL);
    //     if (current_time - timestamp > STAT_CACHE_NEGATIVE_TTL) {
    //         log_print(LOG_DEBUG, SECTION_STATCACHE_ITER, "cache value too old: %s %u", path_prefix, (unsigned)timestamp);
    //         return -STAT_CACHE_OLD_DATA;
    //     }
    // }

    iter = stat_cache_iter_init(cache, path_prefix);
    log_print(LOG_DEBUG, SECTION_STATCACHE_ITER, "iterator initialized with prefix: %s", iter->key_prefix);

    while ((entry = stat_cache_iter_current(iter))) {
        // log_print(LOG_NOTICE, SECTION_STATCACHE_ITER, "key: %s", entry->key);
        // log_print(LOG_NOTICE, SECTION_STATCACHE_ITER, "fn: %s", entry->key + (iter->key_prefix_len - 1));
        // Ignore negative (non-existent) entries, those tagged with st_mode == 0
        if (entry->value->st.st_mode != 0) {
            // f(path_prefix, entry->key + (iter->key_prefix_len - 1), user);
            ++found_entries;
        }
        free(entry);
        stat_cache_iter_next(iter);
    }
    stat_cache_iterator_free(iter);
    log_print(LOG_DEBUG, SECTION_STATCACHE_ITER, "Done iterating: %u items.", found_entries);

    // if (found_entries == 0)
    //     return -STAT_CACHE_NO_DATA;

    return found_entries;
}

void stat_cache_walk(void) {
    leveldb_readoptions_t *roptions;
    struct leveldb_iterator_t *iter;
    const struct stat_cache_value *itervalue;

    log_print(LOG_NOTICE, SECTION_STATCACHE_CACHE, "stat_cache_walk: starting: %p", gcache);

    roptions = leveldb_readoptions_create();
    leveldb_readoptions_set_fill_cache(roptions, false);
    iter = leveldb_create_iterator(gcache, roptions); // We've kept a pointer to cache for just this call
    leveldb_iter_seek_to_first(iter);
    for (; leveldb_iter_valid(iter); leveldb_iter_next(iter)) {
        size_t klen, vlen;
        bool negative_entry;
        char posneg[] = "positive";
        const char *iterkey = leveldb_iter_key(iter, &klen);
        itervalue = (const struct stat_cache_value *) leveldb_iter_value(iter, &vlen);
        negative_entry = stat_cache_is_negative_entry(*itervalue);
        if (negative_entry) strcpy(posneg, "negative");
        log_print(LOG_NOTICE, SECTION_STATCACHE_CACHE, "stat_cache_walk: iterkey = %s :: posneg: %s", iterkey, posneg);
    }
    leveldb_iter_destroy(iter);
    leveldb_readoptions_destroy(roptions);
    log_print(LOG_NOTICE, SECTION_STATCACHE_CACHE, "stat_cache_walk: exiting");
}

bool stat_cache_dir_has_child(stat_cache_t *cache, const char *path) {
    struct stat_cache_iterator *iter;
    struct stat_cache_entry *entry;
    bool has_children = false;

    BUMP(statcache_has_child);

    log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "stat_cache_dir_has_child(%s)", path);

    iter = stat_cache_iter_init(cache, path);
    while ((entry = stat_cache_iter_current(iter))) {
        // Ignore negative (non-existent) entries, those tagged with st_mode == 0
        if (entry->value->st.st_mode != 0) {
            has_children = true;
            log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "stat_cache_dir_has_child(%s); entry \'%s\'", path, entry->key);
            free(entry);
            break;
        }
        free(entry);
        stat_cache_iter_next(iter);
    }
    stat_cache_iterator_free(iter);

    return has_children;
}

void stat_cache_delete_older(stat_cache_t *cache, const char *path_prefix, unsigned long minimum_local_generation, GError **gerr) {
    struct stat_cache_iterator *iter;
    struct stat_cache_entry *entry;
    GError *tmpgerr = NULL;
    unsigned int deleted_entries = 0;
    struct stat_cache_value value;

    BUMP(statcache_delete_older);

    // Zero-out structure; some fields we don't populate but want to be 0, e.g. st_atim.tv_nsec
    memset(&value, 0, sizeof(struct stat_cache_value));

    log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "stat_cache_delete_older: %s", path_prefix);
    iter = stat_cache_iter_init(cache, path_prefix);
    while ((entry = stat_cache_iter_current(iter))) {
        // Not deleting, rather, inserting negative entries.
        if (entry->value->st.st_mode != 0) {
            log_print(LOG_DEBUG, SECTION_STATCACHE_CACHE, "stat_cache_delete_older: %s: min_gen %lu: loc_gen %lu",
                entry->key, minimum_local_generation, entry->value->local_generation);
            if (entry->value->local_generation < minimum_local_generation) {
                stat_cache_negative_set(&value);
                stat_cache_value_set(cache, key2path(entry->key), &value, &tmpgerr);
                if (tmpgerr) {
                    g_propagate_prefixed_error(gerr, tmpgerr, "stat_cache_delete_older: ");
                    free(entry);
                    stat_cache_iterator_free(iter);
                    return;
                }
                log_print(LOG_NOTICE, SECTION_STATCACHE_CACHE, "stat_cache_delete_older: %s: min_gen %lu: loc_gen %lu",
                    key2path(entry->key), minimum_local_generation, entry->value->local_generation);
                ++deleted_entries;
            }
        }
        free(entry);
        stat_cache_iter_next(iter);
    }
    stat_cache_iterator_free(iter);

    log_print(LOG_INFO, SECTION_STATCACHE_CACHE, "stat_cache_delete_older: calling stat_cache_prune on %s : deletedentries %u", path_prefix, deleted_entries);
    // Only prune if there are deleted entries; otherwise there's no work to do
    if (deleted_entries > 0) {
        bool first = false;
        stat_cache_prune(cache, first);
    }

    return;
}

void stat_cache_prune(stat_cache_t *cache, bool first) {
    // leveldb stuff
    leveldb_readoptions_t *roptions;
    leveldb_writeoptions_t *woptions;
    struct leveldb_iterator_t *iter;
    const char *iterkey;
    const char *key;
    char path[PATH_MAX];
    const struct stat_cache_value *itervalue;
    size_t klen, vlen;

    // bloom filter stuff
    bloomfilter_options_t *boptions;
    char *errptr = NULL;

    int pass = 0;
    int passes = 1; // passes will grow as we detect larger depths
    int depth;
    int max_depth = 0;
    const char *base_directory = "/";

    // Statistics
    int visited_entries = 0;
    unsigned long size_of_files = 0;
    const int large_count = 100000;
    const int medium_count = 10000;
    const unsigned long large_size = (10UL * 1024 * 1024 * 1024);
    const unsigned long medium_size = (5UL * 1024 * 1024 * 1024);
    int deleted_entries = 0;
    int issues = 0;
    clock_t elapsedtime;
    static unsigned int numcalls = 0;
    static unsigned long totaltime = 0; //

    BUMP(statcache_prune);

    elapsedtime = clock();

    log_print(LOG_DEBUG, SECTION_STATCACHE_PRUNE, "stat_cache_prune: enter");

    boptions = bloomfilter_init(0, NULL, 0, &errptr);
    if (boptions == NULL) {
        log_print(LOG_WARNING, SECTION_STATCACHE_PRUNE, "stat_cache_prune: failed to allocate bloom filter: %s", errptr);
        free(errptr);
        return;
    }

    // We need to make sure the base_directory is in the filter before continuing
    log_print(LOG_DEBUG, SECTION_STATCACHE_PRUNE, "stat_cache_prune: attempting base_directory %s)", base_directory);
    if (bloomfilter_add(boptions, base_directory, strlen(base_directory)) < 0) {
        log_print(LOG_WARNING, SECTION_STATCACHE_PRUNE, "stat_cache_prune: seed: error on ITERKEY: \'%s\')", path);
        return;
    }

    log_print(LOG_DEBUG, SECTION_STATCACHE_PRUNE, "stat_cache_prune: put base_directory %s in filter", base_directory);

    roptions = leveldb_readoptions_create();
    leveldb_readoptions_set_fill_cache(roptions, false);
    iter = leveldb_create_iterator(cache, roptions);

    // Entries are in alphabetical order, so 10 is before 6;
    // on the first pass, find the first depth less than 10, and process to the end;
    // on the second pass, process depth greater or equal to than 10 but less than 99;
    // on the second pass, process depth greater or equal to than 100 but less than 999;
    // on the second pass, process depth greater or equal to than 1000 but less than 9999;
    while (pass < passes) {

        log_print(LOG_DEBUG, SECTION_STATCACHE_PRUNE, "stat_cache_prune: Changing pass:%d (%d)", pass, passes);
        leveldb_iter_seek_to_first(iter);

        for (; leveldb_iter_valid(iter); leveldb_iter_next(iter)) {
            iterkey = leveldb_iter_key(iter, &klen);
            // I have encountered bad entries in stat cache during development;
            // armor against potential faults
            key = key2path(iterkey);
            if (key == NULL) {
                // If the iterkey is "data_version", it will fail the key2path test, so watch for it.
                // This signals that processing of regular stat cache entries is complete.
                // Other stat cache entries have paths in them and pass the key2path test, e.g.
                // fc:/path and updated_children:/path
                if (!strncmp(iterkey, "data_version", strlen("data_version"))) {
                    continue;
                }
                else {
                    log_print(LOG_NOTICE, SECTION_STATCACHE_PRUNE, "stat_cache_prune: ignoring malformed iterkey: %s", iterkey);
                    woptions = leveldb_writeoptions_create();
                    leveldb_delete(cache, woptions, iterkey, strlen(iterkey) + 1, &errptr);
                    leveldb_writeoptions_destroy(woptions);
                    ++issues;
                    continue;
                }
            }
            // We'll need to change path below, so we don't want it to be a part of iterkey.
            // Make a copy first.
            strncpy(path, key, PATH_MAX);
            log_print(LOG_DEBUG, SECTION_STATCACHE_PRUNE, "stat_cache_prune: ITERKEY: \'%s\' :: %s :: %s", iterkey, path, key);
            itervalue = (const struct stat_cache_value *) leveldb_iter_value(iter, &vlen);

            // We control what kinds of entries are in the leveldb db.
            // Those beginning with a number are stat cache entries and
            // will be alphabetically first. As soon as we find an entry that
            // strtol cannot turn into a number, we know we have passed beyond
            // the normal stat cache entries into something else (e.g. filecache).
            // However, we also have to handle "updated_children" entries. We
            // handle them separately below.
            errno = 0;
            depth = strtol(iterkey, NULL, 10);

            // @TODO seems not to set errno on returning 0
            if (depth == 0 /*&& errno != 0*/) {
                log_print(LOG_DEBUG, SECTION_STATCACHE_PRUNE, 
                        "stat_cache_prune: depth = 0; iterkey: %s; break:%d, %d", iterkey, depth, errno);
                break;
            }

            /* We need to handle paths which have up to 4096 directories in the path name.
             * (Note, the length of the path name itself, not the number of directories in a
             * particular subdirectory.)
             * Since we don't expect depths greater than 99, we avoid iterating again
             * when we know we don't have depths that great.
             * When max_depth crosses a boundary (10, 100, 1000), set it to the max
             * at that boundary (99, 999, 9999) to prevent continually calling this section.
             */
            if (depth > max_depth) {
                max_depth = depth;
                if (max_depth >= 1000) {
                    passes = 4;
                    max_depth = 9999;
                }
                else if (max_depth >= 100) {
                    passes = 3;
                    max_depth = 999;
                }
                else if (max_depth >= 10) {
                    passes = 2;
                    max_depth = 99;
                }
                log_print(LOG_DEBUG, SECTION_STATCACHE_PRUNE, "stat_cache_prune: New max_depth %d (%d :: %d %d)", max_depth, depth, pass, passes);
            }

            if ((pass == 0 && depth <= 9) || (pass == 1 && (depth >= 10 && depth <= 99)) ||
                (pass == 2 && (depth >= 100 && depth <= 999)) || (pass == 3 && depth >= 1000)) {

                char *parentpath;

                log_print(LOG_DEBUG, SECTION_STATCACHE_PRUNE, "stat_cache_prune: Pass %d (%d)", pass, passes);
                ++visited_entries;
                size_of_files += itervalue->st.st_size;

                // If base_directory is in the stat cache, we don't want to compare it
                // to its parent directory, find it absent in the filter, and remove base_directory
                if (strcmp(path, base_directory) == 0) {
                    log_print(LOG_DEBUG, SECTION_STATCACHE_PRUNE, "stat_cache_prune: path == base_directory");
                    continue;
                }

                parentpath = path_parent(path);
                log_print(LOG_DEBUG, SECTION_STATCACHE_PRUNE, "stat_cache_prune: path %s parent_path %s", path, parentpath);

                if (parentpath == NULL) {
                    log_print(LOG_NOTICE, SECTION_STATCACHE_PRUNE, "stat_cache_prune: ignoring errant entry \'%s\'", path);
                    ++issues;
                    continue;
                }

                if (bloomfilter_exists(boptions, parentpath, strlen(parentpath))) {
                    log_print(LOG_DEBUG, SECTION_STATCACHE_PRUNE, 
                            "stat_cache_prune: parent exists in bloom filter\'%s\'", parentpath);
                    // If the parent is in the filter, and this child is a directory, add it to
                    // the filter for iteration at the next depth
                    if (S_ISDIR(itervalue->st.st_mode)) {
                        log_print(LOG_DEBUG, SECTION_STATCACHE_PRUNE, "stat_cache_prune: add path to filter \'%s\')", path);
                        if (bloomfilter_add(boptions, path, strlen(path)) < 0) {
                            log_print(LOG_ERR, SECTION_STATCACHE_PRUNE, "stat_cache_prune: error on bloomfilter_add: \'%s\')", path);
                            ++issues;
                            break;
                        }
                    }
                    else {
                        // Remove negative entries on startup
                        if (first && itervalue->st.st_mode == 0) {
                            log_print(LOG_INFO, SECTION_STATCACHE_PRUNE, "stat_cache_prune: deleting negative entry \'%s\'", path);
                            stat_cache_delete(cache, path, NULL);
                        }
                    }
                }
                else {
                    struct stat_cache_value value;
                    // Zero-out structure; some fields we don't populate but want to be 0, e.g. st_atim.tv_nsec
                    memset(&value, 0, sizeof(struct stat_cache_value));
                    log_print(LOG_INFO, SECTION_STATCACHE_PRUNE, "stat_cache_prune: doesn't exist in bloom filter \'%s\'", parentpath);
                    ++deleted_entries;
                    log_print(LOG_INFO, SECTION_STATCACHE_PRUNE, "stat_cache_prune: setting negative entry \'%s\'", path);
                    stat_cache_negative_set(&value);
                    stat_cache_value_set(cache, path, &value, NULL);
                }
                free(parentpath);
            }
        }
        ++pass;
        log_print(LOG_DEBUG, SECTION_STATCACHE_PRUNE, "stat_cache_prune: updating pass %d", pass);
    }

    // Handle data_version entries
    leveldb_iter_seek(iter, "data_version", strlen("data_version") + 1);

    for (; leveldb_iter_valid(iter); leveldb_iter_next(iter)) {
        iterkey = leveldb_iter_key(iter, &klen);
        log_print(LOG_DEBUG, SECTION_STATCACHE_PRUNE, "DBG: stat_cache_prune: data_version: %s", iterkey);
        if (!strncmp(iterkey, "data_version", strlen("data_version"))) {
            const uint64_t *iterv;
            iterv = (const uint64_t *) leveldb_iter_value(iter, &vlen);
            log_print(LOG_DEBUG, SECTION_STATCACHE_PRUNE, "stat_cache_prune: data_version: %lu", *iterv);
            break;
        }

        // If we pass the last key which begins with data_version, move on
        if (strncmp(iterkey, "data_version", strlen("data_version"))) {
            log_print(LOG_DEBUG, SECTION_STATCACHE_PRUNE, "stat_cache_prune: passed data_version on %s", iterkey);
            break;
        }
    }

    // Handle updated_children entries
    leveldb_iter_seek(iter, "updated_children:", strlen("updated_children:") + 1);

    for (; leveldb_iter_valid(iter); leveldb_iter_next(iter)) {
        const char *basepath = NULL;
        iterkey = leveldb_iter_key(iter, &klen);

        // If we pass the last key which begins with updated_children:, we're done
        if (strncmp(iterkey, "updated_children:", strlen("updated_children:"))) {
            break;
        }
        ++visited_entries;
        // basepath is the "path" we use for the filter, it has "updated_children:" removed
        // If that path is in the filter, keep the updated_children entry; otherwise, delete
        // Unlike the processing above, we do not add to the filter, nor do we deal with
        // the parent path.
        basepath = strchr(iterkey, '/');

        // Bad entry. Log, delete from cache, continue
        if (basepath == NULL) {
            log_print(LOG_NOTICE, SECTION_STATCACHE_PRUNE, "stat_cache_prune: key error in updated_children entry: %s", iterkey);
            woptions = leveldb_writeoptions_create();
            leveldb_delete(cache, woptions, iterkey, strlen(iterkey) + 1, &errptr);
            leveldb_writeoptions_destroy(woptions);
            if (errptr != NULL) {
                log_print(LOG_ALERT, SECTION_STATCACHE_PRUNE, "stat_cache_prune: leveldb_delete error: %s", errptr);
                free(errptr);
            }
            ++issues;
            continue;
        }

        if (bloomfilter_exists(boptions, basepath, strlen(basepath))) {
            log_print(LOG_DEBUG, SECTION_STATCACHE_PRUNE, "stat_cache_prune: exists in bloom filter (basepath of)\'%s\'", iterkey);
        }
        else {
            log_print(LOG_NOTICE, SECTION_STATCACHE_PRUNE, "stat_cache_prune: updated_children: deleting \'%s\'", iterkey);
            ++deleted_entries;
            // We recreate the basics of stat_cache_delete here, since we can't call it directly
            // since it doesn't deal with keys with "updated_children:"
            // NB. We are not imitating stat_cache_negative_entry here
            woptions = leveldb_writeoptions_create();
            leveldb_delete(cache, woptions, iterkey, strlen(iterkey) + 1, &errptr);
            leveldb_writeoptions_destroy(woptions);
            if (errptr != NULL) {
                log_print(LOG_ALERT, SECTION_STATCACHE_PRUNE, "stat_cache_prune: leveldb_delete error: %s", errptr);
                free(errptr);
                ++issues;
            }
        }
    }

    leveldb_iter_destroy(iter);
    leveldb_readoptions_destroy(roptions);

    elapsedtime = clock() - elapsedtime;
    elapsedtime *= 1000;
    elapsedtime /= CLOCKS_PER_SEC;
    ++numcalls;
    totaltime += elapsedtime;
    log_print(LOG_NOTICE, SECTION_STATCACHE_PRUNE,
        "stat_cache_prune: visited %d cache entries; deleted %d; total_file_size is %lu;  had %d issues; elapsedtime %lu (%lu)",
        visited_entries, deleted_entries, size_of_files, issues, elapsedtime, totaltime / numcalls);
    if (visited_entries > large_count) {
        log_print(LOG_NOTICE, SECTION_STATCACHE_PRUNE, "site_stats: large site by file count %d (> %lu)",
            visited_entries, large_count);
    }
    else if (visited_entries > medium_count) {
        log_print(LOG_NOTICE, SECTION_STATCACHE_PRUNE, "site_stats: medium site by file count %d (%lu - %lu)",
            visited_entries, medium_count, large_count);
    }
    else {
        log_print(LOG_NOTICE, SECTION_STATCACHE_PRUNE, "site_stats: small site by file count %d (< %lu)",
            visited_entries, medium_count);
    }

    if (size_of_files > large_size) {
        log_print(LOG_NOTICE, SECTION_STATCACHE_PRUNE, "site_stats: large site by file size %.1f M (> %lu M)",
            size_of_files / (1024.0 * 1024.0), large_size / (1024 * 1024));
    }
    else if (size_of_files > medium_size) {
        log_print(LOG_NOTICE, SECTION_STATCACHE_PRUNE, "site_stats: medium site by file size %.1f M (%lu M - %lu M)",
            size_of_files / (1024.0 * 1024.0), medium_size / (1024 * 1024), large_size / (1024 * 1024));
    }
    else {
        log_print(LOG_NOTICE, SECTION_STATCACHE_PRUNE, "site_stats: small site by file size %.1f M (< %lu M)",
            size_of_files / (1024.0 * 1024.0), medium_size / (1024 * 1024));
    }
    bloomfilter_destroy(boptions);

    return;
}
