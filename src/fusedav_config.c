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

#include <glib.h>

#include "fusedav.h"
#include "fusedav_config.h"
#include "log.h"
#include "log_sections.h"

// GError mechanisms
G_DEFINE_QUARK(FUSEDAV_CONFIG, fusedav_config)

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

enum {
     KEY_HELP,
     KEY_VERSION,
};

#define FUSEDAV_OPT(t, p, v) { t, offsetof(struct fusedav_config, p), v }

static struct fuse_opt fusedav_opts[] = {
    // [ProtocolAndPerformance]
    FUSEDAV_OPT("progressive_propfind",           progressive_propfind, true),
    FUSEDAV_OPT("refresh_dir_for_file_stat",      refresh_dir_for_file_stat, true),
    FUSEDAV_OPT("grace",                          grace, true),
    FUSEDAV_OPT("singlethread",                   singlethread, true),
    FUSEDAV_OPT("cache_uri=%s",                   cache_uri, 0),
    // [Authenticate]
    FUSEDAV_OPT("username=%s",                    username, 0),
    FUSEDAV_OPT("password=%s",                    password, 0),
    FUSEDAV_OPT("ca_certificate=%s",              ca_certificate, 0),
    FUSEDAV_OPT("client_certificate=%s",          client_certificate, 0),
    // [LogAndProcess]
    FUSEDAV_OPT("nodaemon",                       nodaemon, true),
    FUSEDAV_OPT("cache_path=%s",                  cache_path, 0),
    FUSEDAV_OPT("run_as_uid=%s",                  run_as_uid, 0),
    FUSEDAV_OPT("run_as_gid=%s",                  run_as_gid, 0),
    FUSEDAV_OPT("verbosity=%d",                   verbosity, 5),
    FUSEDAV_OPT("section_verbosity=%s",           section_verbosity, 0),
    // Config
    FUSEDAV_OPT("config_file=%s",                 config_file, 0),

    // If we have an old version of titan and a new version of fusedav when it
    // gets restarted, we need to handle these old variables to prevent fuse startup error
    FUSEDAV_OPT("ignoreutimens",                  dummy1, true),
    FUSEDAV_OPT("ignorexattr",                    dummy1, true),
    FUSEDAV_OPT("dir_mode=%o",                    dummy2, 0),
    FUSEDAV_OPT("file_mode=%o",                   dummy2, 0),
    FUSEDAV_OPT("client_certificate_password=%s", dummy3, 0),

    FUSE_OPT_KEY("-V",             KEY_VERSION),
    FUSE_OPT_KEY("--version",      KEY_VERSION),
    FUSE_OPT_KEY("-h",             KEY_HELP),
    FUSE_OPT_KEY("--help",         KEY_HELP),
    FUSE_OPT_KEY("-?",             KEY_HELP),
    FUSE_OPT_END
};

static void print_config(struct fusedav_config *config) {
    log_print(LOG_DEBUG, SECTION_FUSEDAV_CONFIG, "CONFIG:");
    log_print(LOG_DEBUG, SECTION_FUSEDAV_CONFIG, "progressive_propfind %d", config->progressive_propfind);
    log_print(LOG_DEBUG, SECTION_FUSEDAV_CONFIG, "refresh_dir_for_file_stat %d", config->refresh_dir_for_file_stat);
    log_print(LOG_DEBUG, SECTION_FUSEDAV_CONFIG, "grace %d", config->grace);
    log_print(LOG_DEBUG, SECTION_FUSEDAV_CONFIG, "singlethread %d", config->singlethread);
    log_print(LOG_DEBUG, SECTION_FUSEDAV_CONFIG, "cache_uri %s", config->cache_uri);

    // We could set these two, but they are NULL by default, so don't know how to put that in the config file
    log_print(LOG_DEBUG, SECTION_FUSEDAV_CONFIG, "username %s", config->username);
    log_print(LOG_DEBUG, SECTION_FUSEDAV_CONFIG, "password %s", config->password);

    log_print(LOG_DEBUG, SECTION_FUSEDAV_CONFIG, "ca_certificate %s", config->ca_certificate);
    log_print(LOG_DEBUG, SECTION_FUSEDAV_CONFIG, "client_certificate %s", config->client_certificate);
    log_print(LOG_DEBUG, SECTION_FUSEDAV_CONFIG, "nodaemon %d", config->nodaemon);
    log_print(LOG_DEBUG, SECTION_FUSEDAV_CONFIG, "cache_path %s", config->cache_path);
    log_print(LOG_DEBUG, SECTION_FUSEDAV_CONFIG, "run_as_uid %s", config->run_as_uid);
    log_print(LOG_DEBUG, SECTION_FUSEDAV_CONFIG, "run_as_gid %s", config->run_as_gid);
    log_print(LOG_DEBUG, SECTION_FUSEDAV_CONFIG, "verbosity %d", config->verbosity);
    log_print(LOG_DEBUG, SECTION_FUSEDAV_CONFIG, "section_verbosity %s", config->section_verbosity);

    // These are not subject to change by the parse config method
    log_print(LOG_DEBUG, SECTION_FUSEDAV_CONFIG, "uri: %s", config->uri);
    log_print(LOG_DEBUG, SECTION_FUSEDAV_CONFIG, "cache %p", config->cache);
    log_print(LOG_DEBUG, SECTION_FUSEDAV_CONFIG, "config_file %s", config->config_file);

}

/* fusedav.conf looks something like:
    [ProtocolAndPerformance]
    progressive_propfind=true
    refresh_dir_for_file_stat=true
    grace=true
    singlethread=false
    cache_uri=http://50.57.148.118:10061/fusedav-peer-cache

    [Authenticate]
    ca_certificate=/etc/pki/tls/certs/ca-bundle.crt
    client_certificate=/srv/bindings/6f7a106722f74cc7bd96d4d06785ed78/certs/binding.pem

    [LogAndProcess]
    nodaemon=false
    cache_path=/srv/bindings/6f7a106722f74cc7bd96d4d06785ed78/cache
    run_as_uid=6f7a106722f74cc7bd96d4d06785ed78
    run_as_gid=6f7a106722f74cc7bd96d4d06785ed78
    verbosity=5
    section_verbosity=0
*/

void parse_configs(struct fusedav_config *config, GError **gerr) {

    #define BOOL 0
    #define INT 1
    #define STRING 2
    #define keytuple(group, key, type) {#group, #key, offsetof(struct fusedav_config, key), type}

    struct key_value_dest_s {
        const char *group;
        const char *key;
        const int offset;
        const int type;
    };

    GKeyFile *keyfile;
    GError *tmpgerr = NULL;
    bool bret;

    /* Groups are: FileAttributes, ProtocolAndPerformance, Authenticate, LogAndProcess */

    static const struct key_value_dest_s config_entries[] = {
        keytuple(ProtocolAndPerformance, progressive_propfind, BOOL),
        keytuple(ProtocolAndPerformance, refresh_dir_for_file_stat, BOOL),
        keytuple(ProtocolAndPerformance, grace, BOOL),
        keytuple(ProtocolAndPerformance, singlethread, BOOL),
        keytuple(ProtocolAndPerformance, cache_uri, STRING),
        keytuple(Authenticate, ca_certificate, STRING),
        keytuple(Authenticate, client_certificate, STRING),
        keytuple(LogAndProcess, nodaemon, BOOL),
        keytuple(LogAndProcess, cache_path, STRING),
        keytuple(LogAndProcess, run_as_uid, STRING),
        keytuple(LogAndProcess, run_as_gid, STRING),
        keytuple(LogAndProcess, verbosity, INT),
        keytuple(LogAndProcess, section_verbosity, STRING),
        {NULL, NULL, 0, 0}
        };

    print_config(config);

    // JB FIX ME!
    // Step one: make sure this new version of fusedav is running on all mounts before merging
    //           changes to titan and the mount file. If the mount file is updated to include
    //           config_file as an option, the version of fusedav before this one will barf
    //           since it's not a known option.
    // Step two: merge changes to titan including config file
    // Proviso:  ultimately, we want to ensure there is a config file, and err if one is not present
    //           Until titan is updated to include fusedav in the .mount file, ignore errors
    //           from non-existant config files

    // Bail for now if we don't have a config file
    if (config->config_file == NULL) {
        log_print(LOG_NOTICE, SECTION_FUSEDAV_CONFIG, "parse_configs: config_file is null");
        return;
    }

    log_print(LOG_INFO, SECTION_FUSEDAV_CONFIG, "parse_configs: file %s", config->config_file);

    /* Set up the key file stuff */

    keyfile = g_key_file_new();

    bret = g_key_file_load_from_file(keyfile, config->config_file, G_KEY_FILE_NONE, &tmpgerr);
    // g_key_file_load_from_file does not seem to set error on null file
    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "parse_configs: Error on load_from_file");
        return;
    } else if (bret == FALSE) {
        g_set_error(gerr, fusedav_config_quark(), ENOENT, "parse_configs: Error on load_from_file");
        return;
    }

    /* Config, Certificate, and Log args */

    /* These populate the config structure */

    for (int idx = 0; config_entries[idx].key != NULL; idx++) {
        union type_convert_u {
            bool bvalue;
            int ivalue;
            char *svalue;
            void *vvalue;
        } uvalue;

        int type = config_entries[idx].type;
        int size;
        void *field;

        // We only have three types, bool, int, and char *
        size = (type == BOOL) ? sizeof(bool) : (type == INT) ? sizeof(int) : sizeof(char *);
        field = (void *)((unsigned long)config + (unsigned long)config_entries[idx].offset);
        if (type == BOOL) {
            uvalue.bvalue = g_key_file_get_boolean(keyfile, config_entries[idx].group, config_entries[idx].key, &tmpgerr);
        }
        else if (type == INT) {
            uvalue.ivalue = g_key_file_get_integer(keyfile, config_entries[idx].group, config_entries[idx].key, &tmpgerr);
        }
        else if (type == STRING) {
            uvalue.svalue = g_key_file_get_string(keyfile, config_entries[idx].group, config_entries[idx].key, &tmpgerr);
        }

        // fuse actually uses a sscanf to populate fields when using the "...=%d" specifiers we see
        // fusedav_opts above. The bools never specify a specifier (e.g. %d), but it seems are given
        // values via *(int *), which seems like it would break a lot of stuff, since bools only take 1 byte.
        // Since scanf is barely more type-safe than memcpy, and it can't accommodate a bool,
        // let's leave it as it is for now. We currently only have strings and bools, and even with ints,
        // this would be preferable for dealing with bools.
        if (tmpgerr == NULL) {
            memcpy(field, &uvalue.vvalue, size);
        }
        else {
            log_print(LOG_NOTICE, SECTION_FUSEDAV_CONFIG, "parse_config: error on %s : %s", config_entries[idx].key, tmpgerr->message);
            g_clear_error(&tmpgerr);
        }

    }

    g_key_file_free(keyfile);

    print_config(config);

    return;
}

