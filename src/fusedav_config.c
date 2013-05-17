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
#include <grp.h>
#include <pwd.h>
#include <glib.h>
#include <sys/prctl.h>
#include <curl/curl.h>

#include "fusedav.h"
#include "fusedav_config.h"
#include "log.h"
#include "log_sections.h"
#include "util.h"
#include "session.h"

// GError mechanisms
G_DEFINE_QUARK(FUSEDAV_CONFIG, fusedav_config)

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

extern struct fuse_operations dav_oper;

static int fusedav_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs) {
    struct fusedav_config *config = data;

    switch (key) {
    case FUSE_OPT_KEY_NONOPT:
        if (!config->uri) {
            config->uri = strdup(arg);
            return 0;
        }
        break;

    case KEY_HELP:
        fprintf(stderr,
                "usage: %s uri mountpoint [options]\n"
                "\n"
                "general options:\n"
                "    -o opt,[opt...]  mount options\n"
                "    -h   --help      print help\n"
                "    -V   --version   print version\n"
                "\n"
                "fusedav mount options:\n"
                "    Protocol and performance options:\n"
                "        -o progressive_propfind\n"
                "        -o refresh_dir_for_file_stat\n"
                "        -o grace\n"
                "        -o singlethread\n"
                "        -o cache_uri=STRING\n"
                "    Authenticating with the server:\n"
                "        -o username=STRING\n"
                "        -o password=STRING\n"
                "        -o ca_certificate=PATH\n"
                "        -o client_certificate=PATH\n"
                "    Daemon, logging, and process privilege:\n"
                "        -o nodaemon\n"
                "        -o run_as_uid=STRING\n"
                "        -o run_as_gid=STRING (defaults to primary group for run_as_uid)\n"
                "        -o verbosity=NUM (use 7 for debug)\n"
                "        -o section_verbosity=STRING (0 means use global verbosity)\n"
                "    Other:\n"
                "        -o config_file=STRING\n"
                "\n"
                , outargs->argv[0]);
        fuse_opt_add_arg(outargs, "-ho");
        fuse_main(outargs->argc, outargs->argv, &dav_oper, &config);
        exit(1);

    case KEY_VERSION:
        fprintf(stderr, "fusedav version %s\n", PACKAGE_VERSION);
        fprintf(stderr, "LevelDB version %d.%d\n", leveldb_major_version(), leveldb_minor_version());
        fprintf(stderr, "%s\n", curl_version());
        //malloc_stats_print(NULL, NULL, "g");
        fuse_opt_add_arg(outargs, "--version");
        fuse_main(outargs->argc, outargs->argv, &dav_oper, &config);
        exit(0);
    }
    return 1;
}

static int config_privileges(struct fusedav_config *config) {
    if (config->run_as_gid != 0) {
        struct group *g = getgrnam(config->run_as_gid);
        if (setegid(g->gr_gid) < 0) {
            log_print(LOG_ERR, SECTION_FUSEDAV_DEFAULT, "Can't drop gid to %d.", g->gr_gid);
            return -1;
        }
        log_print(LOG_DEBUG, SECTION_FUSEDAV_DEFAULT, "Set egid to %d.", g->gr_gid);
    }

    if (config->run_as_uid != 0) {
        struct passwd *u = getpwnam(config->run_as_uid);

        // If there's no explict group set, use the user's primary gid.
        if (config->run_as_gid == 0) {
            if (setegid(u->pw_gid) < 0) {
                log_print(LOG_ERR, SECTION_FUSEDAV_DEFAULT, "Can't drop git to %d (which is uid %d's primary gid).", u->pw_gid, u->pw_uid);
                return -1;
            }
            log_print(LOG_DEBUG, SECTION_FUSEDAV_DEFAULT, "Set egid to %d (which is uid %d's primary gid).", u->pw_gid, u->pw_uid);
        }

        if (seteuid(u->pw_uid) < 0) {
            log_print(LOG_ERR, SECTION_FUSEDAV_DEFAULT, "Can't drop uid to %d.", u->pw_uid);
            return -1;
        }
        log_print(LOG_DEBUG, SECTION_FUSEDAV_DEFAULT, "Set euid to %d.", u->pw_uid);
    }

    // Ensure the core is still dumpable.
    prctl(PR_SET_DUMPABLE, 1);

    return 0;
}

static void print_config(struct fusedav_config *config) {
    log_print(LOG_NOTICE, SECTION_FUSEDAV_CONFIG, "CONFIG:");
    log_print(LOG_NOTICE, SECTION_FUSEDAV_CONFIG, "progressive_propfind %d", config->progressive_propfind);
    log_print(LOG_NOTICE, SECTION_FUSEDAV_CONFIG, "refresh_dir_for_file_stat %d", config->refresh_dir_for_file_stat);
    log_print(LOG_NOTICE, SECTION_FUSEDAV_CONFIG, "grace %d", config->grace);
    log_print(LOG_NOTICE, SECTION_FUSEDAV_CONFIG, "singlethread %d", config->singlethread);
    log_print(LOG_NOTICE, SECTION_FUSEDAV_CONFIG, "cache_uri %s", config->cache_uri);

    // We could set these two, but they are NULL by default, so don't know how to put that in the config file
    log_print(LOG_NOTICE, SECTION_FUSEDAV_CONFIG, "username %s", config->username);
    log_print(LOG_NOTICE, SECTION_FUSEDAV_CONFIG, "password %s", config->password);

    log_print(LOG_NOTICE, SECTION_FUSEDAV_CONFIG, "ca_certificate %s", config->ca_certificate);
    log_print(LOG_NOTICE, SECTION_FUSEDAV_CONFIG, "client_certificate %s", config->client_certificate);
    log_print(LOG_NOTICE, SECTION_FUSEDAV_CONFIG, "nodaemon %d", config->nodaemon);
    log_print(LOG_NOTICE, SECTION_FUSEDAV_CONFIG, "cache_path %s", config->cache_path);
    log_print(LOG_NOTICE, SECTION_FUSEDAV_CONFIG, "run_as_uid %s", config->run_as_uid);
    log_print(LOG_NOTICE, SECTION_FUSEDAV_CONFIG, "run_as_gid %s", config->run_as_gid);
    log_print(LOG_NOTICE, SECTION_FUSEDAV_CONFIG, "verbosity %d", config->verbosity);
    log_print(LOG_NOTICE, SECTION_FUSEDAV_CONFIG, "section_verbosity %s", config->section_verbosity);

    // These are not subject to change by the parse config method
    log_print(LOG_NOTICE, SECTION_FUSEDAV_CONFIG, "uri: %s", config->uri);
    log_print(LOG_NOTICE, SECTION_FUSEDAV_CONFIG, "cache %p", config->cache);
    log_print(LOG_NOTICE, SECTION_FUSEDAV_CONFIG, "config_file %s", config->config_file);

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

static void parse_configs(struct fusedav_config *config, GError **gerr) {

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

    static const struct key_value_dest_s config_entries[] = {
        keytuple(fusedav, progressive_propfind, BOOL),
        keytuple(fusedav, refresh_dir_for_file_stat, BOOL),
        keytuple(fusedav, grace, BOOL),
        keytuple(fusedav, singlethread, BOOL),
        keytuple(fusedav, cache_uri, STRING),
        keytuple(fusedav, ca_certificate, STRING),
        keytuple(fusedav, client_certificate, STRING),
        keytuple(fusedav, nodaemon, BOOL),
        keytuple(fusedav, cache_path, STRING),
        keytuple(fusedav, run_as_uid, STRING),
        keytuple(fusedav, run_as_gid, STRING),
        keytuple(fusedav, verbosity, INT),
        keytuple(fusedav, section_verbosity, STRING),
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
        config->grace = true; // set default if we don't yet have a config file
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

void configure_fusedav(struct fusedav_config *config, struct fuse_args *args, char **mountpoint, GError **gerr) {
    GError *tmpgerr = NULL;

    // default verbosity: LOG_NOTICE
    config->verbosity = 5;

    // Parse options.
    if (fuse_opt_parse(args, config, fusedav_opts, fusedav_opt_proc) < 0) {
        g_set_error(gerr, fusedav_config_quark(), EINVAL, "FUSE could not parse options.");
        return;
    }

    parse_configs(config, &tmpgerr);
    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "Could not open fusedav config file: %s", config->config_file);
        return;
    }

    if (session_config_init(config->uri, config->ca_certificate, config->client_certificate) < 0) {
        g_set_error(gerr, fusedav_config_quark(), EIO, "Failed to initialize session system.");
        return;
    }

    // Set log levels. We use get_base_directory for the log message, so this call needs to follow
    // session_config_init, where base_directory is set
    log_init(config->verbosity, config->section_verbosity, get_base_url());
    debug = (config->verbosity >= 7);
    log_print(LOG_DEBUG, SECTION_FUSEDAV_MAIN, "Log verbosity: %d.", config->verbosity);

    if (fuse_parse_cmdline(args, mountpoint, NULL, NULL) < 0) {
        g_set_error(gerr, fusedav_config_quark(), EINVAL, "FUSE could not parse the command line.");
        return;
    }

    // fuse_opt_add_arg(&args, "-o atomic_o_trunc");
    // @TODO temporary to make new fusedav work with old titan, until everyone is up to date
    fuse_opt_add_arg(args, "-oumask=0007");

    log_print(LOG_DEBUG, SECTION_FUSEDAV_MAIN, "Parsed command line.");

    if (!config->uri) {
        g_set_error(gerr, fusedav_config_quark(), EINVAL, "Missing the required URI argument.");
        return;
    }

    if (config->cache_uri)
        log_print(LOG_INFO, SECTION_FUSEDAV_MAIN, "Using cache URI: %s", config->cache_uri);

    log_print(LOG_DEBUG, SECTION_FUSEDAV_MAIN, "Attempting to configure privileges.");
    if (config_privileges(config) < 0) {
        g_set_error(gerr, fusedav_config_quark(), EINVAL, "Failed to configure privileges.");
        return;
    }
}

