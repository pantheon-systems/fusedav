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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

#include "fusedav.h"
#include "fusedav_config.h"
#include "log.h"
#include "log_sections.h"
#include "util.h"
#include "session.h"
#include "fusedav-statsd.h"

// GError mechanisms
static G_DEFINE_QUARK(FUSEDAV_CONFIG, fusedav_config)

enum {
     KEY_HELP,
     KEY_VERSION,
     KEY_IGNORE,
};

#define FUSEDAV_OPT(t, p, v) { t, offsetof(struct fusedav_config, p), v }

// Fuse options are set in the .mount file and are handled by fuse independently
// Fusedav options are handled by the fusedav.conf file and don't need to
// be passed to fuse. The only exception is conf itself for the configuration
// file. It is specified in the .mount file so that we now where to find it
// here at configuration time.
static struct fuse_opt fusedav_opts[] = {
    // Config
    FUSEDAV_OPT("conf=%s",         conf, 0),

    FUSE_OPT_KEY("-V",             KEY_VERSION),
    FUSE_OPT_KEY("--version",      KEY_VERSION),
    FUSE_OPT_KEY("-h",             KEY_HELP),
    FUSE_OPT_KEY("--help",         KEY_HELP),
    FUSE_OPT_KEY("-?",             KEY_HELP),
    FUSE_OPT_KEY("-n",             KEY_IGNORE),
    FUSE_OPT_END
};

// We need to access dav_oper since it is accessed globally in fusedav_opt_proc
extern struct fuse_operations dav_oper;
char *user_agent = NULL;

static int fusedav_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs) {
    struct fusedav_config *config = data;

    switch (key) {
    case FUSE_OPT_KEY_NONOPT:
        if (!config->uri) {
            config->uri = strdup(arg);
            return 0;
        }
        break;

    case KEY_IGNORE:
	return 0;

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
                "        -o conf=STRING\n"
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

static void print_config(struct fusedav_config *config) {
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "CONFIG:");
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "progressive_propfind %d", config->progressive_propfind);
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "refresh_dir_for_file_stat %d", config->refresh_dir_for_file_stat);
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "grace %d", config->grace);
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "singlethread %d", config->singlethread);
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "cache_uri %s", config->cache_uri);

    // We could set these two, but they are NULL by default, so don't know how to put that in the config file
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "username %s", config->username);
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "password %s", config->password);

    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "ca_certificate %s", config->ca_certificate);
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "client_certificate %s", config->client_certificate);
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "nodaemon %d", config->nodaemon);
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "cache_path %s", config->cache_path);
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "run_as_uid %s", config->run_as_uid);
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "run_as_gid %s", config->run_as_gid);
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "log_level %d", config->log_level);
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "log_level_by_section %s", config->log_level_by_section);
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "log_prefix %s", config->log_prefix);
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "max_file_size %d", config->max_file_size);
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "statsd_host %s", config->statsd_host);
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "statsd_port %s", config->statsd_port);

    // These are not subject to change by the parse config method
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "uri: %s", config->uri);
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "cache %p", config->cache);
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "conf %s", config->conf);
}

/* fusedav.conf looks something like:
[fusedav]
progressive_propfind=true
refresh_dir_for_file_stat=true
grace=true
cache_uri=http://50.57.148.118:10061/fusedav-peer-cache

ca_certificate=/etc/pki/tls/certs/ca-bundle.crt
client_certificate=/srv/bindings/6f7a106722f74cc7bd96d4d06785ed78/certs/binding.pem

cache_path=/srv/bindings/6f7a106722f74cc7bd96d4d06785ed78/cache
run_as_uid=6f7a106722f74cc7bd96d4d06785ed78
run_as_gid=6f7a106722f74cc7bd96d4d06785ed78
log_level=5
log_level_by_section=0
log_prefix=6f7a106722f74cc7bd96d4d06785ed78
max_file_size=256
statsd_host=127.0.0.1
statsd_port=8126
*/

// Note for future generations; as currently set up, inject error won't start until
// after this function is called, so the inject_error routines will never fire even
// if inject error is turned on


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
        keytuple(fusedav, nodaemon, BOOL),
        keytuple(fusedav, cache_uri, STRING),
        keytuple(fusedav, ca_certificate, STRING),
        keytuple(fusedav, client_certificate, STRING),
        keytuple(fusedav, cache_path, STRING),
        keytuple(fusedav, run_as_uid, STRING),
        keytuple(fusedav, run_as_gid, STRING),
        keytuple(fusedav, log_level, INT),
        keytuple(fusedav, log_level_by_section, STRING),
        keytuple(fusedav, log_prefix, STRING),
        keytuple(fusedav, max_file_size, INT),
        keytuple(fusedav, statsd_host, STRING),
        keytuple(fusedav, statsd_port, STRING),
        {NULL, NULL, 0, 0}
        };

    print_config(config);

    // Bail for now if we don't have a config file
    if (config->conf == NULL) {
        g_set_error(gerr, fusedav_config_quark(), ENOENT, "parse_configs: No conf file");
        return;
    }

    log_print(LOG_INFO, SECTION_CONFIG_DEFAULT, "parse_configs: file %s", config->conf);

    /* Set up the key file stuff */

    keyfile = g_key_file_new();

    bret = g_key_file_load_from_file(keyfile, config->conf, G_KEY_FILE_NONE, &tmpgerr);
    // g_key_file_load_from_file does not seem to set error on null file
    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "parse_configs: Error on load_from_file");
        return;
    } else if (bret == FALSE || inject_error(config_error_load)) {
        g_set_error(gerr, fusedav_config_quark(), ENOENT, "parse_configs: Error on load_from_file");
        return;
    }

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
        // let's leave it as it is for now. We currently only have strings, ints, and bools, and
        // this would be preferable for dealing with bools.
        if (tmpgerr == NULL) {
            memcpy(field, &uvalue.vvalue, size);
        }
        else {
            log_print(LOG_NOTICE, SECTION_CONFIG_DEFAULT, "parse_config: error on %s : %s", config_entries[idx].key, tmpgerr->message);
            g_clear_error(&tmpgerr);
        }
    }

    g_key_file_free(keyfile);

    return;
}

void configure_fusedav(struct fusedav_config *config, struct fuse_args *args, char **mountpoint, GError **gerr) {
    // Defaults for statsd
    GError *tmpgerr = NULL;

    // Set defaults for key items in case some don't otherwise get set
    // config is mem-zeroed out before getting passed in here, so
    // technically only need to set defaults for non-zero things.

    config->progressive_propfind = true;
    config->refresh_dir_for_file_stat = true;
    config->grace = true;
    config->singlethread = false;
    config->nodaemon = false;
    config->max_file_size = 256; // 256M
    config->log_level = 5; // default log_level: LOG_NOTICE
    asprintf(&config->statsd_host, "%s", "127.0.0.1");
    asprintf(&config->statsd_port, "%s", "8126");

    // Parse options.
    if (fuse_opt_parse(args, config, fusedav_opts, fusedav_opt_proc) < 0 || inject_error(config_error_parse)) {
        g_set_error(gerr, fusedav_config_quark(), EINVAL, "configure_fusedav: FUSE could not parse options.");
        return;
    }

    parse_configs(config, &tmpgerr);
    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "configure_fusedav: ");
        return;
    }

    if (session_config_init(config->uri, config->ca_certificate, config->client_certificate, config->grace) < 0 || inject_error(config_error_sessioninit)) {
        g_set_error(gerr, fusedav_config_quark(), ENETDOWN, "configure_fusedav: Failed to initialize session system.");
        return;
    }

    asprintf(&user_agent, "FuseDAV/%s %s", PACKAGE_VERSION, config->log_prefix);

    log_init(config->log_level, config->log_level_by_section, config->log_prefix);
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "log_level: %d.", config->log_level);

    if (stats_init(config->statsd_host, config->statsd_port) < 0) {
        log_print(LOG_CRIT, SECTION_CONFIG_DEFAULT, "ERROR: Failed to initialize stats. Continuing...");
    }

    // call it here after log_init, so that setting the log levels effects what prints
    print_config(config);

    if (fuse_parse_cmdline(args, mountpoint, NULL, NULL) < 0 || inject_error(config_error_cmdline)) {
        g_set_error(gerr, fusedav_config_quark(), EINVAL, "FUSE could not parse the command line.");
        return;
    }

    // @TODO: is there a best place for fuse_opt_add_arg? Does it need to follow fuse_parse_cmdline?
    // fuse_opt_add_arg(&args, "-o atomic_o_trunc");

    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "Parsed command line.");

    if (!config->uri || inject_error(config_error_uri)) {
        g_set_error(gerr, fusedav_config_quark(), EINVAL, "Missing the required URI argument.");
        return;
    }

    if (config->cache_uri) {
        log_print(LOG_INFO, SECTION_CONFIG_DEFAULT, "Using cache URI: %s", config->cache_uri);
    }
}

const char *get_user_agent(void) {
    return user_agent;
}
