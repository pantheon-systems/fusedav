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
#include <unistd.h>

#include "fusedav.h"
#include "fusedav_config.h"
#include "log.h"
#include "log_sections.h"
#include "util.h"
#include "session.h"

// @TODO: These changes assume that we will ensure that there is a new fusedav
// available before the corresponding changes to titan go into effect. We can
// tolerate this new fusedav running on old titan, but we cannot tolerate updating
// to a new titan while still remounting the old fusedav.
// After we update to new fusedav and new titan, we will need to make another
// pass to cleanup these transition elements.


// GError mechanisms
static G_DEFINE_QUARK(FUSEDAV_CONFIG, fusedav_config)

enum {
     KEY_HELP,
     KEY_VERSION,
};

#define FUSEDAV_OPT(t, p, v) { t, offsetof(struct fusedav_config, p), v }

// @TODO: The fusedav_opts are only necessary while we have an old version of titan
// where the .mount file's Options line includes all of these items.
// Once we have a new titan with the short list of Options, all of which are
// recognized internally by fusedav, we will no longer need the FUSEDAV_OPT
// entries here. We will still need the FUSE_OPT_KEY items.
// We can redirect ignoreutimens and ignorexattr to dummy, since we no longer
// keep track of them in the config structure.
// We can redirect dir_mode and file_mode to dummy, since we pass umask to fuse
// itself. We have to 'manually' pass it to fuse in the meantime, but it will
// be part of the Options line when the new titan lays down a new .mount file.
// client_certificate_password is now irrelevant since we use pem not p12, so
// it can be redirected to dummy.
// The old titan will not lay down a new fusedav.conf file, so we still need
// these other entries to populate the config structure correctly. With the
// new titan, we can do away with all of them.
// HOWEVER, we still need 'conf=' as long as we want to specify it via the Options
// line in the .mount file

static struct fuse_opt fusedav_opts[] = {
    // ProtocolAndPerformance
    FUSEDAV_OPT("progressive_propfind",           progressive_propfind, true),
    FUSEDAV_OPT("refresh_dir_for_file_stat",      refresh_dir_for_file_stat, true),
    FUSEDAV_OPT("grace",                          grace, true),
    FUSEDAV_OPT("singlethread",                   singlethread, true),
    FUSEDAV_OPT("cache_uri=%s",                   cache_uri, 0),
    FUSEDAV_OPT("filesystem_domain=%s",           filesystem_domain, 0),
    FUSEDAV_OPT("filesystem_port=%s",             filesystem_port, 0),
    // Authenticate
    FUSEDAV_OPT("username=%s",                    username, 0),
    FUSEDAV_OPT("password=%s",                    password, 0),
    FUSEDAV_OPT("ca_certificate=%s",              ca_certificate, 0),
    FUSEDAV_OPT("client_certificate=%s",          client_certificate, 0),
    // LogAndProcess
    FUSEDAV_OPT("nodaemon",                       nodaemon, true),
    FUSEDAV_OPT("cache_path=%s",                  cache_path, 0),
    FUSEDAV_OPT("run_as_uid=%s",                  run_as_uid, 0),
    FUSEDAV_OPT("run_as_gid=%s",                  run_as_gid, 0),
    FUSEDAV_OPT("verbosity=%d",                   log_level, 5),
    FUSEDAV_OPT("section_verbosity=%s",           log_level_by_section, 0),
    FUSEDAV_OPT("log_prefix=%s",                  log_prefix, 0),
    // Config
    FUSEDAV_OPT("conf=%s",                        conf, 0),

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

// We need to access dav_oper since it is accessed globally in fusedav_opt_proc
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
                "        -o filesystem_domain=STRING\n"
                "        -o filesystem_port=STRING\n"
                "    Authenticating with the server:\n"
                "        -o username=STRING\n"
                "        -o password=STRING\n"
                "        -o ca_certificate=PATH\n"
                "        -o client_certificate=PATH\n"
                "    Daemon, logging, and process privilege:\n"
                "        -o nodaemon\n"
                "        -o run_as_uid=STRING\n"
                "        -o run_as_gid=STRING (defaults to primary group for run_as_uid)\n"
                "        -o log_level=NUM (use 7 for debug)\n"
                "        -o log_level_by_section=STRING (0 means use global verbosity)\n"
                "    Other:\n"
                "        -o max_file_size=NUM (in MB)\n"
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
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "filesystem_domain %s", config->filesystem_domain);
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "filesystem_port %s", config->filesystem_port);

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
filesystem_domain=valhalla.chios.panth.io
filesystem_port=448

ca_certificate=/etc/pki/tls/certs/ca-bundle.crt
client_certificate=/srv/bindings/6f7a106722f74cc7bd96d4d06785ed78/certs/binding.pem

cache_path=/srv/bindings/6f7a106722f74cc7bd96d4d06785ed78/cache
run_as_uid=6f7a106722f74cc7bd96d4d06785ed78
run_as_gid=6f7a106722f74cc7bd96d4d06785ed78
log_level=5
log_level_by_section=0
log_prefix=6f7a106722f74cc7bd96d4d06785ed78
max_file_size=256
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
        keytuple(fusedav, cache_uri, STRING),
        keytuple(fusedav, ca_certificate, STRING),
        keytuple(fusedav, client_certificate, STRING),
        keytuple(fusedav, cache_path, STRING),
        keytuple(fusedav, filesystem_domain, STRING),
        keytuple(fusedav, filesystem_port, STRING),
        keytuple(fusedav, run_as_uid, STRING),
        keytuple(fusedav, run_as_gid, STRING),
        keytuple(fusedav, log_level, INT),
        keytuple(fusedav, log_level_by_section, STRING),
        keytuple(fusedav, log_prefix, STRING),
        keytuple(fusedav, max_file_size, INT),
        {NULL, NULL, 0, 0}
        };

    print_config(config);

    // JB FIX ME!
    // Step one: make sure this new version of fusedav is running on all mounts before merging
    //           changes to titan and the mount file. If the mount file is updated to include
    //           conf as an option, the version of fusedav before this one will barf
    //           since it's not a known option.
    // Step two: merge changes to titan including config file
    // Proviso:  ultimately, we want to ensure there is a config file, and err if one is not present
    //           Until titan is updated to include fusedav in the .mount file, ignore errors
    //           from non-existant config files

    // Bail for now if we don't have a config file
    // @TODO make this an error once the new titan rolls out
    if (config->conf == NULL) {
        config->grace = true; // set default if we don't yet have a config file @TODO get rid of this
        log_print(LOG_NOTICE, SECTION_CONFIG_DEFAULT, "parse_configs: conf was not specified");
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

    print_config(config);

    return;
}

void configure_fusedav(struct fusedav_config *config, struct fuse_args *args, char **mountpoint, GError **gerr) {
    GError *tmpgerr = NULL;
    const char *log_prefix;

    // default log_level: LOG_NOTICE
    config->log_level = 5;
    
    // @TODO: only needed if someone remounts to a new fusedav but doesn't yet converge to
    // get the new fusedav.conf which sets this value. Is this a one-off we can throw away
    // later, or do we want a more elegant mechanism for setting defaults as the future unfolds?
    config->max_file_size = 256;

    // Parse options.
    if (fuse_opt_parse(args, config, fusedav_opts, fusedav_opt_proc) < 0 || inject_error(config_error_parse)) {
        g_set_error(gerr, fusedav_config_quark(), EINVAL, "FUSE could not parse options.");
        return;
    }

    parse_configs(config, &tmpgerr);
    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "Could not open fusedav config file: %s", config->conf);
        return;
    }

    if (session_config_init(config->uri, config->ca_certificate, config->client_certificate, 
        config->filesystem_domain, config->filesystem_port) < 0 || inject_error(config_error_sessioninit)) {
        g_set_error(gerr, fusedav_config_quark(), ENETDOWN, "Failed to initialize session system.");
        return;
    }

    // Set log levels. We use get_base_url for the log message, so this call needs to follow
    // session_config_init, where base_url is set
    // @TODO when new titan rolls out, just pass in config->log_prefix
    if (config->log_prefix) log_prefix = config->log_prefix;
    else log_prefix = get_base_url();
    log_init(config->log_level, config->log_level_by_section, log_prefix);
    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "log_level: %d.", config->log_level);

    if (fuse_parse_cmdline(args, mountpoint, NULL, NULL) < 0 || inject_error(config_error_cmdline)) {
        g_set_error(gerr, fusedav_config_quark(), EINVAL, "FUSE could not parse the command line.");
        return;
    }

    // @TODO: is there a best place for fuse_opt_add_arg? Does it need to follow fuse_parse_cmdline?
    // fuse_opt_add_arg(&args, "-o atomic_o_trunc");
    // @TODO temporary to make new fusedav work with old titan, until everyone is up to date
    fuse_opt_add_arg(args, "-oumask=0007");

    log_print(LOG_DEBUG, SECTION_CONFIG_DEFAULT, "Parsed command line.");

    if (!config->uri || inject_error(config_error_uri)) {
        g_set_error(gerr, fusedav_config_quark(), EINVAL, "Missing the required URI argument.");
        return;
    }

    if (config->cache_uri) {
        log_print(LOG_INFO, SECTION_CONFIG_DEFAULT, "Using cache URI: %s", config->cache_uri);
    }
}

