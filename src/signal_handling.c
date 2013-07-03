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

#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <fuse.h>
#include <glib.h>

#include "util.h"
#include "log.h"
#include "log_sections.h"
#include "signal_handling.h"
#include "stats.h"
#include "statcache.h"

// GError mechanisms
G_DEFINE_QUARK(SIGNAL_HANDLING, signal_handling)

extern struct fuse *fuse;

static void sigusr2_handler(__unused int signum) {
    print_stats();
    stat_cache_walk();
}

static void sigsegv_handler(int signum) {
    assert(signum == 11);
    log_print(LOG_CRIT, SECTION_SIGNALHANDLING_DEFAULT, "Segmentation fault.");
    signal(signum, SIG_DFL);
    kill(getpid(), signum);
}

static void exit_handler(__unused int sig) {
    static const char m[] = "*** Caught signal ***\n";
    if(fuse != NULL) {
        fuse_exit(fuse);
    }
    write(2, m, strlen(m));
}

static void empty_handler(__unused int sig) {}

void setup_signal_handlers(GError **gerr) {
    struct sigaction sa;
    sigset_t m;

    signal(SIGSEGV, sigsegv_handler);
    signal(SIGUSR2, sigusr2_handler);

    sa.sa_handler = exit_handler;
    sigemptyset(&(sa.sa_mask));
    sa.sa_flags = 0;

    if (sigaction(SIGHUP, &sa, NULL) == -1 ||
        sigaction(SIGINT, &sa, NULL) == -1 ||
        sigaction(SIGTERM, &sa, NULL) == -1) {

        log_print(LOG_CRIT, SECTION_SIGNALHANDLING_DEFAULT, "Cannot set exit signal handlers: %s", strerror(errno));
        g_set_error(gerr, signal_handling_quark(), errno, "Cannot set exit signal handlers");
        return;
    }

    sa.sa_handler = SIG_IGN;

    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        g_set_error(gerr, signal_handling_quark(), errno, "Cannot set ignored signals");
        return;
    }

    /* Used to shut down the locking thread */
    sa.sa_handler = empty_handler;

    if (sigaction(SIGUSR1, &sa, NULL) == -1) {
        g_set_error(gerr, signal_handling_quark(), errno, "Cannot set user signals");
        return;
    }

    sigemptyset(&m);
    pthread_sigmask(SIG_BLOCK, &m, &m);
    sigdelset(&m, SIGHUP);
    sigdelset(&m, SIGINT);
    sigdelset(&m, SIGTERM);
    sigaddset(&m, SIGPIPE);
    sigaddset(&m, SIGUSR1);
    pthread_sigmask(SIG_SETMASK, &m, NULL);

    return;
}

