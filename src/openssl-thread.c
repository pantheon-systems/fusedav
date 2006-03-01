/* $Id$ */

/***
  This file is part of fusedav.

  fusedav is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  fusedav is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
  License for more details.
  
  You should have received a copy of the GNU General Public License
  along with fusedav; if not, write to the Free Software Foundation,
  Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pthread.h>
#include <openssl/crypto.h>

#include "fusedav.h"
#include "openssl-thread.h"

static pthread_mutex_t *mutexes;
                                                                                                                                                                         
static void pthreads_locking_callback(int mode, int n, __unused const char *file, __unused int line) {
    if (mode & CRYPTO_LOCK)
        pthread_mutex_lock(mutexes+n);
    else
        pthread_mutex_unlock(mutexes+n);
}                                                                                                                                                                     

static unsigned long pthreads_thread_id(void) {
    return (unsigned long) pthread_self();
}

void openssl_thread_setup(void) {
    int i, l;
    
    mutexes = OPENSSL_malloc((l = CRYPTO_num_locks()) * sizeof(pthread_mutex_t));

    for (i = 0; i < l; i++)
        pthread_mutex_init(mutexes+i, NULL);
                                                                                                                                                                         
    CRYPTO_set_id_callback(pthreads_thread_id);
    CRYPTO_set_locking_callback(pthreads_locking_callback);
}

void openssl_thread_cleanup(void) {
    int i, l;
    
    CRYPTO_set_locking_callback(NULL);

    l = CRYPTO_num_locks();
    for (i = 0; i < l; i++)
        pthread_mutex_destroy(mutexes+i);

    OPENSSL_free(mutexes);
}

