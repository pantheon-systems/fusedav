#include <pthread.h>
#include <openssl/crypto.h>

static pthread_mutex_t *mutexes;
                                                                                                                                                                         
static void pthreads_locking_callback(int mode, int n, const char *file, int line) {
    if (mode & CRYPTO_LOCK)
        pthread_mutex_lock(mutexes+n);
    else
        pthread_mutex_unlock(mutexes+n);
}                                                                                                                                                                     

static unsigned long pthreads_thread_id(void) {
    return (unsigned long)pthread_self();
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

