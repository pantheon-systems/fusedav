#include <stdbool.h>

typedef struct bloomfilter_options_t bloomfilter_options_t;

bloomfilter_options_t *bloomfilter_init(unsigned long fieldsize, unsigned long (*hashfcn)(unsigned long, const void *, size_t),
    unsigned int bits_in_hash_return, char **errptr);
int bloomfilter_add(bloomfilter_options_t *options, const void *key, size_t klen);
bool bloomfilter_exists(bloomfilter_options_t *options, const void *key, size_t klen);
void bloomfilter_destroy(bloomfilter_options_t *options);
