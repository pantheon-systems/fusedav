#include <stdbool.h>
#define SIXTEEN_BITS 65536

int bloom_add(const char *key, int klen, unsigned long salt, char *bloombits);
bool bloom_exists(const char *key, int klen, unsigned long salt, char *bloombits);
