#ifndef foobloomfilterhfoo
#define foobloomfilterhfoo

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

#include <stdbool.h>

typedef struct bloomfilter_options_t bloomfilter_options_t;

bloomfilter_options_t *bloomfilter_init(unsigned long fieldsize, unsigned long (*hashfcn)(unsigned long, const void *, size_t),
    unsigned int bits_in_hash_return, char **errptr);
int bloomfilter_add(bloomfilter_options_t *options, const void *key, size_t klen);
bool bloomfilter_exists(bloomfilter_options_t *options, const void *key, size_t klen);
void bloomfilter_destroy(bloomfilter_options_t *options);

#endif
