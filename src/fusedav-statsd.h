#ifndef foofusedavstatsdhfoo
#define foofusedavstatsdhfoo

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

// Special sample rate for propfinds so as not to overwhelm statsd transmission
extern const float pfsamplerate;

int stats_init(const char *domain, const char *port);
int stats_close(void);
int stats_counter(const char *statname, const int value, const float samplerate);
int stats_counter_cluster(const char *statname, const int value, const float samplerate);
int stats_counter_local(const char *statname, const int value, const float samplerate);
int stats_gauge(const char *statname, const int value);
int stats_gauge_cluster(const char *statname, const int value);
int stats_gauge_local(const char *statname, const int value);
int stats_timer(const char *statname, const int value);
int stats_timer_cluster(const char *statname, const int value);
int stats_timer_local(const char *statname, const int value);
int stats_histo(const char *statname, const int value, const int max, const float samplerate);

#endif
