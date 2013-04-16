testdir = /opt/fusedav/utils

cltest = $(testdir)/cltest.sh
# usage on Makefile line: 'cltest-flags=-i64'
# -i is iters; default is 64
cltest-flags=

statcacheprune = $(testdir)/statcacheprune.sh
# usage on Makefile line: 'statcacheprune-flags=-d2 -f64'
# default for -d is 2; max allowed is 4; for -f it's 64
statcacheprune-flags=

# NB: no PASS/FAIL notification yet from iozone, still requires eyeballs
iozone = /opt/iozone/src/current/iozone
# -g: start with files of this size (by default 64K)
# -n: stop with files of this size (default: don't know, we never succeed past 128M)
# For unit testing, just do the 4M size; it's generally small enough to finish quickly
iozone-unit-flags = -g4096 -n4096
# iozone fails on large files; it sometimes succeeds at 128M, but set to 64M
iozone-stress-flags = -n65536

readrecursive = $(testdir)/readrecursive
# So far, the only flag is -v for verbose, 'readrecursive-flags=-v'
readrecursive-flags =

readwhatwaswritten = $(testdir)/readwhatwaswritten
# So far, the only flag is -v for verbose, 'readwhatwaswritten-flags=-v'
readwhatwaswritten-flags =

all: run-unit-tests run-stress-tests

# restrict unit tests to low-resource tests
run-unit-tests: run-cltest run-statcacheprune run-readrecursive run-iozone-unit run-readwhatwaswritten-unit run-readwhatwaswritten-unlink-unit

# stress test is all test, but run the stress version if there is both a unit and a stress version. e.g. iozone
run-stress-tests: run-cltest run-statcacheprune run-iozone-stress run-readwhatwaswritten-stress run-readwhatwaswritten-unlink-stress

run-cltest:
	$(cltest) $(cltest-flags)

run-statcacheprune:
	$(statcacheprune) $(statcacheprune-dirs) $(statcacheprune-files) $(statcacheprune-verbose)

run-iozone-unit:
	$(iozone) -Ra $(iozone-unit-flags)

run-iozone-stress:
	$(iozone) -Ra $(iozone-stress-flags)

run-readrecursive: $(readrecursive)
	$(readrecursive) $(readrecursive-flags)

$(readrecursive): $(testdir)/readrecursive.c
	cc $< -std=c99 -g -o $@

run-readwhatwaswritten-unit: $(readwhatwaswritten)
	$(readwhatwaswritten) -f16 $(readwhatwaswritten-flags)

run-readwhatwaswritten-unlink-unit: $(readwhatwaswritten)
	$(readwhatwaswritten) -f16 $(readwhatwaswritten-flags) -u

run-readwhatwaswritten-stress: $(readwhatwaswritten)
	$(readwhatwaswritten) -f256 $(readwhatwaswritten-flags)

run-readwhatwaswritten-unlink-stress: $(readwhatwaswritten)
	$(readwhatwaswritten) -f256 $(readwhatwaswritten-flags) -u

$(readwhatwaswritten): $(testdir)/readwhatwaswritten.c
	cc $< -std=c99 -g -o $@

