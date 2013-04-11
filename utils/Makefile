testdir = /opt/fusedav/utils

cltest = $(testdir)/cltest.sh
cltest-iters=
cltest-verbose=

statcacheprune = $(testdir)/statcacheprune.sh
# usage on Makefile line: 'statcacheprune-dirs=-d4'
# default is 2; max allowed is 4
statcacheprune-dirs=
# usage on Makefile line: 'statcacheprune-files=-f32'
# default is 64
statcacheprune-files=

# NB: no PASS/FAIL notification yet from iozone, still requires eyeballs
iozone = /opt/iozone/src/current/iozone
# -g: start with files of this size (by default 64K)
# -n: stop with files of this size (default: don't know, we never succeed past 128M)
# For unit testing, just do the 4M size; it's generally small enough to finish quickly
iozone-unit-g = -g4096
iozone-unit-n = -n4096
# iozone fails on large files; it sometimes does 128M, but set to 64M
iozone-stress-g =
iozone-stress-n = -n65536

readrecursive = $(testdir)/readrecursive

# restrict unit tests to low-resource tests
run-unit-tests: run-cltest run-statcacheprune run-iozone-unit

# stress test is all test, but run the stress version if there is both a unit and a stress version. e.g. iozone
run-stress-tests: run-cltest run-statcacheprune run-iozone-stress

run-cltest:
	$(cltest) $(cltest-iters) $(cltest-verbose)

run-statcacheprune:
	$(statcacheprune) $(statcacheprune-dirs) $(statcacheprune-files) $(statcacheprune-verbose)

run-iozone-unit:
	$(iozone) -Ra $(iozone-unit-n) $(iozone-unit-g)

run-iozone-stress:
	$(iozone) -Ra $(iozone-stress-n) $(iozone-stress-g)

run-readrecursive: $(readrecursive)
	$(readrecursive)

$(readrecursive): $(testdir)/readrecursive.c
	cc $< -std=c99 -g -o $@

