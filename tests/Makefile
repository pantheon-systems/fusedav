testdir = /opt/fusedav/tests

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
iozone-stress-flags = -g65536
# for continual testing, limit iozone to 16M
iozone-continual-flags = -g16384

readrecursive = $(testdir)/readrecursive
# So far, the only flag is -v for verbose, 'readrecursive-flags=-v'
readrecursive-flags =

# If we unlink an open file, make sure we can close it
openunlinkclose = $(testdir)/openunlinkclose
# flag -v for verbose
openunlinkclose-flags =

readwhatwaswritten = $(testdir)/readwhatwaswritten
# flag -v for verbose, -f# for number of files, -u are we doing unlinks 'readwhatwaswritten-flags=-v -u -f16'
readwhatwaswritten-flags =

continualwrites = $(testdir)/continualwrites
# flag -v for verbose, -f# for number of files 'continualwrites-flags=-v -u -f16'
continualwrites-flags =

forensichaventest = $(testdir)/forensic-haven-test
# currently there are no flags
forensichaventest-flags =

trunc = $(testdir)/trunc
# -v for verbose, -r# for number of rounds, -f# for number of files, -s# for size of write, -i# for
# number of write iters'trunc-flags=-v -r 8 -f 8 -s 32 -i 16'
trunc-flags =

all: run-stress-tests

# restrict unit tests to low-resource tests
run-unit-tests: run-cltest run-statcacheprune run-readrecursive run-readwhatwaswritten-unit run-readwhatwaswritten-unlink-unit run-continualwrites-unit run-trunc run-iozone-unit

# stress test is all test, but run the stress version if there is both a unit and a stress version. e.g. iozone
run-stress-tests: run-cltest run-statcacheprune run-readrecursive run-readwhatwaswritten-stress run-readwhatwaswritten-unlink-stress run-continualwrites-unit run-trunc run-iozone-stress

# stress test is all test, but run the stress version if there is both a unit and a stress version. e.g. iozone
# unlink test is creating increasing numbers of open files which never get closed. Remove for now.
# run-continual-tests: run-cltest run-statcacheprune run-readrecursive run-readwhatwaswritten-stress run-readwhatwaswritten-unlink-stress run-trunc run-iozone-continual
run-continual-tests: run-cltest run-statcacheprune run-readrecursive run-readwhatwaswritten-stress run-readwhatwaswritten-unlink-stress run-trunc run-iozone-continual

# short stress test is all tests but iozone, but run the stress version if there is both a unit and a stress version. e.g. iozone
run-short-stress-tests: run-cltest run-statcacheprune run-readrecursive run-readwhatwaswritten-stress run-readwhatwaswritten-unlink-stress run-trunc

# run this to test the system under error. To do this:
# use the fusedav client inject error mechanism. Use the writewrite_test 
# in util.c.
# Also, independently, test error response by:
# sftp a file which is too large for the file server (> 256M)
# do this without error injection running
run-write-errors: run-continualwrites-unit

# run this test in conjunction with filecache_forensic_haven_test in
# util.c while injecting errors (make INJECT_ERRORS=1)
# Run overnight or so; if there are no catastrophic failures (e.g. segv)
# consider it a pass.
# NB: this test needs to create an errors file in <...>/files directory
# but often fails because we are injecting errors. It may need to be
# started several times before it actually takes. If the errors file
# cannot be created, the program exits.
run-forensic-haven-test: run-forensic-haven-unit

run-cltest:
	$(cltest) $(cltest-flags)

run-statcacheprune:
	$(statcacheprune) $(statcacheprune-dirs) $(statcacheprune-flags) $(statcacheprune-verbose)

run-iozone-unit:
	$(iozone) -Ra $(iozone-unit-flags)

run-iozone-stress:
	$(iozone) -Ra $(iozone-stress-flags)

run-iozone-continual:
	$(iozone) -Ra $(iozone-continual-flags)

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

run-openunlinkclose: $(openunlinkclose)
	$(openunlinkclose) $(openunlinkclose-flags)

$(openunlinkclose): $(testdir)/openunlinkclose.c
	cc $< -std=c99 -g -o $@

run-continualwrites-unit: $(continualwrites)
	$(continualwrites) -f16 $(continualwrites-flags)

$(continualwrites): $(testdir)/continualwrites.c
	cc $< -std=c99 -g -o $@

run-forensic-haven-unit: $(forensichaventest)
	$(forensichaventest) -f16 $(forensichaventest-flags)

$(forensichaventest): $(testdir)/forensic-haven-test.c
	cc $< -std=c99 -g -o $@

run-trunc: $(trunc)
	$(trunc) $(trunc-flags)

$(trunc): $(testdir)/trunc.c
	cc $< -std=c99 -g -o $@

