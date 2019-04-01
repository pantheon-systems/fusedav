testdir = /root/pantheon/fusedav/tests
curdir := $(shell pwd)

cltest = $(testdir)/cltest.sh
# usage on Makefile line: 'cltest-flags=-i64'
# -i is iters; default is 64
cltest-flags=

urlencode = $(testdir)/urlencode.sh
# usage on Makefile line: 'urlencode-flags=-i64'
# -i is iters; default is 1
urlencode-flags=

statcacheprune = $(testdir)/statcacheprune.sh
# usage on Makefile line: 'statcacheprune-flags=-d2 -f64 -tdflt'
# default for -d is 2; max allowed is 4; for -f it's 64
statcacheprune-flags=

# statcacheprune takes a flag -t<tag>. This will tag files with
# tag. This is useful for multi-binding tests, so that each
# binding can write different files from the others but in the
# same directories to cause stress and see how the system handles it.
# I used this to trigger "Too Many Events" exception

# This is a regression test. In the past, if run on cltest files after statcacheprune
# was run, du would return 0. So as a quasy-test of the issue is to run dutest right
# after statcacheprune. However, there are two fixes to fix this problem, so it's
# not really sure which one this one is.
dutest = $(testdir)/dutest.sh
# -v for verbose
dutest-flags=

# Create a lot of files in a lot of directories
writefiles-create = $(testdir)/writefiles-create.sh
# -v for verbose
writefiles-create-flags=

# Remove a lot of files in a lot of directories
writefiles-remove = $(testdir)/writefiles-remove.sh
# -v for verbose
writefiles-remove-flags=

# Write some files, delete some of them, check for correct positive/negative entries
write-delete-checknegative = $(testdir)/write-delete-checknegative.sh
# -v for verbose
write-delete-checknegative-flags=

# NB: no PASS/FAIL notification yet from iozone, still requires eyeballs
iozone = /root/pantheon/iozone/src/current/iozone
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
# flag -v for verbose, -f# for number of files 'continualwrites-flags=-v -w -f16'
continualwrites-flags =

rename = $(testdir)/rename
# flag -v for verbose 'rename-flags=-v'
rename-flags =

one-open-many-writes = $(testdir)/one-open-many-writes 
# flag -v for verbose, -f# for number of files 'one-open-many-writes=-v -w -f16'
one-open-many-writes-flags =

forensichaventest = $(testdir)/forensic-haven-test
# currently there are no flags
forensichaventest-flags =

trunc = $(testdir)/trunc
# -v for verbose, -r# for number of rounds, -f# for number of files, -s# for size of write, -i# for
# number of write iters 'trunc-flags=-v -r 8 -f 8 -s 32 -i 16'
trunc-flags =

# Needs to be run from outside of files directory since it accesses the file cache in the binding directory
stat-vs-fstat = $(testdir)/stat-vs-fstat
# -v for verbose, -r# for number of rounds, -f# for number of files, -s# for size of write, -i# for
# number of write iters 'stat-vs-fstat-flags=-v -r 8 -f 8 -s 32 -i 16'
stat-vs-fstat-flags =

# Needs to be run from outside of files directory since it accesses the file cache in the binding directory
stat-stat = $(testdir)/stat-stat
# -v for verbose, -r# for number of rounds, -f# for number of files, -s# for size of write, -i# for
# number of write iters 'stat-stat-flags=-v -s 32 -i 16'
stat-stat-flags =

# Needs to be run from outside of files directory since it accesses the file cache in the binding directory
stat-fstat = $(testdir)/stat-fstat
# -v for verbose, -r# for number of rounds, -f# for number of files, -s# for size of write, -i# for
# number of write iters 'stat-fstat-flags=-v -s 32 -i 16'
stat-fstat-flags =

# Needs to be run from outside of files directory since it accesses the file cache in the binding directory
stat-fstat-unlink = $(testdir)/stat-fstat-unlink
# -v for verbose, -r# for number of rounds, -f# for number of files, -s# for size of write, -i# for
# number of write iters 'stat-fstat-unlink-flags=-v -s 32 -i 16'
stat-fstat-unlink-flags =

# Needs to be run from outside of files directory since it accesses the file cache in the binding directory
stat-stat-unlink = $(testdir)/stat-stat-unlink
# -v for verbose, -r# for number of rounds, -f# for number of files, -s# for size of write, -i# for
# number of write iters 'stat-stat-unlink-flags=-v -s 32 -i 16'
stat-stat-unlink-flags =

pfbackoff = $(testdir)/pfbackoff.sh
# -v for verbose, -n# for number of rounds
# number of iters 'pfbackoff-flags=-v -n 8'
pfbackoff-flags =

saintmode-haproxy = $(testdir)/saintmode-haproxy.sh
# -v for verbose, -i# for number of write iters'saintmode-haproxy-flags=-v -i 16'
saintmode-haproxy-flags =

saintmode-nginx = $(testdir)/saintmode-nginx.sh
# -v for verbose, -i# for number of write iters'saintmode-nginx-flags=-v -i 16'
saintmode-nginx-flags =

saintmode-writes-nginx = $(testdir)/saintmode-writes-nginx.sh
# -v for verbose, -i# for number of write iters'saintmode-writes-nginx-flags=-v -i 16'
saintmode-writes-nginx-flags =

unhealthy-haproxy = $(testdir)/unhealthy-haproxy.sh
# -v for verbose, -i# for number of write iters'unhealthy-haproxy-flags=-v -i 16'
unhealthy-haproxy-flags =

# to run this test by invoking the Makefile, add binding=<binding id> to the make line
# make -f /opt/fusedav/tests/Makefile binding=1b8e45be7c264476bbbc6f65610b3490 run-timestamptest
# otherwise the test will exit prematurely
binding=none
# you must be in a binding's file directory to run this test.
# you must have at leasst 2 bindings in this environment
# you must give the binding id of the second binding
timestamptest = $(testdir)/timestamp.sh
# usage on Makefile line: 'timestamptest-flags=-i64 -b <other binding>'
# -i is iters; default is 64
timestamptest-flags=-b $(binding)

perfanalysis-write = $(testdir)/perfanalysis-write
# -v for verbose, 'perfanalysis-write-flags=-v'
# -i iters 'perfanalysis-write-flags=-i 8'
# -t start_time 'perfanalysis-write-flags=-t <unix epoch>'
perfanalysis-write-flags =

perfanalysis-read = $(testdir)/perfanalysis-read
# -v for verbose, 'perfanalysis-read-flags=-v'
# -i iters 'perfanalysis-read-flags=-i 8'
# -t start_time 'perfanalysis-read-flags=-t <unix epoch>'
perfanalysis-read-flags =

forensic-haven-cleanup = $(testdir)/forensic-haven-cleanup.sh
# -v for verbose, 'forensic-haven-cleanup-flags=-v'
forensic-haven-cleanup-flags =

all: run-simple-stress-tests run-nonfiles-tests

# S
#
# restrict unit tests to low-resource tests
run-unit-tests: echo-start run-cltest run-urlencode run-statcacheprune run-dutest run-writefiles-create run-readrecursive run-writefiles-remove run-readwhatwaswritten-unit run-readwhatwaswritten-unlink-unit run-continualwrites-unit run-rename run-trunc run-iozone-unit echo-finish

# stress test is all test, but run the stress version if there is both a unit and a stress version. e.g. iozone
run-stress-tests: echo-start run-cltest run-urlencode run-statcacheprune run-dutest run-writefiles-create run-readrecursive run-writefiles-remove run-readwhatwaswritten-stress run-readwhatwaswritten-unlink-stress run-continualwrites-unit run-rename run-trunc run-iozone-stress run-saintmode-haproxy run-saintmode-nginx run-unhealthy-haproxy run-saintmode-writes-nginx echo-finish

# simple stress test; don't run the 'saintmode' tests since they assume a unified development environment for creating error conditions which don't generally occur in production environments.
run-simple-stress-tests: echo-start run-cltest run-urlencode run-statcacheprune run-dutest run-writefiles-create run-readrecursive run-writefiles-remove run-readwhatwaswritten-stress run-readwhatwaswritten-unlink-stress run-continualwrites-unit run-rename run-trunc run-iozone-stress echo-finish

# I'm having difficulties running some tests in <bid dir>/files, and some just in <bid dir>. Separate these and
# handle on the command line. If someone can figure out the issues switching over file system boundaries,
# please make this better. For now, I run, from <bid dir>:
# make -f /root/pantheon/fusedav/tests/Makefile run-nonfiles-tests; (cd files; make -f /root/pantheon/fusedav/tests/Makefile)
run-nonfiles-tests: echo-start run-pfbackoff run-write-delete-checknegative run-forensic-haven-cleanup echo-finish

# stress test is all test, but run the stress version if there is both a unit and a stress version. e.g. iozone
# unlink test is creating increasing numbers of open files which never get closed. Remove for now.
# run-continual-tests: run-cltest run-urlencode run-statcacheprune run-writefiles-create run-readrecursive run-writefiles-remove run-readwhatwaswritten-stress run-readwhatwaswritten-unlink-stress run-trunc run-iozone-continual
run-continual-tests: echo-start run-cltest run-urlencode run-statcacheprune run-dutest run-writefiles-create run-readrecursive run-writefiles-remove run-readwhatwaswritten-stress run-readwhatwaswritten-unlink-stress run-trunc run-iozone-continual echo-finish

# short stress test is all tests but iozone, but run the stress version if there is both a unit and a stress version. e.g. iozone
run-short-stress-tests: echo-start run-cltest run-urlencode run-statcacheprune run-dutest run-writefiles-create run-readrecursive run-writefiles-remove run-readwhatwaswritten-stress run-readwhatwaswritten-unlink-stress run-continualwrites-unit run-rename run-trunc echo-finish

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

echo-start:
	@ echo "Start: "; date; echo "Current Directory: $(curdir)"

.PHONY: echo-finish
echo-finish:
	@ echo "Finish: "; date

run-cltest:
	$(cltest) $(cltest-flags)

run-urlencode:
	$(urlencode) $(urlencode-flags)

run-statcacheprune:
	$(statcacheprune) $(statcacheprune-dirs) $(statcacheprune-flags)

run-dutest:
	$(dutest) $(dutest-flags)

run-writefiles-create:
	$(writefiles-create) $(writefiles-create-flags)

run-writefiles-remove:
	$(writefiles-remove) $(writefiles-remove-flags)

.PHONY: run-write-delete-checknegative
run-write-delete-checknegative:
	$(write-delete-checknegative) $(write-delete-checknegative-flags)

.PHONY: run-forensic-haven-cleanup
run-forensic-haven-cleanup:
	$(forensic-haven-cleanup) $(forensic-haven-flags)

# Seems .PHONY is needed for this one; not sure why
.PHONY: run-pfbackoff
run-pfbackoff:
	$(pfbackoff) $(pfbackoff-flags)

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

run-rename: $(rename)
	$(rename) $(rename-flags)

$(rename): $(testdir)/rename.c
	cc $< -std=c99 -g -o $@

run-one-open-many-writes-unit: $(one-open-many-writes)
	$(one-open-many-writes) $(one-open-many-writes-flags)

$(one-open-many-writes): $(testdir)/one-open-many-writes.c
	cc $< -std=c99 -g -o $@

run-forensic-haven-unit: $(forensichaventest)
	$(forensichaventest) -f16 $(forensichaventest-flags)

$(forensichaventest): $(testdir)/forensic-haven-test.c
	cc $< -std=c99 -g -o $@

run-trunc: $(trunc)
	$(trunc) $(trunc-flags)

$(trunc): $(testdir)/trunc.c
	cc $< -std=c99 -g -o $@

run-stat-vs-fstat: $(stat-vs-fstat)
	$(stat-vs-fstat) $(stat-vs-fstat-flags)

$(stat-vs-fstat): $(testdir)/stat-vs-fstat.c
	cc $< -std=c99 -g -o $@

run-stat-stat: $(stat-stat)
	$(stat-stat) $(stat-stat-flags)

$(stat-stat): $(testdir)/stat-stat.c
	cc $< -std=c99 -g -o $@

run-stat-fstat: $(stat-fstat)
	$(stat-fstat) $(stat-fstat-flags)

$(stat-fstat): $(testdir)/stat-fstat.c
	cc $< -std=c99 -g -o $@

run-stat-fstat-unlink: $(stat-fstat-unlink)
	$(stat-fstat-unlink) $(stat-fstat-unlink-flags)

$(stat-fstat-unlink): $(testdir)/stat-fstat-unlink.c
	cc $< -std=c99 -g -o $@

run-stat-stat-unlink: $(stat-stat-unlink)
	$(stat-stat-unlink) $(stat-stat-unlink-flags)

$(stat-stat-unlink): $(testdir)/stat-stat-unlink.c
	cc $< -std=c99 -g -o $@

run-timestamptest:
	$(timestamptest) $(timestamptest-flags)

run-saintmode-haproxy:
	$(saintmode-haproxy) $(saintmode-haproxy-flags)

run-unhealthy-haproxy:
	$(unhealthy-haproxy) $(unhealthy-haproxy-flags)

run-saintmode-nginx:
	$(saintmode-nginx) $(saintmode-nginx-flags)

run-saintmode-writes-nginx:
	$(saintmode-writes-nginx) $(saintmode-writes-nginx-flags)

.PHONY: run-perfanalysis-write
run-perfanalysis-write: $(perfanalysis-write)
	$(perfanalysis-write) $(perfanalysis-write-flags)
	
$(perfanalysis-write): $(testdir)/perfanalysis-writeread.c
	cc $< -std=c99 -g -o $@

.PHONY: run-perfanalysis-read
run-perfanalysis-read: $(perfanalysis-read)
	$(perfanalysis-read) $(perfanalysis-read-flags)
	
$(perfanalysis-read): $(testdir)/perfanalysis-writeread.c
	cc $< -std=c99 -g -o $@
