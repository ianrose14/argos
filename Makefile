ARGOS_MAJOR_VERSION:=1
ARGOS_MINOR_VERSION:=8
ARGOS_VERSION_STR:=$(shell printf "%d.%02d" $(ARGOS_MAJOR_VERSION) $(ARGOS_MINOR_VERSION))

CC:=gcc
CFLAGS:=-ansi -std=c99 -pedantic -Wall -Wswitch-enum -Iinclude \
	-I$(HOME)/include -I/usr/local/include -fgnu89-inline -O2 -g \
	-DARGOS_MAJOR_VERSION=$(ARGOS_MAJOR_VERSION) \
	-DARGOS_MINOR_VERSION=$(ARGOS_MINOR_VERSION)

HEADERS:=$(shell find include -name \*.h)
LIBFLAGS:=-rpath $(HOME)/lib -rpath /usr/local/lib/ -Llib -lpcap -lpktparse

CLICKDIR:=click-1.7.0rc1

CLICK_DEPS:= \
    src/click/elements/argos/version.h \
	$(addprefix src/click/elements/argos/, \
	    $(notdir $(shell ls include/argos/*.h))) \
	$(addprefix src/click/elements/, \
	    binheap.h buffer.c buffer.h ieee802_11.h \
		quicklz.c quicklz.h)

COMMON_OBJS:=$(addprefix obj/, $(addsuffix .o, $(basename $(notdir \
	$(wildcard src/*.c)))))

ORION_OBJS:=$(addprefix obj/orion/, $(addsuffix .o, $(basename $(notdir \
	$(wildcard src/orion/*.c)))))

SNIFFER_OBJS:=$(addprefix obj/sniffer/, main.o net.o)

NETPCAPDUMP_OBJS:=$(addprefix obj/sniffer/, capture.o net.o netpcapdump.o)

PY_LIBS:=$(addprefix lib/python/, ansi.py argos.py argosdb.py argoslog.py \
    argosplot.py argosroutes.py argosstatusserver.py cdf.py rotatinglog.py wigle.py)

TESTS:=$(addprefix bin/test/, $(basename $(notdir $(wildcard src/orion/test/*.c) \
	$(wildcard src/argos/test/*.c) $(wildcard src/test/*.c))))

TOOLS:=$(addprefix bin/tools/, $(basename $(notdir $(wildcard src/tools/*.c))))

# List of all files that should be pushed to remote nodes (with the path they
# should use on the remote node; not the local path)
REL_DEPS:=code/argos/bin/argosniffer code/argos/bin/click code/argos/bin/netpcapdump \
	code/argos/argos.cfg code/argos/netpcapdump.cfg \
	$(addprefix code/argos/lib/python/, $(notdir $(wildcard lib/python/*.py))) \
	code/argos/scripts/logviewer.py lib/libpq.so.5

# boilerplate:
DEPS:=$(foreach file, $(REL_DEPS), $(DEPLOY)/$(file))
DEPDIRS:=$(foreach file, $(REL_DEPS), $(DEPLOY)/$(dir $(file))) $(DEPLOY)/code/argos/dumps

.PHONY: all clean click click-clean click-conf click-elemlist \
	deployment dirs FORCE init install orion python refresh-sniffer \
    sniffer tests tools
.SECONDARY:

# phony targets:

all: sniffer click python tests tools bin/netpcapdump

clean-all:  clean click-clean

clean:
	rm -rf bin/* obj/* src/*.pyc lib/* *.core

click: $(CLICK_DEPS)
	cp $(HOME)/include/pcap.h $(CLICKDIR)/include/
	cp $(HOME)/include/pcap.h $(CLICKDIR)/build/include/
	rsync -avh $(HOME)/include/pcap $(CLICKDIR)/include/
	rsync -avh $(HOME)/include/pcap $(CLICKDIR)/build/include/
	cp $(HOME)/lib/libpcap.a $(CLICKDIR)/build/lib/
	cd $(CLICKDIR) && make install
	cp $(CLICKDIR)/build/bin/click bin/click
	cp $(CLICKDIR)/build/bin/click-check bin/click-check
	cp $(CLICKDIR)/build/bin/click-combine bin/click-combine
	mkdir -p bin/versions
	cp bin/click bin/versions/click-v$(ARGOS_VERSION_STR)

click-clean:
	cd $(CLICKDIR) && make clean

# elements/local must exist or --enabled-local doesn't work right!
click-conf: $(CLICKDIR) $(CLICKDIR)/elements/local
	cd $(CLICKDIR) && ./configure --prefix=$(CURDIR)/$(CLICKDIR)/build/ \
--enable-analysis --enable-local --enable-wifi --disable-linuxmodule \
--disable-threads --enable-stats=0 --disable-app --enable-task-heap \
CFLAGS="-g -O2" CXXFLAGS="-g -I/usr/local/include -I$(HOME)/include"

click-elemlist:
	cd $(CLICKDIR) && make elemlist

FORCE:

# prepare to push to remote node:
deployment: init dirs $(DEPS)
	strip $(DEPLOY)/code/argos/bin/*

dirs:
	@mkdir -p $(DEPDIRS)

init: bin/argosniffer
ifndef DEPLOY
	$(error DEPLOY not specified)
endif

install: sniffer python tests tools
	install -d -C $(HOME)/code/argos/bin/
	install -d -C $(HOME)/code/argos/bin/test/
	install -d -C $(HOME)/code/argos/bin/tools/
	install -d -C $(HOME)/code/argos/lib/
	install -d -C $(HOME)/code/argos/lib/python
	install -d -C $(HOME)/code/argos/scripts/
	install -C bin/argosniffer $(HOME)/code/argos/bin/
	install -C bin/netpcapdump $(HOME)/code/argos/bin/
	install -C bin/click $(HOME)/code/argos/bin/
	install -C bin/test/* $(HOME)/code/argos/bin/test/
	install -C bin/tools/* $(HOME)/code/argos/bin/tools/
	install -C lib/python/*.py $(HOME)/code/argos/lib/python
	install -C /usr/local/lib/libpq.so.5 $(HOME)/lib/
	install -C scripts/*.py $(HOME)/code/argos/scripts
	install -C -m 0660 argos.cfg $(HOME)/code/argos/
	install -C -m 0660 netpcapdump.cfg $(HOME)/code/argos/
	rm -rf $(HOME)/code/argos/config/
	install -d -C $(HOME)/code/argos/config/
	rsync -a config/ $(HOME)/code/argos/config/

orion:  $(ORION_OBJS)

python: $(PY_LIBS)
	cd src/python/dictify && make install

# force main.c to recompile to get the right build date/time
refresh-sniffer:
	@rm -f obj/sniffer/main.o
	@rm -f obj/sniffer/netpcapdump.o
	@rm -f obj/sniffer/dumpserver.o

sniffer: refresh-sniffer bin/argosniffer bin/netpcapdump
	mkdir -p bin/versions
	cp bin/argosniffer bin/versions/argosniffer-v$(ARGOS_VERSION_STR)

tests: $(TESTS)

tools: $(TOOLS)

# real targets:

# download, unpack and patch click
$(CLICKDIR):
	wget http://read.cs.ucla.edu/click/$(CLICKDIR).tar.gz
	tar xvfz $(CLICKDIR).tar.gz
	rm $(CLICKDIR).tar.gz
	cat src/click/patches/* | patch

$(DEPLOY)/code/argos/%: %
	@mkdir -p $(dir $@)
	cp $< $@

# libpq is required by the PostgreSQL element and must be linkable from click
# even on the nodes (which don't even use the PostgreSQL element)
$(DEPLOY)/lib/libpq.so.5: /usr/local/lib/libpq.so.5
	cp $< $@

bin/argosniffer: $(SNIFFER_OBJS) $(ORION_OBJS) $(COMMON_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBFLAGS)

bin/netpcapdump: $(NETPCAPDUMP_OBJS) $(ORION_OBJS) $(COMMON_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBFLAGS) -lm

bin/test/async-test: obj/test/async-test.o obj/async.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBFLAGS)

bin/test/binheap-test: obj/test/binheap-test.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBFLAGS)

bin/test/circbuf-test: obj/test/circbuf-test.o obj/circbuf.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $^

bin/test/multipcap-test: obj/test/multipcap-test.o obj/async.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBFLAGS)

bin/test/rangemap-test: obj/test/rangemap-test.o obj/rangemap.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBFLAGS)

bin/test/vector-test: obj/test/vector-test.o obj/vector.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBFLAGS)

bin/test/%-test: obj/orion/test/%-test.o $(ORION_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBFLAGS)

bin/tools/%: obj/tools/%.o obj/async.o $(ORION_OBJS) $(COMMON_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBFLAGS)

bin/%: obj/%.o
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBFLAGS)

lib/python/%.py: src/python/%.py
	@mkdir -p $(dir $@)
	cp $< $@

obj/%.o: src/%.c $(HEADERS) Makefile
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

# files that need to be copied into click directories
src/click/elements/ieee802_11.h: $(HOME)/include/ieee802_11.h
	@mkdir -p $(dir $@)
	rm -f $@
	cp $< $@
	chmod -w $@

src/click/elements/argos/version.h: FORCE
	@echo "#ifndef _ARGOS_VERSION_H_" > $@
	@echo "#define _ARGOS_VERSION_H_" >> $@
	@echo "#define ARGOS_MAJOR_VERSION " $(ARGOS_MAJOR_VERSION) >> $@
	@echo "#define ARGOS_MINOR_VERSION " $(ARGOS_MINOR_VERSION) >> $@
	@echo "#endif" >> $@

src/click/elements/%.h: include/%.h
	@mkdir -p $(dir $@)
	rm -f $@
	cp -R $< $@
	chmod -w $@

src/click/elements/%.c: src/%.c
	@mkdir -p $(dir $@)
	rm -f $@
	cp $< $@
	chmod -w $@

$(CLICKDIR)/elements/local:
	rm -f $@
	ln -s ../../src/click/elements $@

$(CLICKDIR)/include/click/%.h: include/%.h
	@mkdir -p $(dir $@)
	rm -f $@
	cp $< $@
	chmod -w $@

$(CLICKDIR)/include/click/%.hh: include/click/%.hh
	@mkdir -p $(dir $@)
	rm -f $@
	cp $< $@
	chmod -w $@

$(CLICKDIR)/lib/%.c: src/%.c
	@mkdir -p $(dir $@)
	rm -f $@
	cp $< $@
	chmod -w $@

$(CLICKDIR)/lib/%.cc: src/click/lib/%.cc
	@mkdir -p $(dir $@)
	rm -f $@
	cp $< $@
	chmod -w $@

$(CLICKDIR)/build/lib/%: lib/%
	@mkdir -p $(dir $@)
	rm -f $@
	cp $< $@

crap: crap.c $(HEADERS) Makefile
	$(CC) -ansi -std=c99 -pedantic -Wall -Wswitch-enum -Iinclude -I$(HOME)/include -I/usr/local/include -g -o crap.out crap.c src/quicklz.c $(ORION_OBJS)
#	$(CC) $(CFLAGS) -o crap.out crap.c src/quicklz.c $(ORION_OBJS) -lpcap -lm -lpktparse
