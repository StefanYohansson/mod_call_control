depend: mod-deps

include $(top_srcdir)/build/modmake.rulesam

MODNAME = mod_call_control

mod-deps:
	mkdir -p deps/onion-build ; \
	cd deps/onion-build ; \
	BUILD_STATIC=1 cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DONION_USE_PNG=false -DONION_USE_JPEG=false -DONION_USE_XML2=false -DONION_USE_SYSTEMD=false -DONION_USE_SQLITE3=false -DONION_USE_REDIS=false -DONION_USE_GC=false -DONION_USE_TESTS=false -DONION_EXAMPLES=false -DONION_USE_BINDINGS_CPP=false ../onion ; \
	make ; \
	make install

if HAVE_KS
mod_LTLIBRARIES = mod_call_control.la
mod_call_control_la_SOURCES  = mod_call_control.c call_control_webhook.c call_control_api.c
mod_call_control_la_CFLAGS   = $(AM_CFLAGS)
mod_call_control_la_CFLAGS  += $(CURL_CFLAGS) $(KS_CFLAGS)
mod_call_control_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_call_control_la_LDFLAGS  = $(CURL_LIBS) -avoid-version -module -no-undefined -shared $(KS_LIBS) -lonion
else
install: error
all: error
error:
	$(error You must install libks to build mod_call_control)
endif
