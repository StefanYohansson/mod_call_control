include $(top_srcdir)/build/modmake.rulesam

MODNAME = mod_call_control

if HAVE_KS
mod_LTLIBRARIES = mod_call_control.la
mod_call_control_la_SOURCES  = mod_call_control.c call_control_webhook.c call_control_api.c
mod_call_control_la_CFLAGS   = $(AM_CFLAGS)
mod_call_control_la_CFLAGS  += $(CURL_CFLAGS) $(KS_CFLAGS)
mod_call_control_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_call_control_la_LDFLAGS  = $(CURL_LIBS) -avoid-version -module -no-undefined -shared $(KS_LIBS)
else
install: error
all: error
error:
	$(error You must install libks to build mod_call_control)
endif
