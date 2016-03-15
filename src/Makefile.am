AM_CFLAGS = $(MORE_CFLAGS)
AM_CPPFLAGS = $(MORE_CPPFLAGS)
AM_LDFLAGS = $(MORE_LDFLAGS)

libdir = $(PAMDIR)

## dist_man_MANS = pam_apparmor_ingroup.8
lib_LTLIBRARIES = pam_apparmor_ingroup.la

## pam_apparmor_ingroup_la_LIBADD = -lpam
pam_apparmor_ingroup_la_SOURCES = pam_apparmor_ingroup.c

pam_apparmor_ingroup_la_LIBADD = -lpam
pam_apparmor_ingroup_la_LIBADD += $(APPARMOR_LIBS)
pam_apparmor_ingroup_la_LDFLAGS = -module -avoid-version

install-exec-hook:
	rm -f $(PAMDIR)/pam_apparmor_ingroup.la
	chmod -f 644 $(PAMDIR)/pam_apparmor_ingroup.so || true
