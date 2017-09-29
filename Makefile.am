AM_CFLAGS = -Wall -Wextra -D_FORTIFY_SOURCE=2 $(PIE_CFLAGS) $(RELRO_CFLAGS)
ACLOCAL_AMFLAGS = -I aclocal

root_sbindir = $(ROOTSBINDIR)
root_sbin_PROGRAMS = mount.cifs
mount_cifs_SOURCES = mount.cifs.c mtab.c resolve_host.c util.c
mount_cifs_LDADD = $(LIBCAP) $(CAPNG_LDADD) $(RT_LDADD)
include_HEADERS = cifsidmap.h
pod_man_pages = mount.cifs.8

#
# Generate man pages troff source from POD format
#

man_MANS=

POD2MAN = pod2man -s $$(echo $@ | sed 's,.*\([1-9]\)$$,\1,' ) \
                  -c 'System Administration Tools' -u -r '' --stderr $< $@

%.1: %.pod
	$(POD2MAN)
%.2: %.pod
	$(POD2MAN)
%.3: %.pod
	$(POD2MAN)
%.4: %.pod
	$(POD2MAN)
%.5: %.pod
	$(POD2MAN)
%.6: %.pod
	$(POD2MAN)
%.7: %.pod
	$(POD2MAN)
%.8: %.pod
	$(POD2MAN)

CLEANFILES =
bin_PROGRAMS =
sbin_PROGRAMS =

if CONFIG_CIFSUPCALL
sbin_PROGRAMS += cifs.upcall
cifs_upcall_SOURCES = cifs.upcall.c data_blob.c asn1.c spnego.c
cifs_upcall_LDADD = -ltalloc -lkeyutils $(KRB5_LDADD) $(CAPNG_LDADD)
pod_man_pages += cifs.upcall.8
#
# Fix the pathnames in manpages. To prevent @label@ being replaced by m4, we
# need to obfuscate the LHS of the regex (hence the trivial one character set).
#
cifs.upcall.pod: cifs.upcall.pod.in
	$(SED) 's,[@]sbindir@,$(sbindir),' $(srcdir)/$@.in > $@-t && mv $@-t $@
endif

if CONFIG_CIFSCREDS
bin_PROGRAMS += cifscreds
cifscreds_SOURCES = cifscreds.c cifskey.c resolve_host.c util.c
cifscreds_LDADD = -lkeyutils

pod_man_pages += cifscreds.1

endif

if CONFIG_CIFSIDMAP
sbin_PROGRAMS += cifs.idmap
cifs_idmap_SOURCES = cifs.idmap.c idmap_plugin.c
cifs_idmap_LDADD = -lkeyutils -ldl
pod_man_pages += cifs.idmap.8
CLEANFILES += cifs.idmap.pod
cifs.idmap.pod: cifs.idmap.pod.in
	$(SED) -e 's,[@]sbindir@,$(sbindir),' -e 's,[@]pluginpath@,$(pluginpath),' $(srcdir)/$@.in > $@-t && mv $@-t $@
endif

if CONFIG_CIFSACL
bin_PROGRAMS += getcifsacl
getcifsacl_SOURCES = getcifsacl.c idmap_plugin.c
getcifsacl_LDADD = -ldl

pod_man_pages += getcifsacl.1
CLEANFILES += getcifsacl.pod
getcifsacl.pod: getcifsacl.pod.in
	$(SED) 's,[@]pluginpath@,$(pluginpath),' $(srcdir)/$@.in > $@-t && mv $@-t $@

bin_PROGRAMS += setcifsacl
setcifsacl_SOURCES = setcifsacl.c idmap_plugin.c
setcifsacl_LDADD = -ldl

pod_man_pages += setcifsacl.1
CLEANFILES += setcifsacl.pod
setcifsacl.pod: setcifsacl.pod.in
	$(SED) 's,[@]pluginpath@,$(pluginpath),' $(srcdir)/$@.in > $@-t && mv $@-t $@
endif

if CONFIG_PLUGIN
plugindir = $(pkglibdir)
plugin_PROGRAMS = idmapwb.so
idmapwb.so: idmapwb.c
	$(CC) $(DEFS) $(CFLAGS) $(AM_CFLAGS) $(WBCLIENT_CFLAGS) $(LDFLAGS) -shared -fpic -o $@ $+ $(WBCLIENT_LIBS)

pod_man_pages += idmapwb.8
CLEANFILES += idmapwb.pod
idmapwb.pod: idmapwb.pod.in
	$(SED) 's,[@]pluginpath@,$(pluginpath),' $(srcdir)/$@.in > $@-t && mv $@-t $@
endif

if CONFIG_PAM
pam_PROGRAMS = pam_cifscreds.so
pod_man_pages += pam_cifscreds.8
pam_cifscreds.so: pam_cifscreds.c cifskey.c resolve_host.c util.c
	$(CC) $(DEFS) $(CFLAGS) $(AM_CFLAGS) $(LDFLAGS) -shared -fpic -o $@ $+ -lpam -lkeyutils

endif

if CONFIG_MAN
man_MANS += $(pod_man_pages)
CLEANFILES += $(pod_man_pages)
endif

SUBDIRS = contrib
