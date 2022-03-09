/*
* CIFS user-space helper.
* Copyright (C) Igor Mammedov (niallain@gmail.com) 2007
* Copyright (C) Jeff Layton (jlayton@samba.org) 2010
*
* Used by /sbin/request-key for handling
* cifs upcall for kerberos authorization of access to share and
* cifs upcall for DFS srver name resolving (IPv4/IPv6 aware).
* You should have keyutils installed and add something like the
* following lines to /etc/request-key.conf file:

    create cifs.spnego * * /usr/local/sbin/cifs.upcall %k
    create dns_resolver * * /usr/local/sbin/cifs.upcall %k

* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <string.h>
#include <getopt.h>
#ifdef HAVE_KRB5_KRB5_H
#include <krb5/krb5.h>
#elif defined(HAVE_KRB5_H)
#include <krb5.h>
#endif

#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>
#include <sys/utsname.h>

#include <syslog.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <keyutils.h>
#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <stdbool.h>
#include <errno.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "data_blob.h"
#include "spnego.h"
#include "cifs_spnego.h"

#ifdef HAVE_LIBCAP_NG
#include <cap-ng.h>
#endif

#ifndef discard_const
#define discard_const(ptr) ((void *)((intptr_t)(ptr)))
#endif

static krb5_context	context;
static const char	*prog = "cifs.upcall";

#define DNS_RESOLVER_DEFAULT_TIMEOUT 600 /* 10 minutes */

typedef enum _sectype {
	NONE = 0,
	KRB5,
	MS_KRB5
} sectype_t;

/* These macros unify the keyblock handling of Heimdal and MIT somewhat */
#ifdef HAVE_KRB5_KEYBLOCK_KEYVALUE /* Heimdal */
#define KRB5_KEY_TYPE(k)        ((k)->keytype)
#define KRB5_KEY_LENGTH(k)      ((k)->keyvalue.length)
#define KRB5_KEY_DATA(k)        ((k)->keyvalue.data)
#define KRB5_KEY_DATA_CAST      void
#else /* MIT */
#define KRB5_KEY_TYPE(k)        ((k)->enctype)
#define KRB5_KEY_LENGTH(k)      ((k)->length)
#define KRB5_KEY_DATA(k)        ((k)->contents)
#define KRB5_KEY_DATA_CAST      krb5_octet
#endif

#ifdef HAVE_LIBCAP_NG
static int
trim_capabilities(bool need_environ)
{
	capng_select_t set = CAPNG_SELECT_CAPS;

	capng_clear(CAPNG_SELECT_BOTH);

	/* SETUID and SETGID to change uid, gid, and grouplist */
	if (capng_updatev(CAPNG_ADD, CAPNG_PERMITTED|CAPNG_EFFECTIVE,
			CAP_SETUID, CAP_SETGID, -1)) {
		syslog(LOG_ERR, "%s: Unable to update capability set: %m\n", __func__);
		return 1;
	}

	 /* Need PTRACE and READ_SEARCH for /proc/pid/environ scraping */
	if (need_environ &&
	    capng_updatev(CAPNG_ADD, CAPNG_PERMITTED|CAPNG_EFFECTIVE,
			CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH, -1)) {
		syslog(LOG_ERR, "%s: Unable to update capability set: %m\n", __func__);
		return 1;
	}

	if (capng_have_capability(CAPNG_EFFECTIVE, CAP_SETPCAP)) {
		set = CAPNG_SELECT_BOTH;
	}
	if (capng_apply(set)) {
		syslog(LOG_ERR, "%s: Unable to apply capability set: %m\n", __func__);
		return 1;
	}
	return 0;
}

static int
drop_all_capabilities(void)
{
	capng_select_t set = CAPNG_SELECT_CAPS;

	capng_clear(CAPNG_SELECT_BOTH);
	if (capng_have_capability(CAPNG_EFFECTIVE, CAP_SETPCAP)) {
		set = CAPNG_SELECT_BOTH;
	}
	if (capng_apply(set)) {
		syslog(LOG_ERR, "%s: Unable to apply capability set: %m\n", __func__);
		return 1;
	}
	return 0;
}
#else /* HAVE_LIBCAP_NG */
static int
trim_capabilities(bool unused)
{
	(void)unused;
	return 0;
}

static int
drop_all_capabilities(void)
{
	return 0;
}
#endif /* HAVE_LIBCAP_NG */

/*
 * smb_krb5_principal_get_realm
 *
 * @brief Get realm of a principal
 *
 * @param[in] context		The krb5_context
 * @param[in] principal		The principal
 * @return pointer to the realm
 *
 */
static char *cifs_krb5_principal_get_realm(krb5_principal principal)
{
#ifdef HAVE_KRB5_PRINCIPAL_GET_REALM	/* Heimdal */
	return krb5_principal_get_realm(context, principal);
#elif defined(krb5_princ_realm)	/* MIT */
	krb5_data *realm;
	realm = krb5_princ_realm(context, principal);
	return (char *)realm->data;
#else
	return NULL;
#endif
}

#if !defined(HAVE_KRB5_FREE_UNPARSED_NAME)
static void krb5_free_unparsed_name(krb5_context context, char *val)
{
	free(val);
}
#endif

#if !defined(HAVE_KRB5_AUTH_CON_GETSENDSUBKEY)	/* Heimdal */
static krb5_error_code
krb5_auth_con_getsendsubkey(krb5_context context,
			    krb5_auth_context auth_context,
			    krb5_keyblock **keyblock)
{
	return krb5_auth_con_getlocalsubkey(context, auth_context, keyblock);
}
#endif

/* does the ccache have a valid TGT? */
static time_t get_tgt_time(krb5_ccache ccache)
{
	krb5_cc_cursor cur;
	krb5_creds creds;
	krb5_principal principal;
	time_t credtime = 0;
	char *realm = NULL;

	if (krb5_cc_set_flags(context, ccache, 0)) {
		syslog(LOG_DEBUG, "%s: unable to set flags", __func__);
		goto err_cache;
	}

	if (krb5_cc_get_principal(context, ccache, &principal)) {
		syslog(LOG_DEBUG, "%s: unable to get principal", __func__);
		goto err_cache;
	}

	if (krb5_cc_start_seq_get(context, ccache, &cur)) {
		syslog(LOG_DEBUG, "%s: unable to seq start", __func__);
		goto err_ccstart;
	}

	if ((realm = cifs_krb5_principal_get_realm(principal)) == NULL) {
		syslog(LOG_DEBUG, "%s: unable to get realm", __func__);
		goto err_ccstart;
	}

	while (!credtime && !krb5_cc_next_cred(context, ccache, &cur, &creds)) {
		char *name;
		if (krb5_unparse_name(context, creds.server, &name)) {
			syslog(LOG_DEBUG, "%s: unable to unparse name",
			       __func__);
			goto err_endseq;
		}
		if (krb5_realm_compare(context, creds.server, principal) &&
		    !strncasecmp(name, KRB5_TGS_NAME, KRB5_TGS_NAME_SIZE) &&
		    !strncasecmp(name + KRB5_TGS_NAME_SIZE + 1, realm,
				 strlen(realm))
		    && creds.times.endtime > time(NULL))
			credtime = creds.times.endtime;
		krb5_free_cred_contents(context, &creds);
		krb5_free_unparsed_name(context, name);
	}
err_endseq:
	krb5_cc_end_seq_get(context, ccache, &cur);
err_ccstart:
	krb5_free_principal(context, principal);
err_cache:
	return credtime;
}

static struct namespace_file {
	int nstype;
	const char *name;
	int fd;
} namespace_files[] = {

#ifdef CLONE_NEWCGROUP
	{ CLONE_NEWCGROUP, "cgroup", -1 },
#endif

#ifdef CLONE_NEWIPC
	{ CLONE_NEWIPC, "ipc", -1 },
#endif

#ifdef CLONE_NEWUTS
	{ CLONE_NEWUTS, "uts", -1 },
#endif

#ifdef CLONE_NEWNET
	{ CLONE_NEWNET, "net", -1 },
#endif

#ifdef CLONE_NEWPID
	{ CLONE_NEWPID, "pid", -1 },
#endif

#ifdef CLONE_NEWTIME
	{ CLONE_NEWTIME, "time", -1 },
#endif

#ifdef CLONE_NEWNS
	{ CLONE_NEWNS, "mnt", -1 },
#endif

#ifdef CLONE_NEWUSER
	{ CLONE_NEWUSER, "user", -1 },
#endif
};

#define NS_PATH_FMT    "/proc/%d/ns/%s"
#define NS_PATH_MAXLEN (6 + 10 + 4 + 6 + 1)

/**
 * in_same_user_ns - return true if two processes are in the same user
 *                   namespace.
 * @pid_a: the pid of the first process
 * @pid_b: the pid of the second process
 *
 * Works by comparing the inode numbers for /proc/<pid>/user.
 */
static int
in_same_user_ns(pid_t pid_a, pid_t pid_b)
{
	char path[NS_PATH_MAXLEN];
	ino_t a_ino, b_ino;
	struct stat st;

	snprintf(path, sizeof(path), NS_PATH_FMT, pid_a, "user");
	if (stat(path, &st) != 0)
		return 0;
	a_ino = st.st_ino;

	snprintf(path, sizeof(path), NS_PATH_FMT, pid_b, "user");
	if (stat(path, &st) != 0)
		return 0;
	b_ino = st.st_ino;

	return a_ino == b_ino;
}

/**
 * switch_to_process_ns - change the namespace to the one for the specified
 *                        process.
 * @pid: initiating pid value from the upcall string
 *
 * Uses setns() to switch process namespace.
 * This ensures that we have the same access and configuration as the
 * process that triggered the lookup.
 */
static int
switch_to_process_ns(pid_t pid)
{
	int count = sizeof(namespace_files) / sizeof(struct namespace_file);
	int n, err = 0;
	int rc = 0;

	/* First, open all the namespace fds.  We do this first because
	   the namespace changes might prohibit us from opening them. */
	for (n = 0; n < count; ++n) {
		char nspath[NS_PATH_MAXLEN];
		int ret, fd;

#ifdef CLONE_NEWUSER
		if (namespace_files[n].nstype == CLONE_NEWUSER
		    && in_same_user_ns(getpid(), pid)) {
			/* Switching to the same user namespace is forbidden,
			   because switching to a user namespace grants all
			   capabilities in that namespace regardless of uid. */
			namespace_files[n].fd = -1;
			continue;
		}
#endif

		ret = snprintf(nspath, NS_PATH_MAXLEN, NS_PATH_FMT,
			       pid, namespace_files[n].name);
		if (ret >= NS_PATH_MAXLEN) {
			syslog(LOG_DEBUG, "%s: unterminated path!\n", __func__);
			err = ENAMETOOLONG;
			rc = -1;
			goto out;
		}

		fd = open(nspath, O_RDONLY);
		if (fd < 0 && errno != ENOENT) {
			/*
			 * don't stop on non-existing ns
			 * but stop for other errors
			 */
			err = errno;
			rc = -1;
			goto out;
		}

		namespace_files[n].fd = fd;
	}

	/* Next, call setns for each of them */
	for (n = 0; n < count; ++n) {
		/* skip non-existing ns */
		if (namespace_files[n].fd < 0)
			continue;

		rc = setns(namespace_files[n].fd, namespace_files[n].nstype);

		if (rc < 0) {
			syslog(LOG_DEBUG, "%s: setns() failed for %s\n",
			       __func__, namespace_files[n].name);
			err = errno;
			goto out;
		}
	}

out:
	/* Finally, close all the fds */
	for (n = 0; n < count; ++n) {
		if (namespace_files[n].fd != -1) {
			close(namespace_files[n].fd);
			namespace_files[n].fd = -1;
		}
	}

	if (rc != 0) {
		errno = err;
	}

	return rc;
}

#define	ENV_PATH_FMT			"/proc/%d/environ"
#define	ENV_PATH_MAXLEN			(6 + 10 + 8 + 1)

#define	ENV_NAME			"KRB5CCNAME"
#define	ENV_PREFIX			"KRB5CCNAME="
#define	ENV_PREFIX_LEN			11

#define	ENV_BUF_START			(4096)
#define	ENV_BUF_MAX			(131072)

/**
 * get_cachename_from_process_env - scrape value of $KRB5CCNAME out of the
 * 				    initiating process' environment.
 * @pid: initiating pid value from the upcall string
 *
 * Open the /proc/<pid>/environ file for the given pid, and scrape it for
 * KRB5CCNAME entries.
 *
 * We start with a page-size buffer, and then progressively double it until
 * we can slurp in the whole thing.
 *
 * Note that this is not entirely reliable. If the process is sitting in a
 * container or something, then this is almost certainly not going to point
 * where you expect.
 *
 * Probably it just won't work, but could a user use this to trick cifs.upcall
 * into reading a file outside the container, by setting KRB5CCNAME in a
 * crafty way?
 */
static char *
get_cachename_from_process_env(pid_t pid)
{
	int fd, ret;
	ssize_t buflen;
	ssize_t bufsize = ENV_BUF_START;
	char pathname[ENV_PATH_MAXLEN];
	char *cachename = NULL;
	char *buf = NULL, *pos;

	if (!pid) {
		syslog(LOG_DEBUG, "%s: pid == 0\n", __func__);
		return NULL;
	}

	pathname[ENV_PATH_MAXLEN - 1] = '\0';
	ret = snprintf(pathname, ENV_PATH_MAXLEN, ENV_PATH_FMT, pid);
	if (ret >= ENV_PATH_MAXLEN) {
		syslog(LOG_DEBUG, "%s: unterminated path!\n", __func__);
		return NULL;
	}

	syslog(LOG_DEBUG, "%s: pathname=%s\n", __func__, pathname);
	fd = open(pathname, O_RDONLY);
	if (fd < 0) {
		syslog(LOG_DEBUG, "%s: open failed: %d\n", __func__, errno);
		return NULL;
	}
retry:
	if (bufsize > ENV_BUF_MAX) {
		syslog(LOG_DEBUG, "%s: buffer too big: %zd\n",
							__func__, bufsize);
		goto out_close;
	}

	buf = malloc(bufsize);
	if (!buf) {
		syslog(LOG_DEBUG, "%s: malloc failure\n", __func__);
		goto out_close;
	}

	buflen = read(fd, buf, bufsize);
	if (buflen < 0) {
		syslog(LOG_DEBUG, "%s: read failed: %d\n", __func__, errno);
		goto out_close;
	}

	if (buflen >= bufsize) {
		/* We read to the end of the buffer. Double and try again */
		syslog(LOG_DEBUG, "%s: read to end of buffer (%zu bytes)\n",
					__func__, bufsize);
		free(buf);
		bufsize *= 2;
		if (lseek(fd, 0, SEEK_SET) < 0)
			goto out_close;
		goto retry;
	}

	pos = buf;
	while (buflen > 0) {
		size_t len = strnlen(pos, buflen);

		if (len > ENV_PREFIX_LEN &&
		    !memcmp(pos, ENV_PREFIX, ENV_PREFIX_LEN)) {
			cachename = strndup(pos + ENV_PREFIX_LEN,
							len - ENV_PREFIX_LEN);
			syslog(LOG_DEBUG, "%s: cachename = %s\n",
							__func__, cachename);
			break;
		}
		buflen -= (len + 1);
		pos += (len + 1);
	}
out_close:
	free(buf);
	close(fd);
	return cachename;
}

static krb5_ccache
get_existing_cc(const char *env_cachename)
{
	krb5_error_code ret;
	krb5_ccache cc;
	char *cachename;

	if (env_cachename) {
		if (setenv(ENV_NAME, env_cachename, 1))
			syslog(LOG_DEBUG, "%s: failed to setenv %d\n", __func__, errno);
	}

	ret = krb5_cc_default(context, &cc);
	if (ret) {
		syslog(LOG_DEBUG, "%s: krb5_cc_default returned %d", __func__, ret);
		return NULL;
	}

	ret = krb5_cc_get_full_name(context, cc, &cachename);
	if (ret) {
		syslog(LOG_DEBUG, "%s: krb5_cc_get_full_name failed: %d\n", __func__, ret);
	} else {
		syslog(LOG_DEBUG, "%s: default ccache is %s\n", __func__, cachename);
		krb5_free_string(context, cachename);
	}

	if (!get_tgt_time(cc)) {
		krb5_cc_close(context, cc);
		cc = NULL;
	}
	return cc;
}

static krb5_ccache
init_cc_from_keytab(const char *keytab_name, const char *user)
{
	krb5_error_code ret;
	krb5_creds my_creds;
	krb5_keytab keytab = NULL;
	krb5_principal me = NULL;
	krb5_ccache cc = NULL;

	memset((char *) &my_creds, 0, sizeof(my_creds));

	/*
	 * Unset the environment variable, if any. If we're creating our own
	 * credcache here, stick it in the default location.
	 */
	unsetenv(ENV_NAME);

	if (keytab_name)
		ret = krb5_kt_resolve(context, keytab_name, &keytab);
	else
		ret = krb5_kt_default(context, &keytab);

	if (ret) {
		syslog(LOG_DEBUG, "%s: %d",
			keytab_name ? "krb5_kt_resolve" : "krb5_kt_default",
			(int)ret);
		goto icfk_cleanup;
	}

	ret = krb5_parse_name(context, user, &me);
	if (ret) {
		syslog(LOG_DEBUG, "krb5_parse_name: %d", (int)ret);
		goto icfk_cleanup;
	}

	ret = krb5_get_init_creds_keytab(context, &my_creds, me,
			keytab, 0, NULL, NULL);
	if (ret) {
		syslog(LOG_DEBUG, "krb5_get_init_creds_keytab: %d", (int)ret);
		goto icfk_cleanup;
	}

	ret = krb5_cc_resolve(context, "MEMORY:", &cc);
	if (ret) {
		syslog(LOG_DEBUG, "krb5_cc_resolve: %d", (int)ret);
		goto icfk_cleanup;
	}

	ret = krb5_cc_initialize(context, cc, me);
	if (ret) {
		syslog(LOG_DEBUG, "krb5_cc_initialize: %d", (int)ret);
		goto icfk_cleanup;
	}

	ret = krb5_cc_store_cred(context, cc, &my_creds);
	if (ret) {
		syslog(LOG_DEBUG, "krb5_cc_store_cred: %d", (int)ret);
		goto icfk_cleanup;
	}
out:
	my_creds.client = (krb5_principal)0;
	krb5_free_cred_contents(context, &my_creds);

	if (me)
		krb5_free_principal(context, me);
	if (keytab)
		krb5_kt_close(context, keytab);
	return cc;
icfk_cleanup:
	if (cc) {
		krb5_cc_close(context, cc);
		cc = NULL;
	}
	goto out;
}

#define CIFS_SERVICE_NAME "cifs"

static int
cifs_krb5_get_req(const char *host, krb5_ccache ccache,
		  DATA_BLOB * mechtoken, DATA_BLOB * sess_key)
{
	krb5_error_code ret;
	krb5_keyblock *tokb;
	krb5_creds in_creds, *out_creds;
	krb5_data apreq_pkt, in_data;
	krb5_auth_context auth_context = NULL;
#if defined(HAVE_KRB5_AUTH_CON_SETADDRS) && defined(HAVE_KRB5_AUTH_CON_SET_REQ_CKSUMTYPE)
	static char gss_cksum[24] = { 0x10, 0x00, /* ... */};
#endif
	memset(&in_creds, 0, sizeof(in_creds));

	ret = krb5_cc_get_principal(context, ccache, &in_creds.client);
	if (ret) {
		syslog(LOG_DEBUG, "%s: unable to get client principal name",
		       __func__);
		return ret;
	}

	ret = krb5_sname_to_principal(context, host, CIFS_SERVICE_NAME,
					KRB5_NT_UNKNOWN, &in_creds.server);
	if (ret) {
		syslog(LOG_DEBUG, "%s: unable to convert sname to princ (%s).",
		       __func__, host);
		goto out_free_principal;
	}

	ret = krb5_get_credentials(context, 0, ccache, &in_creds, &out_creds);
	krb5_free_principal(context, in_creds.server);
	if (ret) {
		syslog(LOG_DEBUG, "%s: unable to get credentials for %s",
		       __func__, host);
		goto out_free_principal;
	}

	in_data.length = 0;
	in_data.data = NULL;

	ret = krb5_auth_con_init(context, &auth_context);
	if (ret) {
		syslog(LOG_DEBUG, "%s: unable to create auth_context: %d",
		       __func__, ret);
		goto out_free_creds;
	}

#if defined(HAVE_KRB5_AUTH_CON_SETADDRS) && defined(HAVE_KRB5_AUTH_CON_SET_REQ_CKSUMTYPE)
	/* Ensure we will get an addressless ticket. */
	ret = krb5_auth_con_setaddrs(context, auth_context, NULL, NULL);
	if (ret) {
		syslog(LOG_DEBUG, "%s: unable to set NULL addrs: %d",
		       __func__, ret);
		goto out_free_auth;
	}

	/*
	 * Create a GSSAPI checksum (0x8003), see RFC 4121.
	 *
	 * The current layout is
	 *
	 * 0x10, 0x00, 0x00, 0x00 - length = 16
	 * 0x00, 0x00, 0x00, 0x00 - channel binding info - 16 zero bytes
	 * 0x00, 0x00, 0x00, 0x00
	 * 0x00, 0x00, 0x00, 0x00
	 * 0x00, 0x00, 0x00, 0x00
	 * 0x00, 0x00, 0x00, 0x00 - flags
	 *
	 * GSS_C_NO_CHANNEL_BINDINGS means 16 zero bytes,
	 * this is needed to work against some closed source
	 * SMB servers.
	 *
	 * See https://bugzilla.samba.org/show_bug.cgi?id=7890
	 */
	in_data.data = gss_cksum;
	in_data.length = 24;

	/* MIT krb5 < 1.7 is missing the prototype, but still has the symbol */
#if !HAVE_DECL_KRB5_AUTH_CON_SET_REQ_CKSUMTYPE
	krb5_error_code krb5_auth_con_set_req_cksumtype(
		krb5_auth_context auth_context,
		krb5_cksumtype    cksumtype);
#endif
	ret = krb5_auth_con_set_req_cksumtype(context, auth_context, 0x8003);
	if (ret) {
		syslog(LOG_DEBUG, "%s: unable to set 0x8003 checksum",
		       __func__);
		goto out_free_auth;
	}
#endif

	apreq_pkt.length = 0;
	apreq_pkt.data = NULL;
	ret = krb5_mk_req_extended(context, &auth_context, AP_OPTS_USE_SUBKEY,
				   &in_data, out_creds, &apreq_pkt);
	if (ret) {
		syslog(LOG_DEBUG, "%s: unable to make AP-REQ for %s",
		       __func__, host);
		goto out_free_auth;
	}

	ret = krb5_auth_con_getsendsubkey(context, auth_context, &tokb);
	if (ret) {
		syslog(LOG_DEBUG, "%s: unable to get session key for %s",
		       __func__, host);
		goto out_free_auth;
	}

	*mechtoken = data_blob(apreq_pkt.data, apreq_pkt.length);
	*sess_key = data_blob(KRB5_KEY_DATA(tokb), KRB5_KEY_LENGTH(tokb));

	krb5_free_keyblock(context, tokb);
out_free_auth:
	krb5_auth_con_free(context, auth_context);
out_free_creds:
	krb5_free_creds(context, out_creds);
out_free_principal:
	krb5_free_principal(context, in_creds.client);
	return ret;
}

static void cifs_gss_display_status_1(char *m, OM_uint32 code, int type) {
	OM_uint32 min_stat;
	gss_buffer_desc msg;
	OM_uint32 msg_ctx;

	msg_ctx = 0;
	while (1) {
		(void) gss_display_status(&min_stat, code, type,
				GSS_C_NULL_OID, &msg_ctx, &msg);
		syslog(LOG_DEBUG, "GSS-API error %s: %s\n", m, (char *) msg.value);
		(void) gss_release_buffer(&min_stat, &msg);

		if (!msg_ctx)
			break;
	}
}

void cifs_gss_display_status(char *msg, OM_uint32 maj_stat, OM_uint32 min_stat) {
	cifs_gss_display_status_1(msg, maj_stat, GSS_C_GSS_CODE);
	cifs_gss_display_status_1(msg, min_stat, GSS_C_MECH_CODE);
}

static int
cifs_gss_get_req(const char *host, DATA_BLOB *mechtoken, DATA_BLOB *sess_key)
{
	OM_uint32 maj_stat, min_stat;
	gss_name_t target_name;
	gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
	gss_buffer_desc output_token;
	gss_krb5_lucid_context_v1_t *lucid_ctx = NULL;
	gss_krb5_lucid_key_t *key = NULL;

	size_t service_name_len = sizeof(CIFS_SERVICE_NAME) + 1 /* @ */ +
		strlen(host) + 1;
	char *service_name = malloc(service_name_len);
	if (!service_name) {
		syslog(LOG_DEBUG, "out of memory allocating service name");
		goto out;
	}

	snprintf(service_name, service_name_len, "%s@%s", CIFS_SERVICE_NAME,
		 host);
	gss_buffer_desc target_name_buf;
	target_name_buf.value = service_name;
	target_name_buf.length = service_name_len;

	maj_stat = gss_import_name(&min_stat, &target_name_buf,
			GSS_C_NT_HOSTBASED_SERVICE, &target_name);
	free(service_name);
	if (GSS_ERROR(maj_stat)) {
		cifs_gss_display_status("gss_import_name", maj_stat, min_stat);
		goto out;
	}

	maj_stat = gss_init_sec_context(&min_stat,
			GSS_C_NO_CREDENTIAL, /* claimant_cred_handle */
			&ctx,
			target_name,
			discard_const(gss_mech_krb5), /* force krb5 */
			0, /* flags */
			0, /* time_req */
			GSS_C_NO_CHANNEL_BINDINGS, /* input_chan_bindings */
			GSS_C_NO_BUFFER,
			NULL, /* actual mech type */
			&output_token,
			NULL, /* ret_flags */
			NULL); /* time_rec */

	if (maj_stat != GSS_S_COMPLETE &&
		maj_stat != GSS_S_CONTINUE_NEEDED) {
		cifs_gss_display_status("init_sec_context", maj_stat, min_stat);
		goto out_release_target_name;
	}

	/* as luck would have it, GSS-API hands us the finished article */
	*mechtoken = data_blob(output_token.value, output_token.length);

	maj_stat = gss_krb5_export_lucid_sec_context(&min_stat, &ctx, 1,
							(void **)&lucid_ctx);

	if (GSS_ERROR(maj_stat)) {
		cifs_gss_display_status("gss_krb5_export_lucid_sec_context",
					maj_stat, min_stat);
		goto out_free_sec_ctx;
	}

	switch (lucid_ctx->protocol) {
	case 0:
		key = &lucid_ctx->rfc1964_kd.ctx_key;
		break;
	case 1:
		if (lucid_ctx->cfx_kd.have_acceptor_subkey) {
			key = &lucid_ctx->cfx_kd.acceptor_subkey;
		} else {
			key = &lucid_ctx->cfx_kd.ctx_key;
		}
		break;
	default:
		syslog(LOG_DEBUG, "wrong lucid context protocol %d",
		       lucid_ctx->protocol);
		goto out_free_lucid_ctx;
	}

	*sess_key = data_blob(key->data, key->length);

out_free_lucid_ctx:
	(void) gss_krb5_free_lucid_sec_context(&min_stat, lucid_ctx);
out_free_sec_ctx:
	(void) gss_delete_sec_context(&min_stat, &ctx, GSS_C_NO_BUFFER);
	(void) gss_release_buffer(&min_stat, &output_token);
out_release_target_name:
	(void) gss_release_name(&min_stat, &target_name);
out:
	return GSS_ERROR(maj_stat);
}

/*
 * Prepares AP-REQ data for mechToken and gets session key
 * Uses credentials from cache. It will not ask for password
 * you should receive credentials for yuor name manually using
 * kinit or whatever you wish.
 *
 * in:
 * 	oid -		string with OID/ Could be OID_KERBEROS5
 * 			or OID_KERBEROS5_OLD
 * 	principal -	Service name.
 * 			Could be "cifs/FQDN" for KRB5 OID
 * 			or for MS_KRB5 OID style server principal
 * 			like "pdc$@YOUR.REALM.NAME"
 *
 * out:
 * 	secblob -	pointer for spnego wrapped AP-REQ data to be stored
 * 	sess_key-	pointer for SessionKey data to be stored
 *
 * ret: 0 - success, others - failure
 */
static int
handle_krb5_mech(const char *oid, const char *host, DATA_BLOB * secblob,
		 DATA_BLOB * sess_key, krb5_ccache ccache)
{
	int retval;
	DATA_BLOB tkt_wrapped;

	syslog(LOG_DEBUG, "%s: getting service ticket for %s", __func__, host);

	/*
	 * Fall back to gssapi if there's no credential cache or no TGT
	 * so that gssproxy can maybe help out.
	 */
	if (!ccache) {
		syslog(LOG_DEBUG, "%s: using GSS-API", __func__);
		retval = cifs_gss_get_req(host, &tkt_wrapped, sess_key);
		if (retval) {
			syslog(LOG_DEBUG, "%s: failed to obtain service ticket via GSS (%d)",
			__func__, retval);
			return retval;
		}
	} else {
		DATA_BLOB tkt;
		syslog(LOG_DEBUG, "%s: using native krb5", __func__);

		/* get a kerberos ticket for the service and extract the session key */
		retval = cifs_krb5_get_req(host, ccache, &tkt, sess_key);
		if (retval) {
			syslog(LOG_DEBUG, "%s: failed to obtain service ticket (%d)",
			       __func__, retval);
			return retval;
		}

		syslog(LOG_DEBUG, "%s: obtained service ticket", __func__);

		/* wrap that up in a nice GSS-API wrapping */
		tkt_wrapped = spnego_gen_krb5_wrap(tkt, TOK_ID_KRB_AP_REQ);
		data_blob_free(&tkt);
	}

	/* and wrap that in a shiny SPNEGO wrapper */
	*secblob = gen_negTokenInit(oid, tkt_wrapped);

	data_blob_free(&tkt_wrapped);
	return retval;
}



struct decoded_args {
	int ver;
	char hostname[NI_MAXHOST + 1];
	char ip[NI_MAXHOST + 1];

/* Max user name length. */
#define MAX_USERNAME_SIZE 256
	char username[MAX_USERNAME_SIZE + 1];

	uid_t uid;
	uid_t creduid;
	pid_t pid;
	sectype_t sec;

/*
 * Flags to keep track of what was provided
 */
#define DKD_HAVE_HOSTNAME	0x1
#define DKD_HAVE_VERSION	0x2
#define DKD_HAVE_SEC		0x4
#define DKD_HAVE_IP		0x8
#define DKD_HAVE_UID		0x10
#define DKD_HAVE_PID		0x20
#define DKD_HAVE_CREDUID	0x40
#define DKD_HAVE_USERNAME	0x80
#define DKD_MUSTHAVE_SET (DKD_HAVE_HOSTNAME|DKD_HAVE_VERSION|DKD_HAVE_SEC)
	int have;
};

static unsigned int
__decode_key_description(const char *desc, struct decoded_args *arg)
{
	size_t len;
	char *pos;
	const char *tkn = desc;

	do {
		pos = index(tkn, ';');
		if (strncmp(tkn, "host=", 5) == 0) {

			if (pos == NULL)
				len = strlen(tkn);
			else
				len = pos - tkn;

			len -= 5;
			if (len > sizeof(arg->hostname)-1) {
				syslog(LOG_ERR, "host= value too long for buffer");
				return 1;
			}
			memset(arg->hostname, 0, sizeof(arg->hostname));
			strncpy(arg->hostname, tkn + 5, len);
			arg->have |= DKD_HAVE_HOSTNAME;
			syslog(LOG_DEBUG, "host=%s", arg->hostname);
		} else if (!strncmp(tkn, "ip4=", 4) || !strncmp(tkn, "ip6=", 4)) {
			if (pos == NULL)
				len = strlen(tkn);
			else
				len = pos - tkn;

			len -= 4;
			if (len > sizeof(arg->ip)-1) {
				syslog(LOG_ERR, "ip[46]= value too long for buffer");
				return 1;
			}
			memset(arg->ip, 0, sizeof(arg->ip));
			strncpy(arg->ip, tkn + 4, len);
			arg->have |= DKD_HAVE_IP;
			syslog(LOG_DEBUG, "ip=%s", arg->ip);
		} else if (strncmp(tkn, "user=", 5) == 0) {
			if (pos == NULL)
				len = strlen(tkn);
			else
				len = pos - tkn;

			len -= 5;
			if (len > sizeof(arg->username)-1) {
				syslog(LOG_ERR, "user= value too long for buffer");
				return 1;
			}
			memset(arg->username, 0, sizeof(arg->username));
			strncpy(arg->username, tkn + 5, len);
			arg->have |= DKD_HAVE_USERNAME;
			syslog(LOG_DEBUG, "user=%s", arg->username);
		} else if (strncmp(tkn, "pid=", 4) == 0) {
			errno = 0;
			arg->pid = strtol(tkn + 4, NULL, 0);
			if (errno != 0) {
				syslog(LOG_ERR, "Invalid pid format: %s",
				       strerror(errno));
				return 1;
			}
			syslog(LOG_DEBUG, "pid=%u", arg->pid);
			arg->have |= DKD_HAVE_PID;
		} else if (strncmp(tkn, "sec=", 4) == 0) {
			if (strncmp(tkn + 4, "krb5", 4) == 0) {
				arg->have |= DKD_HAVE_SEC;
				arg->sec = KRB5;
			} else if (strncmp(tkn + 4, "mskrb5", 6) == 0) {
				arg->have |= DKD_HAVE_SEC;
				arg->sec = MS_KRB5;
			}
			syslog(LOG_DEBUG, "sec=%d", arg->sec);
		} else if (strncmp(tkn, "uid=", 4) == 0) {
			errno = 0;
			arg->uid = strtol(tkn + 4, NULL, 16);
			if (errno != 0) {
				syslog(LOG_ERR, "Invalid uid format: %s",
				       strerror(errno));
				return 1;
			}
			arg->have |= DKD_HAVE_UID;
			syslog(LOG_DEBUG, "uid=%u", arg->uid);
		} else if (strncmp(tkn, "creduid=", 8) == 0) {
			errno = 0;
			arg->creduid = strtol(tkn + 8, NULL, 16);
			if (errno != 0) {
				syslog(LOG_ERR, "Invalid creduid format: %s",
				       strerror(errno));
				return 1;
			}
			arg->have |= DKD_HAVE_CREDUID;
			syslog(LOG_DEBUG, "creduid=%u", arg->creduid);
		} else if (strncmp(tkn, "ver=", 4) == 0) {	/* if version */
			errno = 0;
			arg->ver = strtol(tkn + 4, NULL, 16);
			if (errno != 0) {
				syslog(LOG_ERR, "Invalid version format: %s",
				       strerror(errno));
				return 1;
			}
			arg->have |= DKD_HAVE_VERSION;
			syslog(LOG_DEBUG, "ver=%d", arg->ver);
		}
		if (pos == NULL)
			break;
		tkn = pos + 1;
	} while (tkn);
	return 0;
}

static unsigned int
decode_key_description(const char *desc, struct decoded_args **arg)
{
	pid_t pid;
	pid_t rc;
	int status;

	/*
	 * Do all the decoding/string processing in a child process
	 * with low privileges.
	 */

	*arg = mmap(NULL, sizeof(struct decoded_args), PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (*arg == MAP_FAILED) {
		syslog(LOG_ERR, "%s: mmap failed: %s", __func__, strerror(errno));
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		syslog(LOG_ERR, "%s: fork failed: %s", __func__, strerror(errno));
		munmap(*arg, sizeof(struct decoded_args));
		*arg = NULL;
		return -1;
	}
	if (pid == 0) {
		/* do the parsing in child */
		drop_all_capabilities();
		exit(__decode_key_description(desc, *arg));
	}

	rc = waitpid(pid, &status, 0);
	if (rc < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		munmap(*arg, sizeof(struct decoded_args));
		*arg = NULL;
		return 1;
	}

	return 0;
}

static int setup_key(const key_serial_t key, const void *data, size_t datalen)
{
	int rc;

	rc = keyctl_instantiate(key, data, datalen, 0);
	if (rc) {
		switch (errno) {
		case ENOMEM:
		case EDQUOT:
			rc = keyctl_clear(key);
			if (rc) {
				syslog(LOG_ERR, "%s: keyctl_clear: %s",
				       __func__, strerror(errno));
				return rc;
			}
			rc = keyctl_instantiate(key, data, datalen, 0);
			break;
		default:
			;
		}
	}
	if (rc) {
		syslog(LOG_ERR, "%s: keyctl_instantiate: %s",
		       __func__, strerror(errno));
	}
	return rc;
}

static int cifs_resolver(const key_serial_t key, const char *key_descr,
			 const char *key_buf, unsigned expire_time)
{
	int c;
	struct addrinfo *addr;
	char ip[INET6_ADDRSTRLEN];
	void *p;
	const char *keyend = key_buf;
	/* skip next 4 ';' delimiters to get to description */
	for (c = 1; c <= 4; c++) {
		keyend = index(keyend + 1, ';');
		if (!keyend) {
			syslog(LOG_ERR, "invalid key description: %s",
			       key_buf);
			return 1;
		}
	}
	keyend++;

	/* resolve name to ip */
	c = getaddrinfo(keyend, NULL, NULL, &addr);
	if (c) {
		syslog(LOG_ERR, "unable to resolve hostname: %s [%s]",
		       keyend, gai_strerror(c));
		return 1;
	}

	/* conver ip to string form */
	if (addr->ai_family == AF_INET)
		p = &(((struct sockaddr_in *)addr->ai_addr)->sin_addr);
	else
		p = &(((struct sockaddr_in6 *)addr->ai_addr)->sin6_addr);

	if (!inet_ntop(addr->ai_family, p, ip, sizeof(ip))) {
		syslog(LOG_ERR, "%s: inet_ntop: %s", __func__, strerror(errno));
		freeaddrinfo(addr);
		return 1;
	}

	/* needed for keyctl_set_timeout() */
	request_key("keyring", key_descr, NULL, KEY_SPEC_THREAD_KEYRING);

	c = setup_key(key, ip, strlen(ip) + 1);
	if (c) {
		freeaddrinfo(addr);
		return 1;
	}
	c = keyctl_set_timeout(key, expire_time);
	if (c) {
		syslog(LOG_ERR, "%s: keyctl_set_timeout: %s", __func__,
		       strerror(errno));
		freeaddrinfo(addr);
		return 1;
	}
	freeaddrinfo(addr);
	return 0;
}

/*
 * Older kernels sent IPv6 addresses without colons. Well, at least
 * they're fixed-length strings. Convert these addresses to have colon
 * delimiters to make getaddrinfo happy.
 */
static void convert_inet6_addr(const char *from, char *to)
{
	int i = 1;

	while (*from) {
		*to++ = *from++;
		if (!(i++ % 4) && *from)
			*to++ = ':';
	}
	*to = 0;
}

static int ip_to_fqdn(const char *addrstr, char *host, size_t hostlen)
{
	int rc;
	struct addrinfo hints = {.ai_flags = AI_NUMERICHOST };
	struct addrinfo *res;
	const char *ipaddr = addrstr;
	char converted[INET6_ADDRSTRLEN + 1];

	if ((strlen(ipaddr) > INET_ADDRSTRLEN) && !strchr(ipaddr, ':')) {
		convert_inet6_addr(ipaddr, converted);
		ipaddr = converted;
	}

	rc = getaddrinfo(ipaddr, NULL, &hints, &res);
	if (rc) {
		syslog(LOG_DEBUG, "%s: failed to resolve %s to "
		       "ipaddr: %s", __func__, ipaddr,
		       rc == EAI_SYSTEM ? strerror(errno) : gai_strerror(rc));
		return rc;
	}

	rc = getnameinfo(res->ai_addr, res->ai_addrlen, host, hostlen,
			 NULL, 0, NI_NAMEREQD);
	freeaddrinfo(res);
	if (rc) {
		syslog(LOG_DEBUG, "%s: failed to resolve %s to fqdn: %s",
		       __func__, ipaddr,
		       rc == EAI_SYSTEM ? strerror(errno) : gai_strerror(rc));
		return rc;
	}

	syslog(LOG_DEBUG, "%s: resolved %s to %s", __func__, ipaddr, host);
	return 0;
}

/* walk a string and lowercase it in-place */
static void
lowercase_string(char *c)
{
	while(*c) {
		*c = tolower(*c);
		++c;
	}
}

static void usage(void)
{
	fprintf(stderr, "Usage: %s [ -K /path/to/keytab] [-k /path/to/krb5.conf] [-E] [-t] [-v] [-l] [-e nsecs] key_serial\n", prog);
}

static const struct option long_options[] = {
	{"no-env-probe", 0, NULL, 'E'},
	{"krb5conf", 1, NULL, 'k'},
	{"legacy-uid", 0, NULL, 'l'},
	{"trust-dns", 0, NULL, 't'},
	{"keytab", 1, NULL, 'K'},
	{"version", 0, NULL, 'v'},
	{"expire", 1, NULL, 'e'},
	{NULL, 0, NULL, 0}
};

int main(const int argc, char *const argv[])
{
	struct cifs_spnego_msg *keydata = NULL;
	DATA_BLOB secblob = data_blob_null;
	DATA_BLOB sess_key = data_blob_null;
	key_serial_t key = 0;
	size_t datalen;
	unsigned int have;
	long rc = 1;
	int c;
	bool try_dns = false, legacy_uid = false , env_probe = true;
	char *buf;
	char hostbuf[NI_MAXHOST], *host;
	struct decoded_args *arg = NULL;
	const char *oid;
	uid_t uid;
	char *keytab_name = NULL;
	char *env_cachename = NULL;
	krb5_ccache ccache = NULL;
	struct passwd *pw;
	unsigned expire_time = DNS_RESOLVER_DEFAULT_TIMEOUT;
	const char *key_descr = NULL;

	hostbuf[0] = '\0';

	openlog(prog, 0, LOG_DAEMON);

	while ((c = getopt_long(argc, argv, "cEk:K:ltve:", long_options, NULL)) != -1) {
		switch (c) {
		case 'c':
			/* legacy option -- skip it */
			break;
		case 'E':
			/* skip probing initiating process env */
			env_probe = false;
			break;
		case 't':
			try_dns = true;
			break;
		case 'k':
			if (setenv("KRB5_CONFIG", optarg, 1) != 0) {
				syslog(LOG_ERR, "unable to set $KRB5_CONFIG: %d", errno);
				goto out;
			}
			break;
		case 'K':
			keytab_name = optarg;
			break;
		case 'l':
			legacy_uid = true;
			break;
		case 'v':
			rc = 0;
			printf("version: %s\n", VERSION);
			goto out;
		case 'e':
			expire_time = strtoul(optarg, NULL, 10);
			break;
		default:
			syslog(LOG_ERR, "unknown option: %c", c);
			goto out;
		}
	}

	/* is there a key? */
	if (argc <= optind) {
		usage();
		goto out;
	}

	/* get key and keyring values */
	errno = 0;
	key = strtol(argv[optind], NULL, 10);
	if (errno != 0) {
		key = 0;
		syslog(LOG_ERR, "Invalid key format: %s", strerror(errno));
		goto out;
	}

	rc = keyctl_describe_alloc(key, &buf);
	if (rc == -1) {
		syslog(LOG_ERR, "keyctl_describe_alloc failed: %s",
		       strerror(errno));
		rc = 1;
		goto out;
	}

	syslog(LOG_DEBUG, "key description: %s", buf);

	/*
	 * If we are requested a simple DNS query, do it and exit
	 */

	if (strncmp(buf, "cifs.resolver", sizeof("cifs.resolver") - 1) == 0)
		key_descr = ".cifs.resolver";
	else if (strncmp(buf, "dns_resolver", sizeof("dns_resolver") - 1) == 0)
		key_descr = ".dns_resolver";
	if (key_descr) {
		rc = cifs_resolver(key, key_descr, buf, expire_time);
		goto out;
	}

	/*
	 * Otherwise, it's a spnego key request
	 */

	rc = decode_key_description(buf, &arg);
	free(buf);
	if (rc) {
		syslog(LOG_ERR, "failed to decode key description");
		goto out;
	}

	if ((arg->have & DKD_MUSTHAVE_SET) != DKD_MUSTHAVE_SET) {
		syslog(LOG_ERR, "unable to get necessary params from key "
		       "description (0x%x)", have);
		rc = 1;
		goto out;
	}

	if (arg->ver > CIFS_SPNEGO_UPCALL_VERSION) {
		syslog(LOG_ERR, "incompatible kernel upcall version: 0x%x",
		       arg->ver);
		rc = 1;
		goto out;
	}

	if (strlen(arg->hostname) >= NI_MAXHOST) {
		syslog(LOG_ERR, "hostname provided by kernel is too long");
		rc = 1;
		goto out;

	}

	if (!legacy_uid && (arg->have & DKD_HAVE_CREDUID))
		uid = arg->creduid;
	else if (arg->have & DKD_HAVE_UID)
		uid = arg->uid;
	else {
		/* no uid= or creduid= parm -- something is wrong */
		syslog(LOG_ERR, "No uid= or creduid= parm specified");
		rc = 1;
		goto out;
	}

	/*
	 * Change to the process's namespace. This means that things will work
	 * acceptably in containers, because we'll be looking at the correct
	 * filesystem and have the correct network configuration.
	 */
	rc = switch_to_process_ns(arg->pid);
	if (rc == -1) {
		syslog(LOG_ERR, "unable to switch to process namespace: %s", strerror(errno));
		rc = 1;
		goto out;
	}

	if (trim_capabilities(env_probe))
		goto out;

	/*
	 * The kernel doesn't pass down the gid, so we resort here to scraping
	 * one out of the passwd nss db. Note that this might not reflect the
	 * actual gid of the process that initiated the upcall. While we could
	 * scrape that out of /proc, relying on that is a bit more risky.
	 */
	pw = getpwuid(uid);
	if (!pw) {
		syslog(LOG_ERR, "Unable to find pw entry for uid %d: %s\n",
			uid, strerror(errno));
		rc = 1;
		goto out;
	}

	/*
	 * The kernel should send down a zero-length grouplist already, but
	 * just to be on the safe side...
	 */
	rc = setgroups(0, NULL);
	if (rc == -1) {
		syslog(LOG_ERR, "setgroups: %s", strerror(errno));
		rc = 1;
		goto out;
	}

	rc = setgid(pw->pw_gid);
	if (rc == -1) {
		syslog(LOG_ERR, "setgid: %s", strerror(errno));
		rc = 1;
		goto out;
	}

	/*
	 * We can't reasonably do this for root. When mounting a DFS share,
	 * for instance we can end up with creds being overridden, but the env
	 * variable left intact.
	 */
	if (uid == 0)
		env_probe = false;

	/*
	 * Must do this before setuid, as we need elevated capabilities to
	 * look at the environ file.
	 */
	env_cachename =
		get_cachename_from_process_env(env_probe ? arg->pid : 0);

	rc = setuid(uid);
	if (rc == -1) {
		syslog(LOG_ERR, "setuid: %s", strerror(errno));
		rc = 1;
		goto out;
	}

	rc = drop_all_capabilities();
	if (rc)
		goto out;

	rc = krb5_init_context(&context);
	if (rc) {
		syslog(LOG_ERR, "unable to init krb5 context: %ld", rc);
		rc = 1;
		goto out;
	}

	ccache = get_existing_cc(env_cachename);
	/* Couldn't find credcache? Try to use keytab */
	if (ccache == NULL && arg->username[0] != '\0')
		ccache = init_cc_from_keytab(keytab_name, arg->username);

	host = arg->hostname;

	// do mech specific authorization
	switch (arg->sec) {
	case MS_KRB5:
	case KRB5:
		/*
		 * Andrew Bartlett's suggested scheme for picking a principal
		 * name, based on a supplied hostname.
		 *
		 * INPUT: fooo
		 * TRY in order:
		 * cifs/fooo@REALM
		 * cifs/fooo.<guessed domain ?>@REALM
		 *
		 * INPUT: bar.example.com
		 * TRY only:
		 * cifs/bar.example.com@REALM
		 */
		if (arg->sec == MS_KRB5)
			oid = OID_KERBEROS5_OLD;
		else
			oid = OID_KERBEROS5;

retry_new_hostname:
		lowercase_string(host);
		rc = handle_krb5_mech(oid, host, &secblob, &sess_key, ccache);
		if (!rc)
			break;

		/*
		 * If hostname has a '.', assume it's a FQDN, otherwise we
		 * want to guess the domainname.
		 */
		if (!strchr(host, '.')) {
			struct addrinfo hints;
			struct addrinfo *ai;
			char *domainname;
			char fqdn[NI_MAXHOST];

			/*
			 * use getaddrinfo() to resolve the hostname of the
			 * server and set ai_canonname.
			 */
			memset(&hints, 0, sizeof(hints));
			hints.ai_family = AF_UNSPEC;
			hints.ai_flags = AI_CANONNAME;
			rc = getaddrinfo(host, NULL, &hints, &ai);
			if (rc) {
				syslog(LOG_ERR, "Unable to resolve host address: %s [%s]",
				       host, gai_strerror(rc));
				break;
			}

			/* scan forward to first '.' in ai_canonnname */
			domainname = strchr(ai->ai_canonname, '.');
			if (!domainname) {
				rc = -EINVAL;
				freeaddrinfo(ai);
				break;
			}
			lowercase_string(domainname);
			rc = snprintf(fqdn, sizeof(fqdn), "%s%s",
					host, domainname);
			freeaddrinfo(ai);
			if (rc < 0 || (size_t)rc >= sizeof(fqdn)) {
				syslog(LOG_ERR, "Problem setting hostname in string: %ld", rc);
				rc = -EINVAL;
				break;
			}

			rc = handle_krb5_mech(oid, fqdn, &secblob, &sess_key, ccache);
			if (!rc)
				break;
		}

		if (!try_dns || !(arg->have & DKD_HAVE_IP))
			break;

		rc = ip_to_fqdn(arg->ip, hostbuf, sizeof(hostbuf));
		if (rc)
			break;

		try_dns = false;
		host = hostbuf;
		goto retry_new_hostname;
	default:
		syslog(LOG_ERR, "sectype: %d is not implemented", arg->sec);
		rc = 1;
		break;
	}

	if (rc) {
		syslog(LOG_DEBUG, "Unable to obtain service ticket");
		goto out;
	}

	/* pack SecurityBlob and SessionKey into downcall packet */
	datalen =
	    sizeof(struct cifs_spnego_msg) + secblob.length + sess_key.length;
	keydata = (struct cifs_spnego_msg *)calloc(sizeof(char), datalen);
	if (!keydata) {
		rc = 1;
		goto out;
	}
	keydata->version = arg->ver;
	keydata->flags = 0;
	keydata->sesskey_len = sess_key.length;
	keydata->secblob_len = secblob.length;
	memcpy(&(keydata->data), sess_key.data, sess_key.length);
	memcpy(&(keydata->data) + keydata->sesskey_len,
	       secblob.data, secblob.length);

	rc = setup_key(key, keydata, datalen);

out:
	/*
	 * on error, negatively instantiate the key ourselves so that we can
	 * make sure the kernel doesn't hang it off of a searchable keyring
	 * and interfere with the next attempt to instantiate the key.
	 */
	if (rc != 0 && key == 0) {
		syslog(LOG_DEBUG, "Negating key");
		keyctl_negate(key, 1, KEY_REQKEY_DEFL_DEFAULT);
	}
	data_blob_free(&secblob);
	data_blob_free(&sess_key);
	if (ccache)
		krb5_cc_close(context, ccache);
	if (context)
		krb5_free_context(context);
	free(keydata);
	free(env_cachename);
	if (arg)
		munmap(arg, sizeof(*arg));
	syslog(LOG_DEBUG, "Exit status %ld", rc);
	return rc;
}
