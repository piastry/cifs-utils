/*
 * Mount helper utility for Linux CIFS VFS (virtual filesystem) client
 * Copyright (C) 2003,2010 Steve French  (sfrench@us.ibm.com)
 * Copyright (C) 2008 Jeremy Allison (jra@samba.org)
 * Copyright (C) 2010 Jeff Layton (jlayton@samba.org)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <mntent.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <libgen.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/wait.h>
#ifdef HAVE_SYS_FSUID_H
#include <sys/fsuid.h>
#endif /* HAVE_SYS_FSUID_H */
#ifdef HAVE_LIBCAP_NG
#include <cap-ng.h>
#else /* HAVE_LIBCAP_NG */
#ifdef HAVE_PRCTL
#include <sys/prctl.h>
#endif /* HAVE_PRCTL */
#ifdef HAVE_LIBCAP
#include <sys/capability.h>
#endif /* HAVE_LIBCAP */
#endif /* HAVE_LIBCAP_NG */
#include "mount.h"
#include "util.h"
#include "resolve_host.h"

#ifndef MS_MOVE 
#define MS_MOVE 8192 
#endif 

#ifndef MS_BIND
#define MS_BIND 4096
#endif

/* private flags - clear these before passing to kernel */
#define MS_USERS	0x40000000
#define MS_USER		0x80000000

#define MAX_UNC_LEN 1024

/* I believe that the kernel limits options data to a page */
#define MAX_OPTIONS_LEN	4096

/* max length of mtab options */
#define MTAB_OPTIONS_LEN 220

/*
 * Max share name, username, password and domain sizes match the kernel's
 * allowances for these string sizes which in turn match Microsoft's
 * documentation.
 */

/* Max length of the share name portion of a UNC. Share names over 80
 * characters cannot be accessed via commandline in Windows 2000/XP. */
#define MAX_SHARE_LEN 256

/* Max user name length. */
#define MAX_USERNAME_SIZE 256

/* Max domain size. */
#define MAX_DOMAIN_SIZE 256

/* Max password size. */
#define MOUNT_PASSWD_SIZE 512

/*
 * mount.cifs has been the subject of many "security" bugs that have arisen
 * because of users and distributions installing it as a setuid root program
 * before it had been audited for security holes. The default behavior is
 * now to allow mount.cifs to be run as a setuid root program. Some admins
 * may want to disable this fully, so this switch remains in place.
 */
#define CIFS_DISABLE_SETUID_CAPABILITY 0

/*
 * When an unprivileged user runs a setuid mount.cifs, we set certain mount
 * flags by default. These defaults can be changed here.
 */
#define CIFS_SETUID_FLAGS (MS_NOSUID|MS_NODEV)

/*
 * Values for parsing a credentials file.
 */
#define CRED_UNPARSEABLE 0
#define CRED_USER        1
#define CRED_PASS        2
#define CRED_DOM         4
#define CRED_PASS2		 5

/*
 * Values for parsing command line options.
 */
#define OPT_ERROR       -1
#define OPT_IGNORE      0
#define OPT_USERS       1
#define OPT_USER        2
#define OPT_USER_XATTR  3
#define OPT_PASS        4
#define OPT_SEC         5
#define OPT_IP          6
#define OPT_UNC         7
#define OPT_CRED        8
#define OPT_UID         9
#define OPT_GID        10
#define OPT_FMASK      11
#define OPT_FILE_MODE  12
#define OPT_DMASK      13
#define OPT_DIR_MODE   14
#define OPT_DOM        15
#define OPT_NO_SUID    16
#define OPT_SUID       17
#define OPT_NO_DEV     18
#define OPT_DEV        19
#define OPT_NO_LOCK    20
#define OPT_NO_EXEC    21
#define OPT_EXEC       22
#define OPT_GUEST      23
#define OPT_RO         24
#define OPT_RW         25
#define OPT_REMOUNT    26
#define OPT_MAND       27
#define OPT_NOMAND     28
#define OPT_CRUID      29
#define OPT_BKUPUID    30
#define OPT_BKUPGID    31
#define OPT_NOFAIL     32
#define OPT_SNAPSHOT   33
#define OPT_PASS2	   34

#define MNT_TMP_FILE "/.mtab.cifs.XXXXXX"

#define GMT_NAME_LEN 24 /* length of a @GMT- name */
#define GMT_FORMAT "@GMT-%Y.%m.%d-%H.%M.%S"

#define NTFS_TIME_OFFSET ((unsigned long long)(369*365 + 89) * 24 * 3600 * 10000000)

/*
* struct for holding parsed mount info for use by privileged process.
* Please do not keep pointers in this struct.
* That way, reinit of this struct is a simple memset.
*/
struct parsed_mount_info {
	unsigned long flags;
	char host[NI_MAXHOST + 1];
	char share[MAX_SHARE_LEN + 1];
	char prefix[PATH_MAX + 1];
	char options[MAX_OPTIONS_LEN];
	char domain[MAX_DOMAIN_SIZE + 1];
	char username[MAX_USERNAME_SIZE + 1];
	char password[MOUNT_PASSWD_SIZE + 1];
	char password2[MOUNT_PASSWD_SIZE + 1];
	char addrlist[MAX_ADDR_LIST_LEN];
	unsigned int got_user:1;
	unsigned int got_password:1;
	unsigned int got_password2:1;
	unsigned int fakemnt:1;
	unsigned int nomtab:1;
	unsigned int verboseflag:1;
	unsigned int nofail:1;
	unsigned int got_domain:1;
	unsigned int is_krb5:1;
	uid_t sudo_uid;
};

static const char *thisprogram;
static const char *cifs_fstype;

static int parse_unc(const char *unc_name, struct parsed_mount_info *parsed_info, const char *progname);

static int check_setuid(void)
{
	if (geteuid()) {
		fprintf(stderr, "This program is not installed setuid root - "
			" \"user\" CIFS mounts not supported.\n");
		return EX_USAGE;
	}

#if CIFS_DISABLE_SETUID_CAPABILITY
	if (getuid() && !geteuid()) {
		printf("This program has been built with the "
		       "ability to run as a setuid root program disabled.\n");
		return EX_USAGE;
	}
#endif /* CIFS_DISABLE_SETUID_CAPABILITY */

	return 0;
}

static int
check_fstab(const char *progname, const char *mountpoint, const char *devname,
	    char **options)
{
	FILE *fstab;
	struct mntent *mnt;
	size_t len;

	/* make sure this mount is listed in /etc/fstab */
	fstab = setmntent(_PATH_MNTTAB, "r");
	if (!fstab) {
		fprintf(stderr, "Couldn't open %s for reading!\n", _PATH_MNTTAB);
		return EX_FILEIO;
	}

	while ((mnt = getmntent(fstab))) {
		len = strlen(mnt->mnt_dir);
		while (len > 1) {
		        if (mnt->mnt_dir[len - 1] == '/')
			        mnt->mnt_dir[len - 1] = '\0';
		        else
				break;
			len--;
		}
		if (!strcmp(mountpoint, mnt->mnt_dir))
			break;
	}
	endmntent(fstab);

	if (mnt == NULL || strcmp(mnt->mnt_fsname, devname)) {
		fprintf(stderr, "%s: permission denied: no match for "
			"%s found in %s\n", progname, mountpoint, _PATH_MNTTAB);
		return EX_USAGE;
	}

	/*
	 * 'mount' munges the options from fstab before passing them
	 * to us. It is non-trivial to test that we have the correct
	 * set of options. We don't want to trust what the user
	 * gave us, so just take whatever is in /etc/fstab.
	 */
	*options = strdup(mnt->mnt_opts);
	return 0;
}

/* BB finish BB

	cifs_umount
	open nofollow - avoid symlink exposure? 
	get owner of dir see if matches self or if root
	call system(umount argv) etc.

BB end finish BB */

static int mount_usage(FILE * stream)
{
	fprintf(stream, "\nUsage:  %s <remotetarget> <dir> -o <options>\n",
		thisprogram);
	fprintf(stream, "\nMount the remote target, specified as a UNC name,");
	fprintf(stream, " to a local directory.\n\nOptions:\n");
	fprintf(stream, "\tuser=<arg>\n\tpass=<arg>\n\tdom=<arg>\n");
	fprintf(stream, "\nLess commonly used options:");
	fprintf(stream,
		"\n\tcredentials=<filename>,guest,perm,noperm,setuids,nosetuids,rw,ro,");
	fprintf(stream,
		"\n\tsep=<char>,iocharset=<codepage>,suid,nosuid,exec,noexec,serverino,");
	fprintf(stream,
		"\n\tnoserverino,mapchars,nomapchars,nolock,servernetbiosname=<SRV_RFC1001NAME>");
	fprintf(stream,
		"\n\tcache=<strict|none|loose>,nounix,cifsacl,sec=<authentication mechanism>,");
	fprintf(stream,
		"\n\tsign,seal,fsc,snapshot=<token|time>,nosharesock,persistenthandles,");
	fprintf(stream,
		"\n\tresilienthandles,rdma,vers=<smb_dialect>,cruid,password2=<alt password>");
	fprintf(stream,
		"\n\nOptions not needed for servers supporting CIFS Unix extensions");
	fprintf(stream,
		"\n\t(e.g. unneeded for mounts to most Samba versions):");
	fprintf(stream,
		"\n\tuid=<uid>,gid=<gid>,dir_mode=<mode>,file_mode=<mode>,sfu,");
	fprintf(stream,
		"\n\tmfsymlinks,idsfromsid");
	fprintf(stream, "\n\nRarely used options:");
	fprintf(stream,
		"\n\tport=<tcpport>,rsize=<size>,wsize=<size>,unc=<unc_name>,ip=<ip_address>,");
	fprintf(stream,
		"\n\tdev,nodev,nouser_xattr,netbiosname=<OUR_RFC1001NAME>,hard,soft,intr,");
	fprintf(stream,
		"\n\tnointr,ignorecase,noposixpaths,noacl,prefixpath=<path>,nobrl,");
	fprintf(stream,
		"\n\techo_interval=<seconds>,actimeo=<seconds>,max_credits=<credits>,");
	fprintf(stream,
		"\n\tbsize=<size>");
	fprintf(stream,
		"\n\nOptions are described in more detail in the manual page");
	fprintf(stream, "\n\tman 8 %s\n", thisprogram);
	fprintf(stream, "\nTo display the version number of the mount helper:");
	fprintf(stream, "\n\t%s -V\n", thisprogram);

	if (stream == stderr)
		return EX_USAGE;
	return 0;
}

/*
 * CIFS has to "escape" commas in the password field so that they don't
 * end up getting confused for option delimiters. Copy password into pw
 * field, turning any commas into double commas.
 */
static int
set_password(struct parsed_mount_info *parsed_info, const char *src,
			   const int which_pass)
{
	int is_pass2 = which_pass == OPT_PASS2 || which_pass == CRED_PASS2;

	char *dst = is_pass2 ?
				parsed_info->password2 : parsed_info->password;
	unsigned int pass_length = is_pass2 ?
					  sizeof(parsed_info->password2) : sizeof(parsed_info->password);
	unsigned int i = 0, j = 0;

	while (src[i]) {
		if (src[i] == ',')
			dst[j++] = ',';
		dst[j++] = src[i++];
		if (j > pass_length) {
			fprintf(stderr, "Converted password too long!\n");
			return EX_USAGE;
		}
	}
	dst[j] = '\0';
	if (is_pass2)
		parsed_info->got_password2 = 1;
	else
	parsed_info->got_password = 1;
	return 0;
}

#ifdef HAVE_LIBCAP_NG
static int
drop_capabilities(int parent)
{
	capng_select_t set = CAPNG_SELECT_CAPS;

	capng_setpid(getpid());
	capng_clear(CAPNG_SELECT_BOTH);
	if (parent) {
		if (capng_updatev(CAPNG_ADD, CAPNG_PERMITTED, CAP_DAC_READ_SEARCH, CAP_DAC_OVERRIDE, -1)) {
			fprintf(stderr, "Unable to update capability set.\n");
			return EX_SYSERR;
		}
		if (capng_update(CAPNG_ADD, CAPNG_PERMITTED|CAPNG_EFFECTIVE, CAP_SYS_ADMIN)) {
			fprintf(stderr, "Unable to update capability set.\n");
			return EX_SYSERR;
		}
	} else {
		if (capng_update(CAPNG_ADD, CAPNG_PERMITTED, CAP_DAC_READ_SEARCH)) {
			fprintf(stderr, "Unable to update capability set.\n");
			return EX_SYSERR;
		}
	}
	if (capng_have_capability(CAPNG_EFFECTIVE, CAP_SETPCAP)) {
		set = CAPNG_SELECT_BOTH;
	}
	if (capng_apply(set)) {
		fprintf(stderr, "Unable to apply new capability set.\n");
		return EX_SYSERR;
	}
	return 0;
}

static int
toggle_dac_capability(int writable, int enable)
{
	unsigned int capability = writable ? CAP_DAC_OVERRIDE : CAP_DAC_READ_SEARCH;

	if (capng_update(enable ? CAPNG_ADD : CAPNG_DROP, CAPNG_EFFECTIVE, capability)) {
		fprintf(stderr, "Unable to update capability set.\n");
		return EX_SYSERR;
	}
	if (capng_apply(CAPNG_SELECT_CAPS)) {
		fprintf(stderr, "Unable to apply new capability set.\n");
		return EX_SYSERR;
	}
	return 0;
}
#else /* HAVE_LIBCAP_NG */
#ifdef HAVE_LIBCAP
#ifdef HAVE_PRCTL
static int
prune_bounding_set(void)
{
	int i, rc = 0;
	static int bounding_set_cleared;

	if (bounding_set_cleared)
		return 0;

	for (i = 0; i <= CAP_LAST_CAP && rc == 0; ++i)
		rc = prctl(PR_CAPBSET_DROP, i);

	if (rc != 0) {
		fprintf(stderr, "Unable to clear capability bounding set: %d\n", rc);
		return EX_SYSERR;
	}

	++bounding_set_cleared;
	return 0;
}
#else /* HAVE_PRCTL */
static int
prune_bounding_set(void)
{
	return 0;
}
#endif /* HAVE_PRCTL */
static int
drop_capabilities(int parent)
{
	int rc, ncaps;
	cap_t caps;
	cap_value_t cap_list[3];

	rc = prune_bounding_set();
	if (rc)
		return rc;

	caps = cap_get_proc();
	if (caps == NULL) {
		fprintf(stderr, "Unable to get current capability set: %s\n",
			strerror(errno));
		return EX_SYSERR;
	}

	if (cap_clear(caps) == -1) {
		fprintf(stderr, "Unable to clear capability set: %s\n",
			strerror(errno));
		rc = EX_SYSERR;
		goto free_caps;
	}

	if (parent || getuid() == 0) {
		ncaps = 1;
		cap_list[0] = CAP_DAC_READ_SEARCH;
		if (parent) {
			cap_list[1] = CAP_DAC_OVERRIDE;
			cap_list[2] = CAP_SYS_ADMIN;
			ncaps += 2;
		}
		if (cap_set_flag(caps, CAP_PERMITTED, ncaps, cap_list, CAP_SET) == -1) {
			fprintf(stderr, "Unable to set permitted capabilities: %s\n",
				strerror(errno));
			rc = EX_SYSERR;
			goto free_caps;
		}
		if (parent) {
			cap_list[0] = CAP_SYS_ADMIN;
			if (cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_SET) == -1) {
				fprintf(stderr, "Unable to set effective capabilities: %s\n",
					strerror(errno));
				rc = EX_SYSERR;
				goto free_caps;
			}
		}
	}

	if (cap_set_proc(caps) != 0) {
		fprintf(stderr, "Unable to set current process capabilities: %s\n",
			strerror(errno));
		rc = EX_SYSERR;
	}
free_caps:
	cap_free(caps);
	return rc;
}

static int
toggle_dac_capability(int writable, int enable)
{
	int rc = 0;
	cap_t caps;
	cap_value_t capability = writable ? CAP_DAC_OVERRIDE : CAP_DAC_READ_SEARCH;

	caps = cap_get_proc();
	if (caps == NULL) {
		fprintf(stderr, "Unable to get current capability set: %s\n",
			strerror(errno));
		return EX_SYSERR;
	}

	if (cap_set_flag(caps, CAP_EFFECTIVE, 1, &capability,
			 enable ? CAP_SET : CAP_CLEAR) == -1) {
		fprintf(stderr, "Unable to %s effective capabilities: %s\n",
			enable ? "set" : "clear", strerror(errno));
		rc = EX_SYSERR;
		goto free_caps;
	}

	if (cap_set_proc(caps) != 0) {
		fprintf(stderr, "Unable to set current process capabilities: %s\n",
			strerror(errno));
		rc = EX_SYSERR;
	}
free_caps:
	cap_free(caps);
	return rc;
}
#else /* HAVE_LIBCAP */
static int
drop_capabilities(int parent __attribute((unused)))
{
	return 0;
}

static int
toggle_dac_capability(int writable __attribute((unused)), int enable __attribute((unused)))
{
	return 0;
}
#endif /* HAVE_LIBCAP */
#endif /* HAVE_LIBCAP_NG */

static void null_terminate_endl(char *source)
{
	char *newline = strchr(source, '\n');
	if (newline)
		*newline = '\0';
}

/*
 * Parse a line from the credentials file.  Changes target to first
 * character after '=' on 'line' and returns the value type of the line
 * Returns CRED_UNPARSEABLE on failure or if either parameter is NULL.
 */
static int parse_cred_line(char *line, char **target)
{
	if (line == NULL || target == NULL)
		goto parsing_err;

	/* position target at first char of value */
	*target = strchr(line, '=');
	if (!*target)
		goto parsing_err;
	*target += 1;

	/* tell the caller which value target points to */
	if (strncasecmp("user", line, 4) == 0)
		return CRED_USER;
	if (strncasecmp("pass2", line, 5) == 0 ||
		strncasecmp("password2", line, 9) == 0)
		return CRED_PASS2;
	if (strncasecmp("pass", line, 4) == 0)
		return CRED_PASS;
	if (strncasecmp("dom", line, 3) == 0)
		return CRED_DOM;

parsing_err:
	return CRED_UNPARSEABLE;
}

static int open_cred_file(char *file_name,
			struct parsed_mount_info *parsed_info)
{
	char *line_buf = NULL;
	char *temp_val = NULL;
	FILE *fs = NULL;
	int i;
	const int line_buf_size = 4096;
	const int min_non_white = 10;

	i = toggle_dac_capability(0, 1);
	if (i)
		goto return_i;

	i = access(file_name, R_OK);
	if (i) {
		toggle_dac_capability(0, 0);
		i = errno;
		goto return_i;
	}

	fs = fopen(file_name, "r");
	if (fs == NULL) {
		toggle_dac_capability(0, 0);
		i = errno;
		goto return_i;
	}

	i = toggle_dac_capability(0, 0);
	if (i)
		goto return_i;

	line_buf = (char *)malloc(line_buf_size);
	if (line_buf == NULL) {
		i = EX_SYSERR;
		goto return_i;
	}

	/* parse line from credentials file */
	while (fgets(line_buf, line_buf_size, fs)) {
		/* eat leading white space */
		for (i = 0; i < line_buf_size - min_non_white + 1; i++) {
			if ((line_buf[i] != ' ') && (line_buf[i] != '\t'))
				break;
		}
		null_terminate_endl(line_buf);

		/* parse next token */
		switch (parse_cred_line(line_buf + i, &temp_val)) {
		case CRED_USER:
			strlcpy(parsed_info->username, temp_val,
				sizeof(parsed_info->username));
			parsed_info->got_user = 1;
			break;
		case CRED_PASS:
			i = set_password(parsed_info, temp_val, CRED_PASS);
			if (i)
				goto return_i;
			break;
		case CRED_PASS2:
			i = set_password(parsed_info, temp_val, CRED_PASS2);
			if (i)
				goto return_i;
			break;
		case CRED_DOM:
			strlcpy(parsed_info->domain, temp_val,
				sizeof(parsed_info->domain));
			break;
		case CRED_UNPARSEABLE:
			if (parsed_info->verboseflag)
				fprintf(stderr, "Credential formatted "
					"incorrectly\n");
			break;
		}
	}
	i = 0;
return_i:
	if (fs != NULL)
		fclose(fs);

	/* make sure passwords are scrubbed from memory */
	if (line_buf != NULL)
		memset(line_buf, 0, line_buf_size);
	free(line_buf);
	return i;
}

static int
get_password_from_file(int file_descript, char *filename,
		       struct parsed_mount_info *parsed_info, const char *program,
			   const int which_pass)
{
	int rc = 0;
	int is_pass2 = which_pass == OPT_PASS2;
	unsigned int pass_length = is_pass2 ?
					  sizeof(parsed_info->password2) : sizeof(parsed_info->password);
	char buf[pass_length + 1];

	if (filename != NULL) {
		rc = toggle_dac_capability(0, 1);
		if (rc)
			return rc;

		rc = access(filename, R_OK);
		if (rc) {
			fprintf(stderr,
				"%s failed: access check of %s failed: %s\n",
				program, filename, strerror(errno));
			toggle_dac_capability(0, 0);
			return EX_SYSERR;
		}

		file_descript = open(filename, O_RDONLY);
		if (file_descript < 0) {
			fprintf(stderr,
				"%s failed. %s attempting to open password file %s\n",
				program, strerror(errno), filename);
			toggle_dac_capability(0, 0);
			return EX_SYSERR;
		}

		rc = toggle_dac_capability(0, 0);
		if (rc) {
			rc = EX_SYSERR;
			goto get_pw_exit;
		}
	}

	memset(buf, 0, sizeof(buf));
	rc = read(file_descript, buf, sizeof(buf) - 1);
	if (rc < 0) {
		fprintf(stderr,
			"%s failed. Error %s reading password file\n",
			program, strerror(errno));
		rc = EX_SYSERR;
		goto get_pw_exit;
	}

	rc = set_password(parsed_info, buf, which_pass);

get_pw_exit:
	if (filename != NULL)
		close(file_descript);
	return rc;
}

/*
 * Returns OPT_ERROR on unparsable token.
 */
static int parse_opt_token(const char *token)
{
	if (token == NULL)
		return OPT_ERROR;

	/*
	 * token is NULL terminated and contains exactly the
	 * keyword so we can match exactly
	 */
	if (strcmp(token, "users") == 0)
		return OPT_USERS;
	if (strcmp(token, "user_xattr") == 0)
		return OPT_USER_XATTR;
	if (strcmp(token, "user") == 0 ||
		strcmp(token, "username") == 0)
		return OPT_USER;
	if (strcmp(token, "pass") == 0 ||
		strcmp(token, "password") == 0)
		return OPT_PASS;
	if (strcmp(token, "pass2") == 0 ||
		strcmp(token, "password2") == 0)
		return OPT_PASS2;
	if (strcmp(token, "sec") == 0)
		return OPT_SEC;
	if (strcmp(token, "ip") == 0 ||
		strcmp(token, "addr") == 0)
		return OPT_IP;
	if (strcmp(token, "unc") == 0 ||
		strcmp(token, "target") == 0 ||
		strcmp(token, "path") == 0)
		return OPT_UNC;
	if (strcmp(token, "dom") == 0 ||
		strcmp(token, "domain") == 0 ||
		strcmp(token, "workgroup") == 0)
		return OPT_DOM;
	if (strcmp(token, "cred") == 0 || /* undocumented */
		strcmp(token, "credentials") == 0)
		return OPT_CRED;
	if (strcmp(token, "uid") == 0)
		return OPT_UID;
	if (strcmp(token, "cruid") == 0)
		return OPT_CRUID;
	if (strcmp(token, "gid") == 0)
		return OPT_GID;
	if (strcmp(token, "fmask") == 0)
		return OPT_FMASK;
	if (strcmp(token, "file_mode") == 0)
		return OPT_FILE_MODE;
	if (strcmp(token, "dmask") == 0)
		return OPT_DMASK;
	if (strcmp(token, "dir_mode") == 0 ||
		strcmp(token, "dirm") == 0)
		return OPT_DIR_MODE;
	if (strcmp(token, "nosuid") == 0)
		return OPT_NO_SUID;
	if (strcmp(token, "suid") == 0)
		return OPT_SUID;
	if (strcmp(token, "nodev") == 0)
		return OPT_NO_DEV;
	if (strcmp(token, "nobrl") == 0 ||
		strcmp(token, "nolock") == 0)
		return OPT_NO_LOCK;
	if (strcmp(token, "mand") == 0)
		return OPT_MAND;
	if (strcmp(token, "nomand") == 0)
		return OPT_NOMAND;
	if (strcmp(token, "dev") == 0)
		return OPT_DEV;
	if (strcmp(token, "noexec") == 0)
		return OPT_NO_EXEC;
	if (strcmp(token, "exec") == 0)
		return OPT_EXEC;
	if (strcmp(token, "guest") == 0)
		return OPT_GUEST;
	if (strcmp(token, "ro") == 0)
		return OPT_RO;
	if (strcmp(token, "rw") == 0)
		return OPT_RW;
	if (strcmp(token, "remount") == 0)
		return OPT_REMOUNT;
	if (strcmp(token, "_netdev") == 0)
		return OPT_IGNORE;
	if (strcmp(token, "backupuid") == 0)
		return OPT_BKUPUID;
	if (strcmp(token, "backupgid") == 0)
		return OPT_BKUPGID;
	if (strcmp(token, "nofail") == 0)
		return OPT_NOFAIL;
	if (strcmp(token, "comment") == 0)
		return OPT_IGNORE;
	if (strncmp(token, "x-", 2) == 0)
		return OPT_IGNORE;
	if (strncmp(token, "snapshot", 8) == 0)
		return OPT_SNAPSHOT;

	return OPT_ERROR;
}

static int
parse_options(const char *data, struct parsed_mount_info *parsed_info)
{
	char *value = NULL;
	char *equals = NULL;
	char *next_keyword = NULL;
	char *out = parsed_info->options;
	unsigned long *filesys_flags = &parsed_info->flags;
	int out_len = 0;
	int word_len;
	int rc = 0;
	int got_bkupuid = 0;
	int got_bkupgid = 0;
	int got_uid = 0;
	int got_cruid = 0;
	int got_gid = 0;
	int got_snapshot = 0;
	uid_t uid, cruid = 0, bkupuid = 0;
	gid_t gid, bkupgid = 0;
	char *ep;
	struct passwd *pw;
	struct group *gr;
	/*
	 * max 64-bit uint in decimal is 18446744073709551615 which is 20 chars
	 * wide +1 for NULL, and +1 for good measure
	 */
	char txtbuf[22];
	unsigned long long snapshot = 0;
	struct tm tm;

	/* make sure we're starting from beginning */
	out[0] = '\0';

	/* BB fixme check for separator override BB */
	uid = getuid();
	if (uid != 0)
		got_uid = 1;

	gid = getgid();
	if (gid != 0)
		got_gid = 1;

	if (!data)
		return EX_USAGE;

	/*
	 * format is keyword,keyword2=value2,keyword3=value3... 
	 * data  = next keyword
	 * value = next value ie stuff after equal sign
	 */
	while (data && *data) {
		next_keyword = strchr(data, ',');	/* BB handle sep= */

		/* temporarily null terminate end of keyword=value pair */
		if (next_keyword)
			*next_keyword++ = 0;

		/* temporarily null terminate keyword if there's a value */
		value = NULL;
		if ((equals = strchr(data, '=')) != NULL) {
			*equals = '\0';
			value = equals + 1;
		}

		switch(parse_opt_token(data)) {
		case OPT_USERS:
			if (!value || !*value) {
				*filesys_flags |= MS_USERS;
				goto nocopy;
			}
			break;

		case OPT_USER:
			if (!value || !*value) {
				if (data[4] == '\0') {
					*filesys_flags |= MS_USER;
					goto nocopy;
				} else {
					fprintf(stderr,
						"username specified with no parameter\n");
					return EX_USAGE;
				}
			} else {
				strlcpy(parsed_info->username, value,
					sizeof(parsed_info->username));
				parsed_info->got_user = 1;
				goto nocopy;
			}

		case OPT_PASS:
			if (parsed_info->got_password) {
				fprintf(stderr,
					"password specified twice, ignoring second\n");
				goto nocopy;
			}
			if (!value || !*value) {
				parsed_info->got_password = 1;
				goto nocopy;
			}
			rc = set_password(parsed_info, value, OPT_PASS);
			if (rc)
				return rc;
			goto nocopy;

		case OPT_PASS2:
		if (parsed_info->got_password2) {
				fprintf(stderr,
					"password2 specified twice, ignoring second\n");
				goto nocopy;
			}
			if (!value || !*value) {
				parsed_info->got_password2 = 1;
				goto nocopy;
			}
			rc = set_password(parsed_info, value, OPT_PASS2);
			if (rc)
				return rc;
			goto nocopy;

		case OPT_SEC:
			if (value) {
				if (!strncmp(value, "none", 4)) {
					parsed_info->got_password = 1;
					parsed_info->got_password2 = 1;
				}
				if (!strncmp(value, "krb5", 4)) {
					parsed_info->is_krb5 = 1;
					parsed_info->got_password = 1;
					parsed_info->got_password2 = 1;
				}
			}
			break;

		case OPT_IP:
			if (!value || !*value) {
				fprintf(stderr,
					"target ip address argument missing\n");
			} else if (strnlen(value, MAX_ADDRESS_LEN) <
				MAX_ADDRESS_LEN) {
				strlcpy(parsed_info->addrlist, value,
					MAX_ADDRESS_LEN);
				if (parsed_info->verboseflag)
					fprintf(stderr,
						"ip address %s override specified\n",
						value);
				goto nocopy;
			} else {
				fprintf(stderr, "ip address too long\n");
				return EX_USAGE;

			}
			break;

		/* unc || target || path */
		case OPT_UNC:
			if (!value || !*value) {
				fprintf(stderr,
					"invalid path to network resource\n");
				return EX_USAGE;
			}
			rc = parse_unc(value, parsed_info, thisprogram);
			if (rc)
				return rc;
			break;

		/* dom || workgroup */
		case OPT_DOM:
			if (!value) {
				/*
				 * An empty domain has been passed
				 */
				/* not necessary but better safe than.. */
				parsed_info->domain[0] = '\0';
				parsed_info->got_domain = 1;
				goto nocopy;
			}
			if (strnlen(value, sizeof(parsed_info->domain)) >=
			    sizeof(parsed_info->domain)) {
				fprintf(stderr, "domain name too long\n");
				return EX_USAGE;
			}
			strlcpy(parsed_info->domain, value,
				sizeof(parsed_info->domain));
			goto nocopy;

		case OPT_CRED:
			if (!value || !*value) {
				fprintf(stderr,
					"invalid credential file name specified\n");
				return EX_USAGE;
			}
			rc = open_cred_file(value, parsed_info);
			if (rc) {
				fprintf(stderr,
					"error %d (%s) opening credential file %s\n",
					rc, strerror(rc), value);
				return rc;
			}
			goto nocopy;

		case OPT_UID:
			if (!value || !*value)
				goto nocopy;

			got_uid = 1;
			pw = getpwnam(value);
			if (pw) {
				uid = pw->pw_uid;
				goto nocopy;
			}

			errno = 0;
			uid = strtoul(value, &ep, 10);
			if (errno == 0 && *ep == '\0')
				goto nocopy;

			fprintf(stderr, "bad option uid=\"%s\"\n", value);
			return EX_USAGE;
		case OPT_CRUID:
			if (!value || !*value)
				goto nocopy;

			got_cruid = 1;
			pw = getpwnam(value);
			if (pw) {
				cruid = pw->pw_uid;
				goto nocopy;
			}

			errno = 0;
			cruid = strtoul(value, &ep, 10);
			if (errno == 0 && *ep == '\0')
				goto nocopy;

			fprintf(stderr, "bad option: cruid=\"%s\"\n", value);
			return EX_USAGE;
		case OPT_GID:
			if (!value || !*value)
				goto nocopy;

			got_gid = 1;
			gr = getgrnam(value);
			if (gr) {
				gid = gr->gr_gid;
				goto nocopy;
			}

			errno = 0;
			gid = strtoul(value, &ep, 10);
			if (errno == 0 && *ep == '\0')
				goto nocopy;

			fprintf(stderr, "bad option: gid=\"%s\"\n", value);
			return EX_USAGE;
		/* fmask falls through to file_mode */
		case OPT_FMASK:
			fprintf(stderr,
				"WARNING: CIFS mount option 'fmask' is\
				 deprecated. Use 'file_mode' instead.\n");
			data = "file_mode";	/* BB fix this */
			/* Fallthrough */
		case OPT_FILE_MODE:
			if (!value || !*value) {
				fprintf(stderr,
					"Option '%s' requires a numerical argument\n",
					data);
				return EX_USAGE;
			}

			if (value[0] != '0')
				fprintf(stderr,
					"WARNING: '%s' not expressed in octal.\n",
					data);
			break;

		/* dmask falls through to dir_mode */
		case OPT_DMASK:
			fprintf(stderr,
				"WARNING: CIFS mount option 'dmask' is\
				 deprecated. Use 'dir_mode' instead.\n");
			data = "dir_mode";
			/* Fallthrough */
		case OPT_DIR_MODE:
			if (!value || !*value) {
				fprintf(stderr,
					"Option '%s' requires a numerical argument\n",
					data);
				return EX_USAGE;
			}

			if (value[0] != '0')
				fprintf(stderr,
					"WARNING: '%s' not expressed in octal.\n",
					data);
			break;
		case OPT_NO_SUID:
			*filesys_flags |= MS_NOSUID;
			goto nocopy;
		case OPT_SUID:
			*filesys_flags &= ~MS_NOSUID;
			goto nocopy;
		case OPT_NO_DEV:
			*filesys_flags |= MS_NODEV;
			goto nocopy;
		case OPT_NO_LOCK:
			*filesys_flags &= ~MS_MANDLOCK;
			break;
		case OPT_MAND:
			*filesys_flags |= MS_MANDLOCK;
			goto nocopy;
		case OPT_NOMAND:
			*filesys_flags &= ~MS_MANDLOCK;
			goto nocopy;
		case OPT_DEV:
			*filesys_flags &= ~MS_NODEV;
			goto nocopy;
		case OPT_NO_EXEC:
			*filesys_flags |= MS_NOEXEC;
			goto nocopy;
		case OPT_EXEC:
			*filesys_flags &= ~MS_NOEXEC;
			goto nocopy;
		case OPT_GUEST:
			parsed_info->got_user = 1;
			parsed_info->got_password = 1;
			parsed_info->got_password2 = 1;
			goto nocopy;
		case OPT_RO:
			*filesys_flags |= MS_RDONLY;
			goto nocopy;
		case OPT_RW:
			*filesys_flags &= ~MS_RDONLY;
			goto nocopy;
		case OPT_REMOUNT:
			*filesys_flags |= MS_REMOUNT;
			goto nocopy;
		case OPT_IGNORE:
			goto nocopy;
		case OPT_BKUPUID:
			if (!value || !*value)
				goto nocopy;

			got_bkupuid = 1;
			errno = 0;
			bkupuid = strtoul(value, &ep, 10);
			if (errno == 0 && *ep == '\0')
				goto nocopy;

			pw = getpwnam(value);
			if (pw == NULL) {
				fprintf(stderr,
					"bad user name \"%s\"\n", value);
				return EX_USAGE;
			}

			bkupuid = pw->pw_uid;
			goto nocopy;
		case OPT_BKUPGID:
			if (!value || !*value)
				goto nocopy;

			got_bkupgid = 1;
			errno = 0;
			bkupgid = strtoul(value, &ep, 10);
			if (errno == 0 && *ep == '\0')
				goto nocopy;

			gr = getgrnam(value);
			if (gr == NULL) {
				fprintf(stderr,
					"bad group name \"%s\"\n", value);
				return EX_USAGE;
			}

			bkupgid = gr->gr_gid;
			goto nocopy;
		case OPT_NOFAIL:
			parsed_info->nofail = 1;
			goto nocopy;
		case OPT_SNAPSHOT:
			if (!value || !*value)
				goto nocopy;
			if (strncmp(value, "@GMT-", 5))
				break;
			if ((strlen(value) != GMT_NAME_LEN) ||
			    (strptime(value, GMT_FORMAT, &tm) == NULL)) {
				fprintf(stderr, "bad snapshot token\n");
				return EX_USAGE;
			}
			snapshot = timegm(&tm) * 10000000 + NTFS_TIME_OFFSET;
			got_snapshot = 1;
			goto nocopy;
		}

		/* check size before copying option to buffer */
		word_len = strlen(data);
		if (value)
			word_len += 1 + strlen(value);

		/* need 2 extra bytes for comma and null byte */
		if (out_len + word_len + 2 > MAX_OPTIONS_LEN) {
			fprintf(stderr, "Options string too long\n");
			return EX_USAGE;
		}

		/* put back equals sign, if any */
		if (equals)
			*equals = '=';

		/* go ahead and copy */
		if (out_len)
			strlcat(out, ",", MAX_OPTIONS_LEN);

		strlcat(out, data, MAX_OPTIONS_LEN);
		out_len = strlen(out);
nocopy:
		data = next_keyword;
	}


	/* special-case the uid and gid */
	if (got_uid) {
		word_len = snprintf(txtbuf, sizeof(txtbuf), "%u", uid);

		/* comma + "uid=" + terminating NULL == 6 */
		if (out_len + word_len + 6 > MAX_OPTIONS_LEN) {
			fprintf(stderr, "Options string too long\n");
			return EX_USAGE;
		}

		if (out_len) {
			strlcat(out, ",", MAX_OPTIONS_LEN);
			out_len++;
		}
		rc = snprintf(out + out_len, word_len + 5, "uid=%s", txtbuf);
		if (rc < 0) {
			fprintf(stderr, "Error in creating mount string\n");
			return EX_SYSERR;
		}
		out_len = strlen(out);
	}
	if (parsed_info->is_krb5 && parsed_info->sudo_uid) {
		cruid = parsed_info->sudo_uid;
		got_cruid = 1;
	}
	if (got_cruid) {
		word_len = snprintf(txtbuf, sizeof(txtbuf), "%u", cruid);

		/* comma + "cruid=" + terminating NULL == 8 */
		if (out_len + word_len + 8 > MAX_OPTIONS_LEN) {
			fprintf(stderr, "Options string too long\n");
			return EX_USAGE;
		}

		if (out_len) {
			strlcat(out, ",", MAX_OPTIONS_LEN);
			out_len++;
		}
		rc = snprintf(out + out_len, word_len + 7, "cruid=%s", txtbuf);
		if (rc < 0) {
			fprintf(stderr, "Error in creating mount string\n");
			return EX_SYSERR;
		}
		out_len = strlen(out);
	}
	if (got_gid) {
		word_len = snprintf(txtbuf, sizeof(txtbuf), "%u", gid);

		/* comma + "gid=" + terminating NULL == 6 */
		if (out_len + word_len + 6 > MAX_OPTIONS_LEN) {
			fprintf(stderr, "Options string too long\n");
			return EX_USAGE;
		}

		if (out_len) {
			strlcat(out, ",", MAX_OPTIONS_LEN);
			out_len++;
		}
		rc = snprintf(out + out_len, word_len + 5, "gid=%s", txtbuf);
		if (rc < 0) {
			fprintf(stderr, "Error in creating mount string\n");
			return EX_SYSERR;
		}
		out_len = strlen(out);
	}
	if (got_bkupuid) {
		word_len = snprintf(txtbuf, sizeof(txtbuf), "%u", bkupuid);

		/* comma + "backupuid=" + terminating NULL == 12 */
		if (out_len + word_len + 12 > MAX_OPTIONS_LEN) {
			fprintf(stderr, "Options string too long\n");
			return EX_USAGE;
		}

		if (out_len) {
			strlcat(out, ",", MAX_OPTIONS_LEN);
			out_len++;
		}
		rc = snprintf(out + out_len, word_len + 11, "backupuid=%s", txtbuf);
		if (rc < 0) {
			fprintf(stderr, "Error in creating mount string\n");
			return EX_SYSERR;
		}
		out_len = strlen(out);
	}
	if (got_bkupgid) {
		word_len = snprintf(txtbuf, sizeof(txtbuf), "%u", bkupgid);

		/* comma + "backupgid=" + terminating NULL == 12 */
		if (out_len + word_len + 12 > MAX_OPTIONS_LEN) {
			fprintf(stderr, "Options string too long\n");
			return EX_USAGE;
		}

		if (out_len) {
			strlcat(out, ",", MAX_OPTIONS_LEN);
			out_len++;
		}
		rc = snprintf(out + out_len, word_len + 11, "backupgid=%s", txtbuf);
		if (rc < 0) {
			fprintf(stderr, "Error in creating mount string\n");
			return EX_SYSERR;
		}
		out_len = strlen(out);
	}
	if (got_snapshot) {
		word_len = snprintf(txtbuf, sizeof(txtbuf), "%llu", snapshot);

		/* comma + "snapshot=" + terminating NULL == 11 */
		if (out_len + word_len + 11 > MAX_OPTIONS_LEN) {
			fprintf(stderr, "Options string too long\n");
			return EX_USAGE;
		}

		if (out_len) {
			strlcat(out, ",", MAX_OPTIONS_LEN);
			out_len++;
		}
		rc = snprintf(out + out_len, word_len + 10, "snapshot=%s", txtbuf);
		if (rc < 0) {
			fprintf(stderr, "Error in creating mount string\n");
			return EX_SYSERR;
		}
		out_len = strlen(out);
	}

	return 0;
}

static int parse_unc(const char *unc_name, struct parsed_mount_info *parsed_info, const char *progname)
{
	int length = strnlen(unc_name, MAX_UNC_LEN);
	const char *host, *share, *prepath;
	size_t hostlen, sharelen, prepathlen;

	if (length > (MAX_UNC_LEN - 1)) {
		fprintf(stderr, "mount error: UNC name too long\n");
		return EX_USAGE;
	}

	if (length < 3) {
		fprintf(stderr, "mount error: UNC name too short\n");
		return EX_USAGE;
	}

	if ((strncasecmp("cifs://", unc_name, 7) == 0) ||
	    (strncasecmp("smb://", unc_name, 6) == 0)) {
		fprintf(stderr,
			"Mounting cifs URL not implemented yet. Attempt to mount %s\n",
			unc_name);
		return EX_USAGE;
	}

	if (strncmp(unc_name, "//", 2) && strncmp(unc_name, "\\\\", 2)) {
		fprintf(stderr, "%s: bad UNC (%s)\n", progname, unc_name);
		return EX_USAGE;
	}

	host = unc_name + 2;
	hostlen = strcspn(host, "/\\");
	if (!hostlen) {
		fprintf(stderr, "%s: bad UNC (%s)\n", progname, unc_name);
		return EX_USAGE;
	}
	share = host + hostlen + 1;

	if (hostlen + 1 > sizeof(parsed_info->host)) {
		fprintf(stderr, "%s: host portion of UNC too long\n", progname);
		return EX_USAGE;
	}

	sharelen = strcspn(share, "/\\");
	if (sharelen + 1 > sizeof(parsed_info->share)) {
		fprintf(stderr, "%s: share portion of UNC too long\n", progname);
		return EX_USAGE;
	}

	prepath = share + sharelen;
	if (*prepath != '\0')
		prepath++;

	prepathlen = strlen(prepath);

	if (prepathlen + 1 > sizeof(parsed_info->prefix)) {
		fprintf(stderr, "%s: UNC prefixpath too long\n", progname);
		return EX_USAGE;
	}

	/* copy pieces into their resepective buffers */
	memcpy(parsed_info->host, host, hostlen);
	memcpy(parsed_info->share, share, sharelen);
	memcpy(parsed_info->prefix, prepath, prepathlen);

	return 0;
}

static int get_pw_from_env(struct parsed_mount_info *parsed_info, const char *program)
{
	int rc = 0;

	if (getenv("PASSWD"))
		rc = set_password(parsed_info, getenv("PASSWD"), OPT_PASS);
	else if (getenv("PASSWD_FD"))
		rc = get_password_from_file(atoi(getenv("PASSWD_FD")), NULL,
					    parsed_info, program, OPT_PASS);
	else if (getenv("PASSWD_FILE"))
		rc = get_password_from_file(0, getenv("PASSWD_FILE"),
					    parsed_info, program, OPT_PASS);

	if (rc < 0)
		return rc;

	if (getenv("PASSWD2"))
		rc = set_password(parsed_info, getenv("PASSWD2"), OPT_PASS2);
	else if (getenv("PASSWD2_FD"))
		rc = get_password_from_file(atoi(getenv("PASSWD2_FD")), NULL,
					    parsed_info, program, OPT_PASS2);
	else if (getenv("PASSWD2_FILE"))
		rc = get_password_from_file(0, getenv("PASSWD2_FILE"),
					    parsed_info, program, OPT_PASS2);

	return rc;
}

static struct option longopts[] = {
	{"all", 0, NULL, 'a'},
	{"help", 0, NULL, 'h'},
	{"move", 0, NULL, 'm'},
	{"bind", 0, NULL, 'b'},
	{"read-only", 0, NULL, 'r'},
	{"ro", 0, NULL, 'r'},
	{"verbose", 0, NULL, 'v'},
	{"version", 0, NULL, 'V'},
	{"read-write", 0, NULL, 'w'},
	{"rw", 0, NULL, 'w'},
	{"options", 1, NULL, 'o'},
	{"type", 1, NULL, 't'},
	{"uid", 1, NULL, '1'},
	{"gid", 1, NULL, '2'},
	{"user", 1, NULL, 'u'},
	{"username", 1, NULL, 'u'},
	{"dom", 1, NULL, 'd'},
	{"domain", 1, NULL, 'd'},
	{"password", 1, NULL, 'p'},
	{"pass", 1, NULL, 'p'},
	{"password2", 1, NULL, 0},
	{"pass2", 1, NULL, 0},
	{"credentials", 1, NULL, 'c'},
	{"port", 1, NULL, 'P'},
	{"sloppy", 0, NULL, 's'},
	{NULL, 0, NULL, 0}
};

/* convert a string to uppercase. return false if the string
 * wasn't ASCII. Return success on a NULL ptr */
static int uppercase_string(char *string)
{
	if (!string)
		return 1;

	while (*string) {
		/* check for unicode */
		if ((unsigned char)string[0] & 0x80)
			return 0;
		*string = toupper((unsigned char)*string);
		string++;
	}

	return 1;
}

static void print_cifs_mount_version(const char *progname)
{
	printf("%s version: %s\n", progname, VERSION);
}

/*
 * This function borrowed from fuse-utils...
 *
 * glibc's addmntent (at least as of 2.10 or so) doesn't properly encode
 * newlines embedded within the text fields. To make sure no one corrupts
 * the mtab, fail the mount if there are embedded newlines.
 */
static int check_newline(const char *progname, const char *name)
{
	const char *s;
	for (s = "\n"; *s; s++) {
		if (strchr(name, *s)) {
			fprintf(stderr,
				"%s: illegal character 0x%02x in mount entry\n",
				progname, *s);
			return EX_USAGE;
		}
	}
	return 0;
}

static int check_mtab(const char *progname, const char *devname,
		      const char *dir)
{
	if (check_newline(progname, devname) || check_newline(progname, dir))
		return EX_USAGE;
	return 0;
}

static int
add_mtab(char *devname, char *mountpoint, unsigned long flags, const char *fstype)
{
	int rc = 0, tmprc, fd;
	uid_t uid;
	char *mount_user = NULL;
	struct mntent mountent;
	struct stat statbuf;
	FILE *pmntfile;
	sigset_t mask, oldmask;

	uid = getuid();
	if (uid != 0)
		mount_user = getusername(uid);

	/*
	 * Set the real uid to the effective uid. This prevents unprivileged
	 * users from sending signals to this process, though ^c on controlling
	 * terminal should still work.
	 */
	rc = setreuid(geteuid(), -1);
	if (rc != 0) {
		fprintf(stderr, "Unable to set real uid to effective uid: %s\n",
				strerror(errno));
		return EX_FILEIO;
	}

	rc = sigfillset(&mask);
	if (rc) {
		fprintf(stderr, "Unable to set filled signal mask\n");
		return EX_FILEIO;
	}

	rc = sigprocmask(SIG_SETMASK, &mask, &oldmask);
	if (rc) {
		fprintf(stderr, "Unable to make process ignore signals\n");
		return EX_FILEIO;
	}

	rc = toggle_dac_capability(1, 1);
	if (rc)
		return EX_FILEIO;

	atexit(unlock_mtab);
	rc = lock_mtab();
	if (rc) {
		fprintf(stderr, "cannot lock mtab");
		rc = EX_FILEIO;
		goto add_mtab_exit;
	}

	pmntfile = setmntent(MOUNTED, "a+");
	if (!pmntfile) {
		fprintf(stderr, "could not update mount table\n");
		unlock_mtab();
		rc = EX_FILEIO;
		goto add_mtab_exit;
	}

	fd = fileno(pmntfile);
	if (fd < 0) {
		fprintf(stderr, "mntent does not appear to be valid\n");
		unlock_mtab();
		rc = EX_FILEIO;
		goto add_mtab_exit;
	}

	rc = fstat(fd, &statbuf);
	if (rc != 0) {
		fprintf(stderr, "unable to fstat open mtab\n");
		endmntent(pmntfile);
		unlock_mtab();
		rc = EX_FILEIO;
		goto add_mtab_exit;
	}

	mountent.mnt_fsname = devname;
	mountent.mnt_dir = mountpoint;
	mountent.mnt_type = (char *)(void *)fstype;
	mountent.mnt_opts = (char *)calloc(MTAB_OPTIONS_LEN, 1);
	if (mountent.mnt_opts) {
		if (flags & MS_RDONLY)
			strlcat(mountent.mnt_opts, "ro", MTAB_OPTIONS_LEN);
		else
			strlcat(mountent.mnt_opts, "rw", MTAB_OPTIONS_LEN);

		if (flags & MS_MANDLOCK)
			strlcat(mountent.mnt_opts, ",mand", MTAB_OPTIONS_LEN);
		if (flags & MS_NOEXEC)
			strlcat(mountent.mnt_opts, ",noexec", MTAB_OPTIONS_LEN);
		if (flags & MS_NOSUID)
			strlcat(mountent.mnt_opts, ",nosuid", MTAB_OPTIONS_LEN);
		if (flags & MS_NODEV)
			strlcat(mountent.mnt_opts, ",nodev", MTAB_OPTIONS_LEN);
		if (flags & MS_SYNCHRONOUS)
			strlcat(mountent.mnt_opts, ",sync", MTAB_OPTIONS_LEN);
		if (mount_user) {
			strlcat(mountent.mnt_opts, ",user=", MTAB_OPTIONS_LEN);
			strlcat(mountent.mnt_opts, mount_user,
				MTAB_OPTIONS_LEN);
		}
	}
	mountent.mnt_freq = 0;
	mountent.mnt_passno = 0;
	rc = addmntent(pmntfile, &mountent);
	if (rc) {
		int ignore __attribute__((unused));

		fprintf(stderr, "unable to add mount entry to mtab\n");
		ignore = ftruncate(fd, statbuf.st_size);
		rc = EX_FILEIO;
	}
	tmprc = my_endmntent(pmntfile, statbuf.st_size);
	if (tmprc) {
		fprintf(stderr, "error %d detected on close of mtab\n", tmprc);
		rc = EX_FILEIO;
	}
	unlock_mtab();
	free(mountent.mnt_opts);
add_mtab_exit:
	toggle_dac_capability(1, 0);
	sigprocmask(SIG_SETMASK, &oldmask, NULL);

	return rc;
}

static int
del_mtab(char *mountpoint)
{
	int len, tmprc, rc = 0;
	FILE *mnttmp, *mntmtab;
	struct mntent *mountent;
	char *mtabfile, *mtabdir, *mtabtmpfile = NULL;

	mtabfile = strdup(MOUNTED);
	if (!mtabfile) {
		fprintf(stderr, "del_mtab: cannot strdup MOUNTED\n");
		rc = EX_FILEIO;
		goto del_mtab_exit;
	}

	mtabdir = dirname(mtabfile);
	len = strlen(mtabdir) + strlen(MNT_TMP_FILE);
	mtabtmpfile = malloc(len + 1);
	if (!mtabtmpfile) {
		fprintf(stderr, "del_mtab: cannot allocate memory to tmp file\n");
		rc = EX_FILEIO;
		goto del_mtab_exit;
	}

	if (sprintf(mtabtmpfile, "%s%s", mtabdir, MNT_TMP_FILE) != len) {
		fprintf(stderr, "del_mtab: error writing new string\n");
		rc = EX_FILEIO;
		goto del_mtab_exit;
	}

	atexit(unlock_mtab);
	rc = lock_mtab();
	if (rc) {
		fprintf(stderr, "del_mtab: cannot lock mtab\n");
		rc = EX_FILEIO;
		goto del_mtab_exit;
	}

	mtabtmpfile = mktemp(mtabtmpfile);
	if (!mtabtmpfile) {
		fprintf(stderr, "del_mtab: cannot setup tmp file destination\n");
		rc = EX_FILEIO;
		goto del_mtab_exit;
	}

	mntmtab = setmntent(MOUNTED, "r");
	if (!mntmtab) {
		fprintf(stderr, "del_mtab: could not update mount table\n");
		rc = EX_FILEIO;
		goto del_mtab_exit;
	}

	mnttmp = setmntent(mtabtmpfile, "w");
	if (!mnttmp) {
		fprintf(stderr, "del_mtab: could not update mount table\n");
		endmntent(mntmtab);
		rc = EX_FILEIO;
		goto del_mtab_exit;
	}

	while ((mountent = getmntent(mntmtab)) != NULL) {
		if (!strcmp(mountent->mnt_dir, mountpoint))
			continue;
		rc = addmntent(mnttmp, mountent);
		if (rc) {
			fprintf(stderr, "del_mtab: unable to add mount entry to mtab\n");
			rc = EX_FILEIO;
			goto del_mtab_error;
		}
	}

	endmntent(mntmtab);

	tmprc = my_endmntent(mnttmp, 0);
	if (tmprc) {
		fprintf(stderr, "del_mtab: error %d detected on close of tmp file\n", tmprc);
		rc = EX_FILEIO;
		goto del_mtab_error;
	}

	if (rename(mtabtmpfile, MOUNTED)) {
		fprintf(stderr, "del_mtab: error %d when renaming mtab in place\n", errno);
		rc = EX_FILEIO;
		goto del_mtab_error;
	}

del_mtab_exit:
	unlock_mtab();
	free(mtabtmpfile);
	free(mtabfile);
	return rc;

del_mtab_error:
	if (unlink(mtabtmpfile))
		fprintf(stderr, "del_mtab: failed to delete tmp file - %s\n",
				strerror(errno));
	goto del_mtab_exit;
}

/* have the child drop root privileges */
static int
drop_child_privs(void)
{
	int rc;
	uid_t uid = getuid();
	gid_t gid = getgid();

	if (gid) {
		rc = setgid(gid);
		if (rc) {
			fprintf(stderr, "Unable set group identity: %s\n",
					strerror(errno));
			return EX_SYSERR;
		}
	}
	if (uid) {
		rc = setuid(uid);
		if (rc) {
			fprintf(stderr, "Unable set user identity: %s\n",
					strerror(errno));
			return EX_SYSERR;
		}
	}

	return 0;
}

#ifdef ENABLE_SYSTEMD
static int get_passwd_by_systemd(const char *prompt, char *input, int capacity)
{
	int fd[2];
	pid_t pid;
	int offs = 0;
	int rc = 1;

	if (pipe(fd) == -1) {
		fprintf(stderr, "Failed to create pipe: %s\n", strerror(errno));
		return 1;
	}

	pid = fork();
	if (pid == -1) {
		fprintf(stderr, "Unable to fork: %s\n", strerror(errno));
		close(fd[0]);
		close(fd[1]);
		return 1;
	}
	if (pid == 0) {
		close(fd[0]);
		dup2(fd[1], STDOUT_FILENO);
		if (execlp("systemd-ask-password", "systemd-ask-password", prompt, NULL) == -1) {
			fprintf(stderr, "Failed to execute systemd-ask-password: %s\n",
				strerror(errno));
		}
		exit(1);
	}

	close(fd[1]);
	for (;;) {
		if (offs+1 >= capacity) {
			fprintf(stderr, "Password too long.\n");
			kill(pid, SIGTERM);
			rc = 1;
			break;
		}
		rc = read(fd[0], input + offs, capacity - offs);
		if (rc == -1) {
			fprintf(stderr, "Failed to read from pipe: %s\n", strerror(errno));
			rc = 1;
			break;
		}
		if (!rc)
			break;
		offs += rc;
		input[offs] = '\0';
	}
	if (wait(&rc) == -1) {
		fprintf(stderr, "Failed to wait child: %s\n", strerror(errno));
		rc = 1;
		goto out;
	}
	if (!WIFEXITED(rc) || WEXITSTATUS(rc)) {
		rc = 1;
		goto out;
	}

	rc = 0;

out:
	close(fd[0]);
	return rc;
}
#endif

/*
 * If systemd is running and systemd-ask-password --
 * is available, then use that else fallback on getpass(..)
 *
 * Returns: @input or NULL on error
 */
static char*
get_password(const char *prompt, char *input, int capacity)
{
#ifdef ENABLE_SYSTEMD
	int is_systemd_running;
	struct stat a, b;

	memset(input, 0, capacity);

	/* We simply test whether the systemd cgroup hierarchy is
	 * mounted */
	is_systemd_running = (lstat("/sys/fs/cgroup", &a) == 0)
		&& (lstat("/sys/fs/cgroup/systemd", &b) == 0)
		&& (a.st_dev != b.st_dev);

	if (is_systemd_running && !get_passwd_by_systemd(prompt, input, capacity)) {
		int len = strlen(input);
		if (input[len - 1] == '\n')
			input[len - 1] = '\0';
		return input;
	}
#endif
	memset(input, 0, capacity);

	/*
	 * Falling back to getpass(..)
	 * getpass is obsolete, but there's apparently nothing that replaces it
	 */
	char *tmp_pass = getpass(prompt);
	if (!tmp_pass)
		return NULL;

	strncpy(input, tmp_pass, capacity - 1);
	input[capacity - 1] = '\0';

	/* zero-out the static buffer */
	memset(tmp_pass, 0, strlen(tmp_pass));

	return input;
}

static int
assemble_mountinfo(struct parsed_mount_info *parsed_info,
		   const char *thisprogram, const char *mountpoint,
		   const char *orig_dev, char *orgoptions)
{
	int rc;
	char *newopts = NULL;

	rc = drop_capabilities(0);
	if (rc)
		goto assemble_exit;

	rc = drop_child_privs();
	if (rc)
		goto assemble_exit;

	if (getuid()) {
		rc = check_fstab(thisprogram, mountpoint, orig_dev,
				 &newopts);
		if (rc)
			goto assemble_exit;

		orgoptions = newopts;
		/* enable any default user mount flags */
		parsed_info->flags |= CIFS_SETUID_FLAGS;
	}

	rc = get_pw_from_env(parsed_info, thisprogram);
	if (rc)
		goto assemble_exit;

	if (orgoptions) {
		rc = parse_options(orgoptions, parsed_info);
		if (rc)
			goto assemble_exit;
	}

	if (getuid()) {
		if (!(parsed_info->flags & (MS_USERS | MS_USER))) {
			fprintf(stderr, "%s: permission denied\n", thisprogram);
			rc = EX_USAGE;
			goto assemble_exit;
		}
	}

	parsed_info->flags &= ~(MS_USERS | MS_USER);

	rc = parse_unc(orig_dev, parsed_info, thisprogram);
	if (rc)
		goto assemble_exit;

	if (parsed_info->addrlist[0] == '\0') {
		rc = resolve_host(parsed_info->host, parsed_info->addrlist);
		if (rc == 0 && parsed_info->verboseflag)
			fprintf(stderr, "Host \"%s\" resolved to the following IP addresses: %s\n", parsed_info->host, parsed_info->addrlist);
	}

	switch (rc) {
	case EX_USAGE:
		fprintf(stderr, "mount error: could not resolve address for "
			"%s: %s\n", parsed_info->host,
			rc == EAI_SYSTEM ? strerror(errno) : gai_strerror(rc));
		goto assemble_exit;

	case EX_SYSERR:
		fprintf(stderr, "mount error: problem parsing address "
			"list: %s\n", strerror(errno));
		goto assemble_exit;
	}

	if (!parsed_info->got_user) {
		/*
		 * Note that the password will not be retrieved from the
		 * USER env variable (ie user%password form) as there is
		 * already a PASSWD environment varaible
		 */
		if (getenv("USER"))
			strlcpy(parsed_info->username, getenv("USER"),
				sizeof(parsed_info->username));
		else
			strlcpy(parsed_info->username, getusername(getuid()),
				sizeof(parsed_info->username));
		parsed_info->got_user = 1;
	}

	// no need to prompt for password2
	if (!parsed_info->got_password && !(parsed_info->flags & MS_REMOUNT)) {
		char tmp_pass[MOUNT_PASSWD_SIZE + 1];
		char *prompt = NULL;

		if(asprintf(&prompt, "Password for %s@%s: ", parsed_info->username, orig_dev) < 0)
			prompt = NULL;

		if (get_password(prompt ? prompt : "Password: ", tmp_pass, MOUNT_PASSWD_SIZE + 1)) {
			rc = set_password(parsed_info, tmp_pass, OPT_PASS);
		} else {
			fprintf(stderr, "Error reading password, exiting\n");
			rc = EX_SYSERR;
		}

		free(prompt);
		if (rc)
			goto assemble_exit;
	}

	/* copy in user= string */
	if (parsed_info->got_user) {
		if (*parsed_info->options)
			strlcat(parsed_info->options, ",",
				sizeof(parsed_info->options));
		strlcat(parsed_info->options, "user=",
			sizeof(parsed_info->options));
		strlcat(parsed_info->options, parsed_info->username,
			sizeof(parsed_info->options));
	}

	if (*parsed_info->domain) {
		if (*parsed_info->options)
			strlcat(parsed_info->options, ",",
				sizeof(parsed_info->options));
		strlcat(parsed_info->options, "domain=",
			sizeof(parsed_info->options));
		strlcat(parsed_info->options, parsed_info->domain,
			sizeof(parsed_info->options));
	} else if (parsed_info->got_domain) {
		strlcat(parsed_info->options, ",domain=",
			sizeof(parsed_info->options));
	}

assemble_exit:
	free(newopts);
	return rc;
}

/*
 * chdir() into the mountpoint and determine "realpath". We assume here that
 * "mountpoint" is a statically allocated string and does not need to be freed.
 */
static int
acquire_mountpoint(char **mountpointp)
{
	int rc, dacrc;
	uid_t realuid, oldfsuid;
	gid_t oldfsgid;
	char *mountpoint = NULL;

	/*
	 * Acquire the necessary privileges to chdir to the mountpoint. If
	 * the real uid is root, then we reacquire CAP_DAC_READ_SEARCH. If
	 * it's not, then we change the fsuid to the real uid to ensure that
	 * the mounting user actually has access to the mountpoint.
	 *
	 * The mount(8) manpage does not state that users must be able to
	 * chdir into the mountpoint in order to mount onto it, but if we
	 * allow that, then an unprivileged user could use this program to
	 * "probe" into directories to which he does not have access.
	 */
	realuid = getuid();
	if (realuid == 0) {
		rc = toggle_dac_capability(0, 1);
		if (rc)
			goto out;
	} else {
		oldfsuid = setfsuid(realuid);
		oldfsgid = setfsgid(getgid());
	}

	rc = chdir(*mountpointp);
	if (rc) {
		fprintf(stderr, "Couldn't chdir to %s: %s\n", *mountpointp,
			strerror(errno));
		rc = EX_USAGE;
		goto restore_privs;
	}

	mountpoint = realpath(".", NULL);
	if (!mountpoint) {
		fprintf(stderr, "Unable to resolve %s to canonical path: %s\n",
			*mountpointp, strerror(errno));
		rc = EX_SYSERR;
	}

restore_privs:
	if (realuid == 0) {
		dacrc = toggle_dac_capability(0, 0);
		if (dacrc)
			rc = rc ? rc : dacrc;
	} else {
		uid_t __attribute__((unused)) uignore = setfsuid(oldfsuid);
		gid_t __attribute__((unused)) gignore = setfsgid(oldfsgid);
	}

out:
	if (rc) {
		free(mountpoint);
		mountpoint = NULL;
	}

	*mountpointp = mountpoint;
	return rc;
}

int main(int argc, char **argv)
{
	int c;
	char *orgoptions = NULL;
	char *mountpoint = NULL;
	char *options = NULL;
	char *orig_dev = NULL;
	char *currentaddress, *nextaddress;
	char *value = NULL;
	char *ep = NULL;
	int rc = 0;
	int already_uppercased = 0;
	int sloppy = 0;
	int fallback_sudo_uid = 0;
	size_t options_size = MAX_OPTIONS_LEN;
	struct parsed_mount_info *parsed_info = NULL;
	struct parsed_mount_info *reinit_parsed_info = NULL;
	pid_t pid;
	uid_t sudo_uid = 0;

	rc = check_setuid();
	if (rc)
		return rc;

	rc = drop_capabilities(1);
	if (rc)
		return EX_SYSERR;

	/* setlocale(LC_ALL, "");
	   bindtextdomain(PACKAGE, LOCALEDIR);
	   textdomain(PACKAGE); */

	if (!argc || !argv) {
		rc = mount_usage(stderr);
		goto mount_exit;
	}

	thisprogram = basename(argv[0]);
	if (thisprogram == NULL)
		thisprogram = "mount.cifs";

	if(strcmp(thisprogram, "mount.cifs") == 0)
		cifs_fstype = "cifs";

	if(strcmp(thisprogram, "mount.smb3") == 0)
		cifs_fstype = "smb3";

	/* allocate parsed_info as shared anonymous memory range */
	parsed_info = mmap((void *)0, sizeof(*parsed_info), PROT_READ | PROT_WRITE,
			   MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (parsed_info == (struct parsed_mount_info *) -1) {
		parsed_info = NULL;
		fprintf(stderr, "Unable to allocate memory: %s\n",
				strerror(errno));
		rc = EX_SYSERR;
		goto mount_exit;
	}

	reinit_parsed_info = malloc(sizeof(*reinit_parsed_info));
	if (reinit_parsed_info == NULL) {
		fprintf(stderr, "Unable to allocate memory: %s\n",
				strerror(errno));
		rc = EX_SYSERR;
		goto mount_exit;
	}

	options = calloc(options_size, 1);
	if (!options) {
		fprintf(stderr, "Unable to allocate memory.\n");
		rc = EX_SYSERR;
		goto mount_exit;
	}

	/* add sharename in opts string as unc= parm */
	while ((c = getopt_long(argc, argv, "?fhno:rsvVw",
				longopts, NULL)) != -1) {
		switch (c) {
		case '?':
		case 'h':	/* help */
			rc = mount_usage(stdout);
			goto mount_exit;
		case 'n':
			++parsed_info->nomtab;
			break;
		case 'o':
			orgoptions = strndup(optarg, MAX_OPTIONS_LEN);
			if (!orgoptions) {
				rc = EX_SYSERR;
				goto mount_exit;
			}
			break;
		case 'r':	/* mount readonly */
			parsed_info->flags |= MS_RDONLY;
			break;
		case 'v':
			++parsed_info->verboseflag;
			break;
		case 'V':
			print_cifs_mount_version(thisprogram);
			exit(0);
		case 'w':
			parsed_info->flags &= ~MS_RDONLY;
			break;
		case 'f':
			++parsed_info->fakemnt;
			break;
		case 's':
			++sloppy;
			break;
		default:
			fprintf(stderr, "unknown command-line option: %c\n", c);
			rc = mount_usage(stderr);
			goto mount_exit;
		}
	}

	if (argc < optind + 2) {
		rc = mount_usage(stderr);
		goto mount_exit;
	}

	orig_dev = argv[optind];
	mountpoint = argv[optind + 1];

	/* chdir into mountpoint as soon as possible */
	rc = acquire_mountpoint(&mountpoint);
	if (rc) {
		goto mount_exit;
	}

	/* Before goto assemble_retry, reinitialize parsed_info with reinit_parsed_info */
	memcpy(reinit_parsed_info, parsed_info,	sizeof(*reinit_parsed_info));

assemble_retry:
	/*
	 * mount.cifs does privilege separation. Most of the code to handle
	 * assembling the mount info is done in a child process that drops
	 * privileges. The info is assembled in parsed_info which is a
	 * shared, mmaped memory segment. The parent waits for the child to
	 * exit and checks the return code. If it's anything but "0", then
	 * the process exits without attempting anything further.
	 */
	pid = fork();
	if (pid == -1) {
		fprintf(stderr, "Unable to fork: %s\n", strerror(errno));
		rc = EX_SYSERR;
		goto mount_exit;
	} else if (!pid) {
		/* child */
		rc = assemble_mountinfo(parsed_info, thisprogram, mountpoint,
					orig_dev, orgoptions);
		goto mount_child_exit;
	} else {
		/* parent */
		pid = wait(&rc);
		if (!WIFEXITED(rc)) {
			fprintf(stderr, "Child process terminated abnormally.\n");
			rc = EX_SYSERR;
			goto mount_exit;
		}
		rc = WEXITSTATUS(rc);
		if (rc)
			goto mount_exit;
	}

	currentaddress = parsed_info->addrlist;
	nextaddress = strchr(currentaddress, ',');
	if (nextaddress)
		*nextaddress++ = '\0';

mount_retry:
	options[0] = '\0';
	if (!currentaddress) {
		fprintf(stderr, "Unable to find suitable address.\n");
		rc = parsed_info->nofail ? 0 : EX_FAIL;
		goto mount_exit;
	}
	strlcpy(options, "ip=", options_size);
	strlcat(options, currentaddress, options_size);

	strlcat(options, ",unc=\\\\", options_size);
	strlcat(options, parsed_info->host, options_size);
	strlcat(options, "\\", options_size);
	strlcat(options, parsed_info->share, options_size);

	if (*parsed_info->options) {
		strlcat(options, ",", options_size);
		strlcat(options, parsed_info->options, options_size);
	}

	if (*parsed_info->prefix) {
		strlcat(options, ",prefixpath=", options_size);
		strlcat(options, parsed_info->prefix, options_size);
	}

	if (sloppy)
		strlcat(options, ",sloppy", options_size);

	if (parsed_info->verboseflag)
		fprintf(stderr, "%s kernel mount options: %s",
			thisprogram, options);

	if (parsed_info->got_password) {
		/*
		 * Commas have to be doubled, or else they will
		 * look like the parameter separator
		 */
		strlcat(options, ",pass=", options_size);
		strlcat(options, parsed_info->password, options_size);
		if (parsed_info->verboseflag)
			fprintf(stderr, ",pass=********");
	}

	if (parsed_info->got_password2) {
		strlcat(options, ",password2=", options_size);
		strlcat(options, parsed_info->password2, options_size);
		if (parsed_info->verboseflag)
			fprintf(stderr, ",password2=********");
	}

	if (parsed_info->verboseflag)
		fprintf(stderr, "\n");

	rc = check_mtab(thisprogram, orig_dev, mountpoint);
	if (rc)
		goto mount_exit;

	if (!parsed_info->fakemnt) {
		toggle_dac_capability(0, 1);
		rc = mount(orig_dev, ".", cifs_fstype, parsed_info->flags, options);
		toggle_dac_capability(0, 0);
		if (rc == 0)
			goto do_mtab;

		switch (errno) {
		case ECONNREFUSED:
		case EHOSTUNREACH:
			if (currentaddress) {
				fprintf(stderr, "mount error(%d): could not connect to %s",
					errno, currentaddress);
			}
			currentaddress = nextaddress;
			if (currentaddress) {
				nextaddress = strchr(currentaddress, ',');
				if (nextaddress)
					*nextaddress++ = '\0';
			}
			goto mount_retry;
		case ENODEV:
			fprintf(stderr,
				"mount error: %s filesystem not supported by the system\n", cifs_fstype);
			break;
		case EHOSTDOWN:
			fprintf(stderr,
				"mount error: Server abruptly closed the connection.\n"
				"This can happen if the server does not support the SMB version you are trying to use.\n"
				"The default SMB version recently changed from SMB1 to SMB2.1 and above. Try mounting with vers=1.0.\n");
			break;
		case ENXIO:
			if (!already_uppercased &&
			    uppercase_string(parsed_info->host) &&
			    uppercase_string(parsed_info->share) &&
			    uppercase_string(parsed_info->prefix) &&
			    uppercase_string(orig_dev)) {
				fprintf(stderr,
					"Retrying with upper case share name\n");
				already_uppercased = 1;
				goto mount_retry;
			}
			break;
		case ENOKEY:
			if (!fallback_sudo_uid && parsed_info->is_krb5) {
				/* mount could have failed because cruid option was not passed when triggered with sudo */
				value = getenv("SUDO_UID");
				if (value) {
					errno = 0;
					sudo_uid = strtoul(value, &ep, 10);
					if (errno == 0 && *ep == '\0' && sudo_uid) {
						/* Reinitialize parsed_info and assemble options again with sudo_uid */
						memcpy(parsed_info, reinit_parsed_info, sizeof(*parsed_info));
						parsed_info->sudo_uid = sudo_uid;
						fallback_sudo_uid = 1;
						goto assemble_retry;
					}
				}
			}
			break;
		}
		fprintf(stderr, "mount error(%d): %s\n", errno,
			strerror(errno));
		fprintf(stderr,
			"Refer to the %s(8) manual page (e.g. man "
			"%s) and kernel log messages (dmesg)\n", thisprogram, thisprogram);
		rc = EX_FAIL;
		goto mount_exit;
	}

do_mtab:
	if (!parsed_info->nomtab && !mtab_unusable()) {
		if (parsed_info->flags & MS_REMOUNT) {
			rc = del_mtab(mountpoint);
			if (rc)
				goto mount_exit;
		}

		rc = add_mtab(orig_dev, mountpoint, parsed_info->flags, cifs_fstype);
	}

mount_exit:
	if (parsed_info) {
		memset(parsed_info->password, 0, sizeof(parsed_info->password));
		memset(parsed_info->password2, 0, sizeof(parsed_info->password2));
		munmap(parsed_info, sizeof(*parsed_info));
	}

mount_child_exit:
	/* Objects to be freed both in main process and child */
	free(reinit_parsed_info);
	free(options);
	free(orgoptions);
	free(mountpoint);
	return rc;
}
