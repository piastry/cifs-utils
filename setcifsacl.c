/*
* setcifsacl utility
*
* Copyright (C) Shirish Pargaonkar (shirishp@us.ibm.com) 2011
*
* Used to alter entries of an ACL or replace an entire ACL in a
* security descriptor of a file system object that belongs to a
* share mounted using option cifsacl.
*
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
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <sys/xattr.h>

#include "cifsacl.h"
#include "idmap_plugin.h"

enum setcifsacl_actions {
	ActUnknown = -1,
	ActDelete,
	ActModify,
	ActAdd,
	ActSetAcl,
	ActSetOwner,
	ActSetGroup
};

static void *plugin_handle;
static bool plugin_loaded;

static int
copy_cifs_sid(struct cifs_sid *dst, const struct cifs_sid *src)
{
	int i, size = 0;

	dst->revision = src->revision;
	size += sizeof(uint8_t);

	dst->num_subauth = src->num_subauth;
	size += sizeof(uint8_t);

	for (i = 0; i < NUM_AUTHS; i++)
		dst->authority[i] = src->authority[i];
	size += (sizeof(uint8_t) * NUM_AUTHS);

	for (i = 0; i < src->num_subauth; i++)
		dst->sub_auth[i] = src->sub_auth[i];
	size += (sizeof(uint32_t) * src->num_subauth);

	return size;
}

static ssize_t
copy_sec_desc(const struct cifs_ntsd *pntsd, struct cifs_ntsd *pnntsd,
		int numaces, int acessize)
{
	int size, osidsoffset, gsidsoffset, dacloffset;
	ssize_t bufsize;
	struct cifs_sid *owner_sid_ptr, *group_sid_ptr;
	struct cifs_sid *nowner_sid_ptr, *ngroup_sid_ptr;
	struct cifs_ctrl_acl *dacl_ptr, *ndacl_ptr;

	/* copy security descriptor control portion */
	osidsoffset = le32toh(pntsd->osidoffset);
	gsidsoffset = le32toh(pntsd->gsidoffset);
	dacloffset = le32toh(pntsd->dacloffset);

	size = sizeof(struct cifs_ntsd);
	pnntsd->revision = pntsd->revision;
	pnntsd->type = pntsd->type;
	pnntsd->osidoffset = pntsd->osidoffset;
	pnntsd->gsidoffset = pntsd->gsidoffset;
	pnntsd->dacloffset = pntsd->dacloffset;
	bufsize = size;

	dacl_ptr = (struct cifs_ctrl_acl *)((char *)pntsd + dacloffset);
	ndacl_ptr = (struct cifs_ctrl_acl *)((char *)pnntsd + dacloffset);

	size = acessize + sizeof(struct cifs_ctrl_acl);
	ndacl_ptr->revision = dacl_ptr->revision;
	ndacl_ptr->size = htole16(size);
	ndacl_ptr->num_aces = htole32(numaces);
	bufsize += size;

	/* copy owner sid */
	owner_sid_ptr = (struct cifs_sid *)((char *)pntsd + osidsoffset);
	group_sid_ptr = (struct cifs_sid *)((char *)pntsd + gsidsoffset);
	/*
	 * some servers like Azure return the owner and group SIDs at end rather
	 * than at the beginning of the ACL so don't want to overwrite the last ACEs
         */
	if (dacloffset <= osidsoffset) {
		/* owners placed at end of ACL */
		nowner_sid_ptr = (struct cifs_sid *)((char *)pnntsd + dacloffset + size);
		osidsoffset = dacloffset + size;
		pnntsd->osidoffset = htole32(osidsoffset);
		size = copy_cifs_sid(nowner_sid_ptr, owner_sid_ptr);
		bufsize += size;
		/* put group SID after owner SID */
		ngroup_sid_ptr = (struct cifs_sid *)((char *)nowner_sid_ptr + size);
		gsidsoffset = osidsoffset + size;
		pnntsd->gsidoffset = htole32(gsidsoffset);
	} else {
		/*
		 * Most servers put the owner information at the beginning,
		 * before the ACL
		 */
		nowner_sid_ptr = (struct cifs_sid *)((char *)pnntsd + osidsoffset);
		size = copy_cifs_sid(nowner_sid_ptr, owner_sid_ptr);
		bufsize += size;
		ngroup_sid_ptr = (struct cifs_sid *)((char *)pnntsd + gsidsoffset);
	}

	/* copy group sid */
	size = copy_cifs_sid(ngroup_sid_ptr, group_sid_ptr);
	bufsize += size;

	return bufsize;
}

/*
 * This function (and the one above) does not need to set the SACL-related
 * fields, and this works fine because on the SMB protocol level, setting owner
 * info, DACL, and SACL requires one to use separate flags that control which
 * part of the descriptor is begin looked at on the server side
 */
static ssize_t
copy_sec_desc_with_sid(const struct cifs_ntsd *pntsd, struct cifs_ntsd *pnntsd,
		struct cifs_sid *sid, int maction)
{
	int size, daclsize;
	int osidoffset, gsidoffset, dacloffset;
	int nosidoffset, ngsidoffset, ndacloffset, nsidssize;
	ssize_t bufsize;
	struct cifs_sid *owner_sid_ptr, *group_sid_ptr;
	struct cifs_sid *nowner_sid_ptr, *ngroup_sid_ptr;
	struct cifs_ctrl_acl *dacl_ptr, *ndacl_ptr;

	/* copy security descriptor control portion */
	osidoffset = le32toh(pntsd->osidoffset);
	gsidoffset = le32toh(pntsd->gsidoffset);
	dacloffset = le32toh(pntsd->dacloffset);
	/*
	 * the size of the owner or group sid might be different from the old
	 * one, so the group sid offest might change, and if the owner is
	 * positioned before the DACL, the dacl offset might change as well;
	 * note however, that the owner sid offset does not change
	 */
	nosidoffset = osidoffset;
	size = sizeof(struct cifs_ntsd);
	pnntsd->revision = pntsd->revision;
	pnntsd->type = pntsd->type;
	pnntsd->osidoffset = pntsd->osidoffset;
	bufsize = size;

	/* set the pointers for source sids */
	if (maction == ActSetOwner) {
		owner_sid_ptr = sid;
		group_sid_ptr = (struct cifs_sid *)((char *)pntsd + gsidoffset);
	}
	if (maction == ActSetGroup) {
		owner_sid_ptr = (struct cifs_sid *)((char *)pntsd + osidoffset);
		group_sid_ptr = sid;
	}

	dacl_ptr = (struct cifs_ctrl_acl *)((char *)pntsd + dacloffset);
	daclsize = le16toh(dacl_ptr->size) + sizeof(struct cifs_ctrl_acl);

	/* copy owner sid */
	nowner_sid_ptr = (struct cifs_sid *)((char *)pnntsd + nosidoffset);
	size = copy_cifs_sid(nowner_sid_ptr, owner_sid_ptr);
	bufsize += size;
	nsidssize = size;

	/* copy group sid */
	ngsidoffset = nosidoffset + size;
	ngroup_sid_ptr = (struct cifs_sid *)((char *)pnntsd + ngsidoffset);
	pnntsd->gsidoffset = htole32(ngsidoffset);
	size = copy_cifs_sid(ngroup_sid_ptr, group_sid_ptr);
	bufsize += size;
	nsidssize += size;

	/* position the dacl control info as in the fetched descriptor */
	if (dacloffset <= osidoffset)
		ndacloffset = dacloffset;
	else
		ndacloffset = nosidoffset + nsidssize;
	ndacl_ptr = (struct cifs_ctrl_acl *)((char *)pnntsd + ndacloffset);
	pnntsd->dacloffset = htole32(ndacloffset);

	/* the DACL control fields do not change */
	ndacl_ptr->revision = dacl_ptr->revision;
	ndacl_ptr->size = dacl_ptr->size;
	ndacl_ptr->num_aces = dacl_ptr->num_aces;

	/*
	 * add DACL size (control portion and the array of aces) to the
	 * buffer size
	 */
	bufsize += daclsize;

	return bufsize;
}

static int
copy_ace(struct cifs_ace *dace, struct cifs_ace *sace)
{
	dace->type = sace->type;
	dace->flags = sace->flags;
	dace->access_req = sace->access_req;

	copy_cifs_sid(&dace->sid, &sace->sid);

	dace->size = sace->size;

	return le16toh(dace->size);
}

static int
compare_aces(struct cifs_ace *sace, struct cifs_ace *dace, int compflags)
{
	int i;

	if (compflags & COMPSID) {
		if (dace->sid.revision != sace->sid.revision)
			return 0;
		if (dace->sid.num_subauth != sace->sid.num_subauth)
			return 0;
		for (i = 0; i < NUM_AUTHS; i++) {
			if (dace->sid.authority[i] != sace->sid.authority[i])
				return 0;
		}
		for (i = 0; i < sace->sid.num_subauth; i++) {
			if (dace->sid.sub_auth[i] != sace->sid.sub_auth[i])
				return 0;
		}
	}

	if (compflags & COMPTYPE) {
		if (dace->type != sace->type)
			return 0;
	}

	if (compflags & COMPFLAG) {
		if (dace->flags != sace->flags)
			return 0;
	}

	if (compflags & COMPMASK) {
		if (dace->access_req != sace->access_req)
			return 0;
	}

	return 1;
}

static int
alloc_sec_desc(struct cifs_ntsd *pntsd, struct cifs_ntsd **npntsd,
			int aces, size_t *acesoffset)
{
	unsigned int size, acessize, bufsize, dacloffset;

	size = sizeof(struct cifs_ntsd) +
		2 * sizeof(struct cifs_sid) +
		sizeof(struct cifs_ctrl_acl);

	dacloffset = le32toh(pntsd->dacloffset);

	*acesoffset = dacloffset + sizeof(struct cifs_ctrl_acl);
	acessize = aces * sizeof(struct cifs_ace);
	bufsize = size + acessize;

	*npntsd = calloc(1, bufsize);
	if (!*npntsd) {
		printf("%s: Memory allocation failure", __func__);
		return errno;
	}

	return 0;
}

static int
ace_set(struct cifs_ntsd *pntsd, struct cifs_ntsd **npntsd, ssize_t *bufsize,
			struct cifs_ace **cacesptr, int numcaces)
{
	int i, rc, size = 0, acessize = 0;
	size_t acesoffset;
	char *acesptr;

	rc = alloc_sec_desc(pntsd, npntsd, numcaces, &acesoffset);
	if (rc)
		return rc;

	acesptr = (char *)*npntsd + acesoffset;
	for (i = 0; i < numcaces; ++i) {
		size = copy_ace((struct cifs_ace *)acesptr, cacesptr[i]);
		acessize += size;
		acesptr += size;
	}

	*bufsize = copy_sec_desc(pntsd, *npntsd, numcaces, acessize);

	return 0;
}

static int
ace_add(struct cifs_ntsd *pntsd, struct cifs_ntsd **npntsd, ssize_t *bufsize,
		struct cifs_ace **facesptr, int numfaces,
		struct cifs_ace **cacesptr, int numcaces)
{
	int i, rc, numaces, size, acessize = 0;
	size_t acesoffset;
	char *acesptr;

	numaces = numfaces + numcaces;
	rc = alloc_sec_desc(pntsd, npntsd, numaces, &acesoffset);
	if (rc)
		return rc;

	acesptr = (char *)*npntsd + acesoffset;
	for (i = 0; i < numfaces; ++i) {
		size = copy_ace((struct cifs_ace *)acesptr, facesptr[i]);
		acesptr += size;
		acessize += size;
	}
	for (i = 0; i < numcaces; ++i) {
		size = copy_ace((struct cifs_ace *)acesptr, cacesptr[i]);
		acesptr += size;
		acessize += size;
	}

	*bufsize = copy_sec_desc(pntsd, *npntsd, numaces, acessize);

	return 0;
}

static int
ace_modify(struct cifs_ntsd *pntsd, struct cifs_ntsd **npntsd, ssize_t *bufsize,
		struct cifs_ace **facesptr, int numfaces,
		struct cifs_ace **cacesptr, int numcaces)
{
	int i, j, rc, size, acessize = 0;
	size_t acesoffset;
	char *acesptr;

	if (numfaces == 0) {
		printf("%s: No entries to modify", __func__);
		return -1;
	}

	rc = alloc_sec_desc(pntsd, npntsd, numfaces, &acesoffset);
	if (rc)
		return rc;

	for (j = 0; j < numcaces; ++j) {
		for (i = 0; i < numfaces; ++i) {
			if (compare_aces(facesptr[i], cacesptr[j],
					COMPSID | COMPTYPE)) {
				copy_ace(facesptr[i], cacesptr[j]);
				break;
			}
		}
	}

	acesptr = (char *)*npntsd + acesoffset;
	for (i = 0; i < numfaces; ++i) {
		size = copy_ace((struct cifs_ace *)acesptr, facesptr[i]);
		acesptr += size;
		acessize += size;
	}

	*bufsize = copy_sec_desc(pntsd, *npntsd, numfaces, acessize);

	return 0;
}

static int
ace_delete(struct cifs_ntsd *pntsd, struct cifs_ntsd **npntsd, ssize_t *bufsize,
		struct cifs_ace **facesptr, int numfaces,
		struct cifs_ace **cacesptr, int numcaces)
{
	int i, j, numaces = 0, rc, size, acessize = 0;
	size_t acesoffset;
	char *acesptr;

	if (numfaces == 0) {
		printf("%s: No entries to delete\n", __func__);
		return -1;
	}

	if (numfaces < numcaces) {
		printf("%s: Invalid entries to delete\n", __func__);
		return -1;
	}

	rc = alloc_sec_desc(pntsd, npntsd, numfaces, &acesoffset);
	if (rc)
		return rc;

	acesptr = (char *)*npntsd + acesoffset;
	for (i = 0; i < numfaces; ++i) {
		for (j = 0; j < numcaces; ++j) {
			if (compare_aces(facesptr[i], cacesptr[j], COMPALL))
				break;
		}
		if (j == numcaces) {
			size = copy_ace((struct cifs_ace *)acesptr,
								facesptr[i]);
			acessize += size;
			acesptr += size;
			++numaces;
		}
	}

	if (numaces == numfaces) {
		printf("%s: Nothing to delete\n", __func__);
		return 1;
	}

	*bufsize = copy_sec_desc(pntsd, *npntsd, numaces, acessize);

	return 0;
}

static int
get_numfaces(struct cifs_ntsd *pntsd, ssize_t acl_len,
			struct cifs_ctrl_acl **daclptr)
{
	int numfaces = 0;
	uint32_t dacloffset;
	struct cifs_ctrl_acl *ldaclptr;
	char *end_of_acl = ((char *)pntsd) + acl_len;

	dacloffset = le32toh(pntsd->dacloffset);
	if (!dacloffset)
		return 0;

	ldaclptr = (struct cifs_ctrl_acl *)((char *)pntsd + dacloffset);

	/* validate that we do not go past end of acl */
	if (end_of_acl >= (char *)ldaclptr + le16toh(ldaclptr->size)) {
		numfaces = le32toh(ldaclptr->num_aces);
		*daclptr = ldaclptr;
	}

	return numfaces;
}

static struct cifs_ace **
build_fetched_aces(char *daclptr, int numfaces)
{
	int i, acl_size;
	char *acl_base;
	struct cifs_ace *pace, **facesptr;

	facesptr = calloc(numfaces, sizeof(struct cifs_aces *));
	if (!facesptr) {
		printf("%s: Error %d allocating ACE array",
				__func__, errno);
		return facesptr;
	}

	acl_base = daclptr;
	acl_size = sizeof(struct cifs_ctrl_acl);
	for (i = 0; i < numfaces; ++i) {
		facesptr[i] = malloc(sizeof(struct cifs_ace));
		if (!facesptr[i])
			goto build_fetched_aces_err;
		pace = (struct cifs_ace *) (acl_base + acl_size);
		memcpy(facesptr[i], pace, sizeof(struct cifs_ace));
		acl_base = (char *)pace;
		acl_size = le16toh(pace->size);
	}
	return facesptr;

build_fetched_aces_err:
	printf("%s: Invalid fetched ace\n", __func__);
	for (i = 0; i < numfaces; ++i)
		free(facesptr[i]);
	free(facesptr);
	return NULL;
}

static int
verify_ace_type(char *typestr, uint8_t *typeval)
{
	int i, len;
	char *invaltype;

	if (strstr(typestr, "0x")) { /* hex type value */
		*typeval = strtol(typestr, &invaltype, 16);
		if (!strlen(invaltype)) {
			if (*typeval != ACCESS_ALLOWED &&
				*typeval != ACCESS_DENIED &&
				*typeval != ACCESS_ALLOWED_OBJECT &&
				*typeval != ACCESS_DENIED_OBJECT) {
					printf("%s: Invalid type: %s\n",
						__func__, typestr);
					return 1;
			}
			return 0;
		}
	}

	len = strlen(typestr);
	for (i = 0; i < len; ++i)
		*(typestr + i) = toupper(*(typestr + i));
	if (!strcmp(typestr, "ALLOWED"))
		*typeval = 0x0;
	else if (!strcmp(typestr, "DENIED"))
		*typeval = 0x1;
	else if (!strcmp(typestr, "ALLOWED_OBJECT"))
		*typeval = 0x5;
	else if (!strcmp(typestr, "DENIED_OBJECT"))
		*typeval = 0x6;
	else {
		printf("%s: Invalid type: %s\n", __func__, typestr);
		return 1;
	}

	return 0;
}

static uint8_t
ace_flag_value(char *flagstr)
{
	uint8_t flagval = 0x0;
	char *iflag;

	iflag = strtok(flagstr, "|"); /* everything before | */
	while (iflag) {
		if (!strcmp(iflag, "OI"))
			flagval += 0x1;
		else if (!strcmp(iflag, "CI"))
			flagval += 0x2;
		else if (!strcmp(iflag, "NP"))
			flagval += 0x4;
		else if (!strcmp(iflag, "IO"))
			flagval += 0x8;
		else if (!strcmp(iflag, "I"))
			flagval += 0x10;
		else
			return 0x0; /* Invalid flag */
		iflag = strtok(NULL, "|"); /* everything before | */
	}

	return flagval;
}

static int
verify_ace_flags(char *flagstr, uint8_t *flagval)
{
	char *invalflag;

	if (!strcmp(flagstr, "0") || !strcmp(flagstr, "0x0"))
		return 0;

	if (strstr(flagstr, "0x")) { /* hex flag value */
		*flagval = strtol(flagstr, &invalflag, 16);
		if (strlen(invalflag)) {
			printf("%s: Invalid flags: %s\n", __func__, flagstr);
			return 1;
		}
	} else
		*flagval = ace_flag_value(flagstr);

	if (!*flagval || (*flagval & ~VFLAGS)) {
		printf("%s: Invalid flag %s and value: 0x%x\n",
			__func__, flagstr, *flagval);
		return 1;
	}

	return 0;
}

static uint32_t
ace_mask_value(char *mask)
{
	uint32_t maskval = 0;
	char cur;

	if (!strcmp(mask, "FULL"))
		return FULL_CONTROL;
	if (!strcmp(mask, "CHANGE"))
		return CHANGE;
	if (!strcmp(mask, "READ"))
		return EREAD;

	while((cur = *mask++)) {
		switch(cur) {
		case 'R':
			maskval |= EREAD;
			break;
		case 'W':
			maskval |= EWRITE;
			break;
		case 'X':
			maskval |= EXEC;
			break;
		case 'D':
			maskval |= DELETE;
			break;
		case 'P':
			maskval |= WRITE_DAC;
			break;
		case 'O':
			maskval |= WRITE_OWNER;
			break;
		default:
			return 0;
		}
	}
	return maskval;
}

static int
verify_ace_mask(char *maskstr, uint32_t *maskval)
{
	unsigned long val;
	char *ep;

	errno = 0;
	val = strtoul(maskstr, &ep, 0);
	if (errno == 0 && *ep == '\0')
		*maskval = htole32((uint32_t)val);
	else
		*maskval = htole32(ace_mask_value(maskstr));

	if (!*maskval) {
		printf("%s: Invalid mask %s (value 0x%x)\n", __func__,
			maskstr, *maskval);
		return 1;
	}

	return 0;
}

#define AUTHORITY_MASK (~(0xffffffffffffULL))

static int
raw_str_to_sid(const char *str, struct cifs_sid *csid)
{
	const char *p;
	char *q;
	unsigned long long x;

	/* Sanity check for either "S-" or "s-" */
	if ((str[0] != 'S' && str[0] != 's') || (str[1]!='-')) {
		plugin_errmsg = "SID string does not start with \"S-\"";
		return -EINVAL;
	}

	/* Get the SID revision number */
	p = str + 2;
	x = strtoull(p, &q, 10);
	if (x == 0 || x > UCHAR_MAX || !q || *q != '-') {
		plugin_errmsg = "Invalid SID revision number";
		return -EINVAL;
	}
	csid->revision = (uint8_t)x;

	/*
	 * Next the Identifier Authority. This is stored in big-endian in a
	 * 6 byte array. If the authority value is > UINT_MAX, then it should
	 * be expressed as a hex value.
	 */
	p = q + 1;
	x = strtoull(p, &q, 0);
	if ((x & AUTHORITY_MASK) || !q || *q !='-') {
		plugin_errmsg = "Invalid SID authority";
		return -EINVAL;
	}
	csid->authority[5] = (x & 0x0000000000ffULL);
	csid->authority[4] = (x & 0x00000000ff00ULL) >> 8;
	csid->authority[3] = (x & 0x000000ff0000ULL) >> 16;
	csid->authority[2] = (x & 0x0000ff000000ULL) >> 24;
	csid->authority[1] = (x & 0x00ff00000000ULL) >> 32;
	csid->authority[0] = (x & 0xff0000000000ULL) >> 40;

	/* now read the the subauthorities and store as __le32 vals */
	p = q + 1;
	csid->num_subauth = 0;
	while (csid->num_subauth < SID_MAX_SUB_AUTHORITIES) {
		x = strtoul(p, &q, 10);
		if (p == q)
			break;
		if (x > UINT_MAX) {
			plugin_errmsg = "Invalid sub authority value";
			return -EINVAL;
		}
		csid->sub_auth[csid->num_subauth++] = htole32((uint32_t)x);

		if (*q != '-')
			break;
		p = q + 1;
	}

	/* IF we ended early, then the SID could not be converted */
	if (q && *q != '\0') {
		plugin_errmsg = "Invalid sub authority value";
		return -EINVAL;
	}

	return 0;
}

static int
setcifsacl_str_to_sid(const char *str, struct cifs_sid *sid)
{
	if (plugin_loaded)
		return str_to_sid(plugin_handle, str, sid);
	return raw_str_to_sid(str, sid);
}

static struct cifs_ace **
build_cmdline_aces(char **arrptr, int numcaces)
{
	int i;
	char *acesid, *acetype, *aceflag, *acemask;
	struct cifs_ace **cacesptr;

	cacesptr = calloc(numcaces, sizeof(struct cifs_aces *));
	if (!cacesptr) {
		printf("%s: Error %d allocating ACE array", __func__, errno);
		return NULL;
	}

	for (i = 0; i < numcaces; ++i) {
		acesid = strtok(arrptr[i], ":");
		acetype = strtok(NULL, "/");
		aceflag = strtok(NULL, "/");
		acemask = strtok(NULL, "/");

		if (!acesid || !acetype || !aceflag || !acemask) {
			printf("%s: Incomplete ACE: %s\n", __func__, arrptr[i]);
			goto build_cmdline_aces_ret;
		}

		cacesptr[i] = calloc(1, sizeof(struct cifs_ace));
		if (!cacesptr[i]) {
			printf("%s: ACE alloc error %d\n", __func__, errno);
			goto build_cmdline_aces_ret;
		}

		if (setcifsacl_str_to_sid(acesid, &cacesptr[i]->sid)) {
			printf("%s: Invalid SID (%s): %s\n", __func__, arrptr[i],
				plugin_errmsg);
			goto build_cmdline_aces_ret;
		}

		if (verify_ace_type(acetype, &cacesptr[i]->type)) {
			printf("%s: Invalid ACE type: %s\n",
					__func__, arrptr[i]);
			goto build_cmdline_aces_ret;
		}

		if (verify_ace_flags(aceflag, &cacesptr[i]->flags)) {
			printf("%s: Invalid ACE flag: %s\n",
				__func__, arrptr[i]);
			goto build_cmdline_aces_ret;
		}

		if (verify_ace_mask(acemask, &cacesptr[i]->access_req)) {
			printf("%s: Invalid ACE mask: %s\n",
				__func__, arrptr[i]);
			goto build_cmdline_aces_ret;
		}

		cacesptr[i]->size = htole16(1 + 1 + 2 + 4 + 1 + 1 + 6 +
					    cacesptr[i]->sid.num_subauth * 4);
	}
	return cacesptr;

build_cmdline_aces_ret:
	for (i = 0; i < numcaces; ++i)
		free(cacesptr[i]);
	free(cacesptr);
	return NULL;
}

static char **
parse_cmdline_aces(char *acelist, int numcaces)
{
	int i = 0;
	char *acestr, *vacestr, **arrptr = NULL;

	arrptr = (char **)malloc(numcaces * sizeof(char *));
	if (!arrptr) {
		printf("%s: Unable to allocate char array\n", __func__);
		return NULL;
	}

	while (i < numcaces) {
		acestr = strtok(acelist, ","); /* everything before , */
		if (!acestr)
			goto parse_cmdline_aces_err;

		vacestr = strstr(acestr, "ACL:"); /* ace as ACL:*" */
		if (!vacestr)
			goto parse_cmdline_aces_err;
		vacestr += 4; /* skip past "ACL:" */
		if (*vacestr) {
			arrptr[i] = vacestr;
			++i;
		}
		acelist = NULL;
	}
	return arrptr;

parse_cmdline_aces_err:
	printf("%s: Error parsing ACEs\n", __func__);
	free(arrptr);
	return NULL;
}

/* How many aces were provided on the command-line? Count the commas. */
static unsigned int
get_numcaces(const char *aces)
{
	unsigned int num = 1;
	const char *current;

	current = aces;
	while((current = strchr(current, ','))) {
		++current;
		++num;
	}

	return num;
}

static int
setacl_action(struct cifs_ntsd *pntsd, struct cifs_ntsd **npntsd,
		ssize_t *bufsize, struct cifs_ace **facesptr, int numfaces,
		struct cifs_ace **cacesptr, int numcaces,
		enum setcifsacl_actions maction)
{
	int rc = 1;

	switch (maction) {
	case ActDelete:
		rc = ace_delete(pntsd, npntsd, bufsize, facesptr,
				numfaces, cacesptr, numcaces);
		break;
	case ActModify:
		rc = ace_modify(pntsd, npntsd, bufsize, facesptr,
				numfaces, cacesptr, numcaces);
		break;
	case ActAdd:
		rc = ace_add(pntsd, npntsd, bufsize, facesptr,
				numfaces, cacesptr, numcaces);
		break;
	case ActSetAcl:
		rc = ace_set(pntsd, npntsd, bufsize, cacesptr, numcaces);
		break;
	default:
		printf("%s: Invalid action: %d\n", __func__, maction);
		break;
	}

	return rc;
}

static void
setcifsacl_usage(const char *prog)
{
	fprintf(stderr,
	"%s: Alter CIFS/NTFS ACL or owner/group in a security descriptor of a file object\n",
		prog);
	fprintf(stderr, "Usage: %s option [<list_of_ACEs>|<SID>] <file_name>\n",
		prog);
	fprintf(stderr, "Valid options:\n");
	fprintf(stderr, "\t-v	Version of the program\n");
	fprintf(stderr, "\n\t-a	Add ACE(s), separated by a comma, to an ACL\n");
	fprintf(stderr,
	"\tsetcifsacl -a \"ACL:Administrator:ALLOWED/0x0/FULL\" <file_name>\n");
	fprintf(stderr, "\n");
	fprintf(stderr,
	"\t-D	Delete ACE(s), separated by a comma, from an ACL\n");
	fprintf(stderr,
	"\tsetcifsacl -D \"ACL:Administrator:DENIED/0x0/D\" <file_name>\n");
	fprintf(stderr, "\n");
	fprintf(stderr,
	"\t-M	Modify ACE(s), separated by a comma, in an ACL\n");
	fprintf(stderr,
	"\tsetcifsacl -M \"ACL:user1:ALLOWED/0x0/0x1e01ff\" <file_name>\n");
	fprintf(stderr,
	"\n\t-S	Replace existing ACL with ACE(s), separated by a comma\n");
	fprintf(stderr,
	"\tsetcifsacl -S \"ACL:Administrator:ALLOWED/0x0/D\" <file_name>\n");
	fprintf(stderr,
	"\n\t-o	Set owner using specified SID (name or raw format)\n");
	fprintf(stderr,
	"\tsetcifsacl -o \"Administrator\" <file_name>\n");
	fprintf(stderr,
	"\n\t-g	Set group using specified SID (name or raw format)\n");
	fprintf(stderr,
	"\tsetcifsacl -g \"Administrators\" <file_name>\n");
	fprintf(stderr, "\nRefer to setcifsacl(1) manpage for details\n");
}

int
main(const int argc, char *const argv[])
{
	int i, rc, c, numcaces = 0, numfaces = 0;
	enum setcifsacl_actions maction = ActUnknown;
	ssize_t attrlen, bufsize = BUFSIZE;
	char *ace_list = NULL, *filename = NULL, *attrval = NULL,
		**arrptr = NULL, *sid_str = NULL;
	struct cifs_ctrl_acl *daclptr = NULL;
	struct cifs_ace **cacesptr = NULL, **facesptr = NULL;
	struct cifs_ntsd *ntsdptr = NULL;
	struct cifs_sid sid;
	char *attrname = ATTRNAME_ACL;

	c = getopt(argc, argv, "hvD:M:a:S:o:g:");
	switch (c) {
	case 'D':
		maction = ActDelete;
		ace_list = optarg;
		break;
	case 'M':
		maction = ActModify;
		ace_list = optarg;
		break;
	case 'a':
		maction = ActAdd;
		ace_list = optarg;
		break;
	case 'S':
		maction = ActSetAcl;
		ace_list = optarg;
		break;
	case 'o':
		maction = ActSetOwner;
		sid_str = optarg;
		attrname = ATTRNAME_NTSD;
		break;
	case 'g':
		maction = ActSetGroup;
		sid_str = optarg;
		attrname = ATTRNAME_NTSD;
		break;
	case 'h':
		setcifsacl_usage(basename(argv[0]));
		return 0;
	case 'v':
		printf("Version: %s\n", VERSION);
		return 0;
	default:
		setcifsacl_usage(basename(argv[0]));
		return -1;
	}

	/* We expect 1 argument in addition to the option */
	if (argc != 4) {
		setcifsacl_usage(basename(argv[0]));
		return -1;
	}
	filename = argv[3];

	if (!ace_list && maction != ActSetOwner && maction != ActSetGroup) {
		printf("%s: No valid ACEs specified\n", __func__);
		return -1;
	}

	if (!sid_str && (maction == ActSetOwner || maction == ActSetGroup)) {
		printf("%s: No valid SIDs specified\n", __func__);
		return -1;
	}

	if (init_plugin(&plugin_handle)) {
		fprintf(stderr, "WARNING: unable to initialize idmapping "
				"plugin. Only \"raw\" SID strings will be "
				"accepted: %s\n", plugin_errmsg);
		plugin_loaded = false;
	} else {
		plugin_loaded = true;
	}

	if (maction == ActSetOwner || maction == ActSetGroup) {
		/* parse the sid */
		if (setcifsacl_str_to_sid(sid_str, &sid)) {
			printf("%s: failed to parce \'%s\' as SID\n", __func__,
				sid_str);
			goto setcifsacl_numcaces_ret;
		}
	} else {
		numcaces = get_numcaces(ace_list);

		arrptr = parse_cmdline_aces(ace_list, numcaces);
		if (!arrptr)
			goto setcifsacl_numcaces_ret;

		cacesptr = build_cmdline_aces(arrptr, numcaces);
		if (!cacesptr)
			goto setcifsacl_cmdlineparse_ret;
	}
cifsacl:
	if (bufsize >= XATTR_SIZE_MAX) {
		printf("%s: Buffer size %zd exceeds max size of %d\n",
				__func__, bufsize, XATTR_SIZE_MAX);
		goto setcifsacl_cmdlineverify_ret;
	}

	attrval = malloc(bufsize * sizeof(char));
	if (!attrval) {
		printf("error allocating memory for attribute value buffer\n");
		goto setcifsacl_cmdlineverify_ret;
	}

	attrlen = getxattr(filename, attrname, attrval, bufsize);
	if (attrlen == -1) {
		if (errno == ERANGE) {
			free(attrval);
			bufsize += BUFSIZE;
			goto cifsacl;
		} else {
			printf("getxattr error: %d\n", errno);
			goto setcifsacl_getx_ret;
		}
	}

	if (maction == ActSetOwner || maction == ActSetGroup) {
		struct cifs_ntsd *pfntsd = (struct cifs_ntsd *)attrval;
		int dacloffset = le32toh(pfntsd->dacloffset);
		struct cifs_ctrl_acl *daclinfo =
				(struct cifs_ctrl_acl *)(attrval + dacloffset);
		int numaces = le16toh(daclinfo->num_aces);
		int acessize = le32toh(daclinfo->size);
		size_t faceoffset, naceoffset;
		char *faceptr, *naceptr;

		/*
		 * this allocates large enough buffer for max sid size and the
		 * dacl info from the fetched security descriptor
		 */
		rc = alloc_sec_desc(pfntsd, &ntsdptr, numaces, &faceoffset);
		if (rc)
			goto setcifsacl_numcaces_ret;

		/*
		 * copy the control structures from the fetched descriptor, the
		 * sid specified by the user, and adjust the offsets/move dacl
		 * control structure if needed
		 */
		bufsize = copy_sec_desc_with_sid(pfntsd, ntsdptr, &sid,
				maction);

		/* copy aces verbatim as they have not changed */
		faceptr = attrval + faceoffset;
		naceoffset = le32toh(ntsdptr->dacloffset) +
				sizeof(struct cifs_ctrl_acl);
		naceptr = (char *)ntsdptr + naceoffset;
		memcpy(naceptr, faceptr, acessize);
	} else {
		bufsize = 0;

		numfaces = get_numfaces((struct cifs_ntsd *)attrval, attrlen,
				&daclptr);
		if (!numfaces && maction != ActAdd) {
			/* if we are not adding aces */
			printf("%s: Empty DACL\n", __func__);
			goto setcifsacl_facenum_ret;
		}

		facesptr = build_fetched_aces((char *)daclptr, numfaces);
		if (!facesptr)
			goto setcifsacl_facenum_ret;

		rc = setacl_action((struct cifs_ntsd *)attrval, &ntsdptr,
				&bufsize, facesptr, numfaces, cacesptr,
				numcaces, maction);
		if (rc)
			goto setcifsacl_action_ret;
	}

	attrlen = setxattr(filename, attrname, ntsdptr, bufsize, 0);
	if (attrlen == -1) {
		printf("%s: setxattr error: %s\n", __func__, strerror(errno));
		goto setcifsacl_action_ret;
	}

	if (plugin_loaded)
		exit_plugin(plugin_handle);
	return 0;

setcifsacl_action_ret:
	if (ntsdptr)
		free(ntsdptr);

setcifsacl_facenum_ret:
	if (facesptr) {
		for (i = 0; i < numfaces; ++i)
			free(facesptr[i]);
		free(facesptr);
	}

setcifsacl_getx_ret:
	if (attrval)
		free(attrval);

setcifsacl_cmdlineverify_ret:
	if (cacesptr) {
		for (i = 0; i < numcaces; ++i)
			free(cacesptr[i]);
		free(cacesptr);
	}

setcifsacl_cmdlineparse_ret:
	if (arrptr)
		free(arrptr);

setcifsacl_numcaces_ret:
	if (plugin_loaded)
		exit_plugin(plugin_handle);
	return -1;
}
