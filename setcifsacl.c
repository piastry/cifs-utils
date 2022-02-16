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

/*
 * This utility modifies various components of the security descriptor. These
 * actions require different permissions and different SMB protocol-level flags.
 * The user needs to make sure the share is mounted using the user credentials
 * for the user who has appropriate permissions and privileges. The kernel
 * CIFS client knows which flags to use based on the extended attribute name:
 * - system.cifs_acl - set dacl only
 * - system.cifs_ndst - set dacl and owner info
 * - system.cifs_ntsd_full - set dacl, owner, and sacl
 *
 * For simplicity, the utility modifies one component of the descriptor:
 * owner sid, group sid, DACL, or SACL. The rest of the descriptor is unchanged.
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
	ActSetGroup,
	ActSetSacl,
	ActAddReorder
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

static int
get_cifs_sid_size(const struct cifs_sid *sid)
{
	return (2 * sizeof(uint8_t) +
		sizeof(uint8_t) * NUM_AUTHS +
		sizeof(uint32_t) * sid->num_subauth);
}

/*
 * This function takes a pointer of the fetched (original) descriptor, and
 * it returns the offset of the ACL in the new descriptor.
 *
 * If the original descriptor does not have an ACL, the corresponding offset
 * is 0, and we need to determine where to place the ACL in the new descriptor.
 * If SACL offset is zero, and there is DACL (dacloffset is not 0), then we will
 * put SACL after DACL. If the DACL is not present either, we do not know if the
 * ACLs should go before or after the owner and group SIDs (see below), and so
 * we will use the offset right past the group SID.
 * Similarly, if DACL offset is zero, we will use the offset the past the end
 * of group SID.
 * @todo: need to add a command-line argument to know if this is
 *        Azure-style descriptor or a regular-style descriptor
 */
static int get_aces_offset(const struct cifs_ntsd *pntsd, ace_kinds ace_kind) {
	int dacloffset, sacloffset, acesoffset;

	switch(ace_kind) {
	case ACE_KIND_SACL:
		sacloffset = le32toh(pntsd->sacloffset);
		if (sacloffset) {
			acesoffset = sacloffset + sizeof(struct cifs_ctrl_acl);
		} else {
			dacloffset = le32toh(pntsd->dacloffset);
			if (dacloffset) {
				struct cifs_ctrl_acl *dacl_ptr =
					(struct cifs_ctrl_acl *)((char *)pntsd +
							dacloffset);
				acesoffset = dacloffset +
					le16toh(dacl_ptr->size) +
					sizeof(struct cifs_ctrl_acl);
			} else {
				int gsidoffset = le32toh(pntsd->gsidoffset);
				struct cifs_sid *group_sid_ptr =
					(struct cifs_sid *)((char *)pntsd +
							gsidoffset);
				int gsidsize = get_cifs_sid_size(group_sid_ptr);
				acesoffset = gsidoffset + gsidsize +
					sizeof(struct cifs_ctrl_acl);
			}
		}
		break;
	case ACE_KIND_DACL:
	default:
		dacloffset = le32toh(pntsd->dacloffset);
		if (dacloffset) {
			acesoffset = dacloffset + sizeof(struct cifs_ctrl_acl);
		} else {
			int gsidoffset = le32toh(pntsd->gsidoffset);
			struct cifs_sid *group_sid_ptr =
				(struct cifs_sid *)((char *)pntsd +
						gsidoffset);
			int gsidsize = get_cifs_sid_size(group_sid_ptr);
			acesoffset = gsidoffset + gsidsize +
				sizeof(struct cifs_ctrl_acl);
		}
		break;
	}
	return acesoffset;
}

int get_aces_size(const struct cifs_ntsd *pntsd, ace_kinds ace_kind) {
	int acloffset, size;
	struct cifs_ctrl_acl *acl_ptr;

	switch(ace_kind) {
	case ACE_KIND_SACL:
		acloffset = le32toh(pntsd->sacloffset);
		break;
	case ACE_KIND_DACL:
	default:
		acloffset = le32toh(pntsd->dacloffset);
	}
	if (acloffset) {
		acl_ptr = (struct cifs_ctrl_acl *)((char *)pntsd + acloffset);
		size = le16toh(acl_ptr->size);
	} else {
		size = 0;
	}
	return size;
}

uint16_t get_acl_revision(const struct cifs_ntsd *pntsd, ace_kinds ace_kind) {
	struct cifs_ctrl_acl *acl_ptr;
	int acloffset;
	switch(ace_kind) {
	case ACE_KIND_SACL:
		acloffset = le32toh(pntsd->sacloffset);
		if (acloffset) {
			acl_ptr = (struct cifs_ctrl_acl *)((char *)pntsd +
							   acloffset);
			return acl_ptr->revision;
		}
	/* intentional fall through */
	case ACE_KIND_DACL:
	default:
		acloffset = le32toh(pntsd->dacloffset);
		if (acloffset) {
			acl_ptr = (struct cifs_ctrl_acl *)((char *)pntsd +
							   acloffset);
			return acl_ptr->revision;
		} else {
			return DEFAULT_ACL_REVISION;
		}
		break;
	}
}

/*
 * The actual changes to the ACL specified in ace_kind are performed by the
 * caller of this function; this function copies/backfills the remaining
 * relevant compoenents of the security descriptor that remain unchanged.
 */
static ssize_t
copy_sec_desc(const struct cifs_ntsd *pntsd, struct cifs_ntsd *pnntsd,
		int numaces, int acessize, ace_kinds ace_kind)
{
	int size, osidsoffset, gsidsoffset, acloffset, dacloffset;
	ssize_t bufsize;
	struct cifs_sid *owner_sid_ptr, *group_sid_ptr;
	struct cifs_sid *nowner_sid_ptr, *ngroup_sid_ptr;
	struct cifs_ctrl_acl *nacl_ptr, *dacl_ptr;
	char *ndacl_ptr;

	/* copy security descriptor control portion */
	osidsoffset = le32toh(pntsd->osidoffset);
	gsidsoffset = le32toh(pntsd->gsidoffset);

	size = sizeof(struct cifs_ntsd);
	pnntsd->revision = pntsd->revision;
	pnntsd->type = pntsd->type;
	pnntsd->osidoffset = pntsd->osidoffset;
	pnntsd->gsidoffset = pntsd->gsidoffset;
	pnntsd->dacloffset = pntsd->dacloffset;
	bufsize = size;

	/* owner and group SIDs in the original defscriptor */
	owner_sid_ptr = (struct cifs_sid *)((char *)pntsd + osidsoffset);
	group_sid_ptr = (struct cifs_sid *)((char *)pntsd + gsidsoffset);

	/* get the offset of the acl control structure to initialize */
	acloffset = get_aces_offset(pntsd, ace_kind) - sizeof(struct cifs_ctrl_acl);
	if (ace_kind == ACE_KIND_SACL) {
		/* copy (unchanged) DACL if present, increment bufsize */
		dacloffset = le32toh(pntsd->dacloffset);
		if (dacloffset) {
			dacl_ptr = (struct cifs_ctrl_acl *)((char *)pntsd + dacloffset);
			ndacl_ptr = (char *)pnntsd + dacloffset;
			size = sizeof(struct cifs_ctrl_acl) + le16toh(dacl_ptr->size);
			memcpy(ndacl_ptr, (char *)dacl_ptr, size);
			bufsize += size;
		}
		/* initialize SACL offset */
		pnntsd->sacloffset = acloffset;
	}

	nacl_ptr = (struct cifs_ctrl_acl *)((char *)pnntsd + acloffset);
	nacl_ptr->revision = get_acl_revision(pntsd, ace_kind);
	size = acessize + sizeof(struct cifs_ctrl_acl);
	nacl_ptr->size = htole16(size);
	nacl_ptr->num_aces = htole32(numaces);
	bufsize += size;

	/* copy owner sid */

	/*
	 * some servers like Azure return the owner and group SIDs at end rather
	 * than at the beginning of the ACL so don't want to overwrite the last ACEs
         */
	if (acloffset <= osidsoffset) {
		/* owners placed at end of ACL */
		nowner_sid_ptr = (struct cifs_sid *)((char *)pnntsd + acloffset + size);
		osidsoffset = acloffset + size;
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
 * This function does not need to set the SACL-related fields, and this works
 * fine because the code path calling this function picks the 'system.cifs_ntsd'
 * attribute name. This name tells Linux CIFS client that SACL is not modified.
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

	if (dacloffset) {
		dacl_ptr = (struct cifs_ctrl_acl *)((char *)pntsd + dacloffset);
		daclsize = le16toh(dacl_ptr->size) + sizeof(struct cifs_ctrl_acl);
	} else {
		dacl_ptr = NULL;
		daclsize = 0;
	}

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
	if (dacloffset) {
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
	} else {
		pnntsd->dacloffset = 0;
	}
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

/*
 * This is somewhat suboptimal, but to keep the code simple, we will still
 * allocate the ACL control headers for DACL and SACL even thought there is
 * no corresponding ACL (dacloffset = 0 or sacloffset = 0).
 * When seetting DACL, we allocate sufficient space for the descriptor control
 * structure, owner and group sids, and the DACL (ACL control structure and
 * the aces).
 * When setting SACL, we allocate sufficient space to copy the above components
 * plus the SACL to be set (ACL controla and aces).
 */
static int
alloc_sec_desc(struct cifs_ntsd *pntsd, struct cifs_ntsd **npntsd,
		int aces, size_t *acesoffset, ace_kinds ace_kind)
{
	unsigned int size, acessize, bufsize;

	switch(ace_kind) {
	case ACE_KIND_SACL:
		size = sizeof(struct cifs_ntsd) +
			2 * sizeof(struct cifs_sid) +
			sizeof(struct cifs_ctrl_acl) +
			get_aces_size(pntsd, ACE_KIND_DACL) +
			sizeof(struct cifs_ctrl_acl);
		break;
	case ACE_KIND_DACL:
	default:
		size = sizeof(struct cifs_ntsd) +
			2 * sizeof(struct cifs_sid) +
			sizeof(struct cifs_ctrl_acl);
		break;
	}

	*acesoffset = get_aces_offset(pntsd, ace_kind);
	acessize = aces * sizeof(struct cifs_ace);
	bufsize = size + acessize;
	*npntsd = calloc(1, bufsize);
	if (!*npntsd) {
		fprintf(stderr, "%s: Memory allocation failure", __func__);
		return errno;
	}

	return 0;
}

static struct cifs_ace **
build_reorder_aces(struct cifs_ace **facesptr, int numfaces)
{
	struct cifs_ace *pace, **allowedacesptr, **deniedacesptr,
			**allowedinhacesptr, **deniedinhacesptr, **reorderacesptr;
	int i, numallowedaces, numdeniedaces,
	    numallowedinhaces, numdeniedinhaces, numreorderaces;

	allowedacesptr = calloc(numfaces, sizeof(struct cifs_ace *));
	deniedacesptr = calloc(numfaces, sizeof(struct cifs_ace *));
	allowedinhacesptr = calloc(numfaces, sizeof(struct cifs_ace *));
	deniedinhacesptr = calloc(numfaces, sizeof(struct cifs_ace *));
	reorderacesptr = calloc(numfaces, sizeof(struct cifs_ace *));

	numallowedaces = 0;
	numdeniedaces = 0;
	numallowedinhaces = 0;
	numdeniedinhaces = 0;
	numreorderaces = 0;

        for (i = 0; i < numfaces; i++) {
		pace = facesptr[i];
		if ((pace->type == ACCESS_DENIED) || (pace->type == ACCESS_DENIED_OBJECT)) {
			if (!(pace->flags & INHERITED_ACE_FLAG)) {
				deniedacesptr[numdeniedaces] = malloc(sizeof(struct cifs_ace));
				memcpy(deniedacesptr[numdeniedaces], pace, sizeof(struct cifs_ace));
				numdeniedaces++;
			} else {
				deniedinhacesptr[numdeniedinhaces] = malloc(sizeof(struct cifs_ace));
				memcpy(deniedinhacesptr[numdeniedinhaces], pace, sizeof(struct cifs_ace));
				numdeniedinhaces++;
			}
		} else if ((pace->type == ACCESS_ALLOWED) || (pace->type == ACCESS_ALLOWED_OBJECT)) {
			if (!(pace->flags & INHERITED_ACE_FLAG)) {
                                allowedacesptr[numallowedaces] = malloc(sizeof(struct cifs_ace));
                                memcpy(allowedacesptr[numallowedaces], pace, sizeof(struct cifs_ace));
                                numallowedaces++;
                        } else {
                                allowedinhacesptr[numallowedinhaces] = malloc(sizeof(struct cifs_ace));
                                memcpy(allowedinhacesptr[numallowedinhaces], pace, sizeof(struct cifs_ace));
                                numallowedinhaces++;
                        }
		}
	}

        for (i = 0; i < numdeniedaces; i++) {
		reorderacesptr[numreorderaces] = malloc(sizeof(struct cifs_ace));
		memcpy(reorderacesptr[numreorderaces], deniedacesptr[i], sizeof(struct cifs_ace));
		numreorderaces++;
		free(deniedacesptr[i]);
	}

	for (i = 0; i < numallowedaces; i++) {
		reorderacesptr[numreorderaces] = malloc(sizeof(struct cifs_ace));
		memcpy(reorderacesptr[numreorderaces], allowedacesptr[i], sizeof(struct cifs_ace));
		numreorderaces++;
		free(allowedacesptr[i]);
	}

	for (i = 0; i < numdeniedinhaces; i++) {
		reorderacesptr[numreorderaces] = malloc(sizeof(struct cifs_ace));
		memcpy(reorderacesptr[numreorderaces], deniedinhacesptr[i], sizeof(struct cifs_ace));
		numreorderaces++;
		free(deniedinhacesptr[i]);
	}

	for (i = 0; i < numallowedinhaces; i++) {
		reorderacesptr[numreorderaces] = malloc(sizeof(struct cifs_ace));
		memcpy(reorderacesptr[numreorderaces], allowedinhacesptr[i], sizeof(struct cifs_ace));
		numreorderaces++;
		free(allowedinhacesptr[i]);
	}

	free(deniedacesptr);
	free(allowedacesptr);
	free(deniedinhacesptr);
	free(allowedinhacesptr);

	return reorderacesptr;
}

static int
ace_set(struct cifs_ntsd *pntsd, struct cifs_ntsd **npntsd, ssize_t *bufsize,
		struct cifs_ace **cacesptr, int numcaces, ace_kinds ace_kind)
{
	int i, rc, size = 0, acessize = 0;
	size_t acesoffset;
	char *acesptr;

	rc = alloc_sec_desc(pntsd, npntsd, numcaces, &acesoffset, ace_kind);
	if (rc)
		return rc;

	acesptr = (char *)*npntsd + acesoffset;
	for (i = 0; i < numcaces; ++i) {
		size = copy_ace((struct cifs_ace *)acesptr, cacesptr[i]);
		acessize += size;
		acesptr += size;
	}

	*bufsize = copy_sec_desc(pntsd, *npntsd, numcaces, acessize, ace_kind);

	return 0;
}

static int
ace_add(struct cifs_ntsd *pntsd, struct cifs_ntsd **npntsd, ssize_t *bufsize,
		struct cifs_ace **facesptr, int numfaces,
		struct cifs_ace **cacesptr, int numcaces,
		ace_kinds ace_kind)
{
	int i, rc, numaces, size, acessize = 0;
	size_t acesoffset;
	char *acesptr;

	numaces = numfaces + numcaces;
	rc = alloc_sec_desc(pntsd, npntsd, numaces, &acesoffset, ace_kind);
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

	*bufsize = copy_sec_desc(pntsd, *npntsd, numaces, acessize, ace_kind);

	return 0;
}

static int
ace_add_reorder(struct cifs_ntsd *pntsd, struct cifs_ntsd **npntsd, ssize_t *bufsize,
		struct cifs_ace **facesptr, int numfaces,
		struct cifs_ace **cacesptr, int numcaces,
		ace_kinds ace_kind)
{
	struct cifs_ace **reorderacesptr, **totalacesptr;
	int i, rc, numaces;

	numaces = numfaces + numcaces;
	totalacesptr = calloc(numaces, sizeof(struct cifs_ace *));

	for (i = 0; i < numfaces; i++) {
		totalacesptr[i] = facesptr[i];
	}

	for (i = numfaces; i < numaces; i++) {
		totalacesptr[i] = cacesptr[i - numfaces];
	}

	reorderacesptr = build_reorder_aces(totalacesptr, numaces);
	rc = ace_add(pntsd, npntsd, bufsize, reorderacesptr,
			numaces, cacesptr, 0, ace_kind);

	free(totalacesptr);
	free(reorderacesptr);
	return rc;
}

static int
ace_modify(struct cifs_ntsd *pntsd, struct cifs_ntsd **npntsd, ssize_t *bufsize,
		struct cifs_ace **facesptr, int numfaces,
		struct cifs_ace **cacesptr, int numcaces,
		ace_kinds ace_kind)
{
	int i, j, rc, size, acessize = 0;
	size_t acesoffset;
	char *acesptr;

	if (numfaces == 0) {
		fprintf(stderr, "%s: No entries to modify", __func__);
		return -1;
	}

	rc = alloc_sec_desc(pntsd, npntsd, numfaces, &acesoffset, ace_kind);
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

	*bufsize = copy_sec_desc(pntsd, *npntsd, numfaces, acessize, ace_kind);

	return 0;
}

static int
ace_delete(struct cifs_ntsd *pntsd, struct cifs_ntsd **npntsd, ssize_t *bufsize,
		struct cifs_ace **facesptr, int numfaces,
		struct cifs_ace **cacesptr, int numcaces,
		ace_kinds ace_kind)
{
	int i, j, numaces = 0, rc, size, acessize = 0;
	size_t acesoffset;
	char *acesptr;

	if (numfaces == 0) {
		fprintf(stderr, "%s: No entries to delete\n", __func__);
		return -1;
	}

	if (numfaces < numcaces) {
		fprintf(stderr, "%s: Invalid entries to delete\n", __func__);
		return -1;
	}

	rc = alloc_sec_desc(pntsd, npntsd, numfaces, &acesoffset, ace_kind);
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
		fprintf(stderr, "%s: Nothing to delete\n", __func__);
		return 1;
	}

	*bufsize = copy_sec_desc(pntsd, *npntsd, numaces, acessize, ace_kind);

	return 0;
}

static int
get_numfaces(struct cifs_ntsd *pntsd, ssize_t acl_len,
		struct cifs_ctrl_acl **aclptr, ace_kinds ace_kind)
{
	int numfaces = 0;
	uint32_t acloffset;
	struct cifs_ctrl_acl *laclptr;
	char *end_of_acl = ((char *)pntsd) + acl_len;

	switch(ace_kind) {
	case ACE_KIND_SACL:
		acloffset = le32toh(pntsd->sacloffset);
		break;
	case ACE_KIND_DACL:
	default:
		acloffset = le32toh(pntsd->dacloffset);
		break;
	}

	if (!acloffset)
		return 0;

	laclptr = (struct cifs_ctrl_acl *)((char *)pntsd + acloffset);

	/* validate that we do not go past end of acl */
	if (end_of_acl >= (char *)laclptr + le16toh(laclptr->size)) {
		numfaces = le32toh(laclptr->num_aces);
		*aclptr = laclptr;
	}

	return numfaces;
}

static struct cifs_ace **
build_fetched_aces(char *aclptr, int numfaces)
{
	int i, acl_size;
	char *acl_base;
	struct cifs_ace *pace, **facesptr;

	facesptr = calloc(numfaces, sizeof(struct cifs_ace *));
	if (!facesptr) {
		fprintf(stderr, "%s: Error %d allocating ACE array",
				__func__, errno);
		return facesptr;
	}

	acl_base = aclptr;
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
	fprintf(stderr, "%s: Invalid fetched ace\n", __func__);
	for (i = 0; i < numfaces; ++i)
		free(facesptr[i]);
	free(facesptr);
	return NULL;
}

static int
verify_ace_type(char *typestr, uint8_t *typeval, ace_kinds ace_kind)
{
	int i, len;
	char *invaltype;
	uint8_t ace_type_mask;

	switch(ace_kind) {
	case ACE_KIND_SACL:
		ace_type_mask = SACL_VTYPES;
		break;
	case ACE_KIND_DACL:
	default:
		ace_type_mask = DACL_VTYPES;
		break;
	}

	if (strstr(typestr, "0x")) { /* hex type value */
		*typeval = strtol(typestr, &invaltype, 16);
		if (!strlen(invaltype)) {
			/* the type must be a single bit from the bit mask */
			if (*typeval != (*typeval & ace_type_mask)) {
				fprintf(stderr, "%s: Invalid type: %s\n",
					__func__, typestr);
				return 1;
			}
			return 0;
		}
	}

	len = strlen(typestr);
	switch(ace_kind) {
	case ACE_KIND_SACL:
		for (i = 0; i < len; ++i)
			*(typestr + i) = toupper(*(typestr + i));
		if (!strcmp(typestr, "AUDIT"))
			*typeval = SYSTEM_AUDIT;
		else if (!strcmp(typestr, "AUDIT_OBJECT"))
			*typeval = SYSTEM_AUDIT_OBJECT;
		else if (!strcmp(typestr, "AUDIT_CALLBACK"))
			*typeval = SYSTEM_AUDIT_CALLBACK;
		else if (!strcmp(typestr, "AUDIT_CALLBACK_OBJECT"))
			*typeval = SYSTEM_AUDIT_CALLBACK_OBJECT;
		else if (!strcmp(typestr, "MANDATODY_LABEL"))
			*typeval = SYSTEM_MANDATORY_LABEL;
		else if (!strcmp(typestr, "RESOURCE_ATTRIBUTE"))
			*typeval = SYSTEM_RESOURCE_ATTRIBUTE;
		else if (!strcmp(typestr, "SCOPED_POLICY_ID"))
			*typeval = SYSTEM_SCOPED_POLICY_ID;
		else {
			fprintf(stderr, "%s: Invalid type: %s\n", __func__,
				typestr);
			return 1;
		}
		break;
	case ACE_KIND_DACL:
	default:
		for (i = 0; i < len; ++i)
			*(typestr + i) = toupper(*(typestr + i));
		if (!strcmp(typestr, "ALLOWED"))
			*typeval = ACCESS_ALLOWED;
		else if (!strcmp(typestr, "DENIED"))
			*typeval = ACCESS_DENIED;
		else if (!strcmp(typestr, "ALLOWED_OBJECT"))
			*typeval = ACCESS_ALLOWED_OBJECT;
		else if (!strcmp(typestr, "DENIED_OBJECT"))
			*typeval = ACCESS_DENIED_OBJECT;
		else {
		fprintf(stderr, "%s: Invalid type: %s\n", __func__, typestr);
			return 1;
		}
		break;
	}

	return 0;
}

static uint8_t
ace_flag_value(char *flagstr, ace_kinds ace_kind)
{
	uint8_t flagval = 0x0;
	char *iflag;

	iflag = strtok(flagstr, "|"); /* everything before | */
	switch(ace_kind) {
	case ACE_KIND_SACL:
		while (iflag) {
			if (!strcmp(iflag, "SA"))
				flagval |= SUCCESSFUL_ACCESS;
			else if (!strcmp(iflag, "FA"))
				flagval |= FAILED_ACCESS;
			else
				return 0x0; /* Invalid flag */
			iflag = strtok(NULL, "|"); /* everything before | */
		}
		break;
	case ACE_KIND_DACL:
	default:
		while (iflag) {
			if (!strcmp(iflag, "OI"))
				flagval |= OBJECT_INHERIT_FLAG;
			else if (!strcmp(iflag, "CI"))
				flagval |= CONTAINER_INHERIT_FLAG;
			else if (!strcmp(iflag, "NP"))
				flagval |= NO_PROPAGATE_INHERIT_FLAG;
			else if (!strcmp(iflag, "IO"))
				flagval |= INHERIT_ONLY_FLAG;
			else if (!strcmp(iflag, "I"))
				flagval |= INHERITED_ACE_FLAG;
			else
				return 0x0; /* Invalid flag */
			iflag = strtok(NULL, "|"); /* everything before | */
		}
		break;
	}

	return flagval;
}

static int
verify_ace_flags(char *flagstr, uint8_t *flagval, ace_kinds ace_kind)
{
	char *invalflag;
	uint8_t ace_flag_mask = 0;

	if (!strcmp(flagstr, "0") || !strcmp(flagstr, "0x0"))
		return 0;

	if (strstr(flagstr, "0x")) { /* hex flag value */
		*flagval = strtol(flagstr, &invalflag, 16);
		if (strlen(invalflag)) {
			fprintf(stderr, "%s: Invalid flags: %s\n", __func__,
				flagstr);
			return 1;
		}
	} else
		*flagval = ace_flag_value(flagstr, ace_kind);

	switch(ace_kind) {
	case ACE_KIND_SACL:
		ace_flag_mask = SACL_VFLAGS;
		break;
	case ACE_KIND_DACL:
	default:
		ace_flag_mask = DACL_VFLAGS;
		break;
	}
	if (!*flagval || (*flagval & ~ace_flag_mask)) {
		fprintf(stderr, "%s: Invalid flag %s and value: 0x%x\n",
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
	if (!strcmp(mask, "RWXDPO"))
		return ALL_ACCESS_BITS;

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
		fprintf(stderr, "%s: Invalid mask %s (value 0x%x)\n", __func__,
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
build_cmdline_aces(char **arrptr, int numcaces, ace_kinds ace_kind)
{
	int i;
	char *acesid, *acetype, *aceflag, *acemask;
	struct cifs_ace **cacesptr;
	uint32_t access_req = 0;

	cacesptr = calloc(numcaces, sizeof(struct cifs_ace *));
	if (!cacesptr) {
		fprintf(stderr, "%s: Error %d allocating ACE array", __func__,
			errno);
		return NULL;
	}

	for (i = 0; i < numcaces; ++i) {
		acesid = strtok(arrptr[i], ":");
		acetype = strtok(NULL, "/");
		aceflag = strtok(NULL, "/");
		acemask = strtok(NULL, "/");

		if (!acesid || !acetype || !aceflag || !acemask) {
			fprintf(stderr, "%s: Incomplete ACE: %s\n", __func__,
				arrptr[i]);
			goto build_cmdline_aces_ret;
		}

		cacesptr[i] = calloc(1, sizeof(struct cifs_ace));
		if (!cacesptr[i]) {
			fprintf(stderr, "%s: ACE alloc error %d\n", __func__,
				errno);
			goto build_cmdline_aces_ret;
		}

		if (setcifsacl_str_to_sid(acesid, &cacesptr[i]->sid)) {
			fprintf(stderr, "%s: Invalid SID (%s): %s\n", __func__,
				arrptr[i], plugin_errmsg);
			goto build_cmdline_aces_ret;
		}

		if (verify_ace_type(acetype, &cacesptr[i]->type, ace_kind)) {
			fprintf(stderr, "%s: Invalid ACE type: %s\n",
					__func__, arrptr[i]);
			goto build_cmdline_aces_ret;
		}

		if (verify_ace_flags(aceflag, &cacesptr[i]->flags, ace_kind)) {
			fprintf(stderr, "%s: Invalid ACE flag: %s\n",
				__func__, arrptr[i]);
			goto build_cmdline_aces_ret;
		}

		if (verify_ace_mask(acemask, &access_req)) {
			fprintf(stderr, "%s: Invalid ACE mask: %s\n",
				__func__, arrptr[i]);
			goto build_cmdline_aces_ret;
		}

		cacesptr[i]->access_req = access_req;

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
		fprintf(stderr, "%s: Unable to allocate char array\n",
			__func__);
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
	fprintf(stderr, "%s: Error parsing ACEs\n", __func__);
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
		enum setcifsacl_actions maction, ace_kinds ace_kind)
{
	int rc = 1;

	switch (maction) {
	case ActDelete:
		rc = ace_delete(pntsd, npntsd, bufsize, facesptr,
				numfaces, cacesptr, numcaces, ace_kind);
		break;
	case ActModify:
		rc = ace_modify(pntsd, npntsd, bufsize, facesptr,
				numfaces, cacesptr, numcaces, ace_kind);
		break;
	case ActAdd:
		rc = ace_add(pntsd, npntsd, bufsize, facesptr,
				numfaces, cacesptr, numcaces, ace_kind);
		break;
	case ActSetAcl:
		rc = ace_set(pntsd, npntsd, bufsize, cacesptr, numcaces,
				ace_kind);
		break;
	case ActAddReorder:
		rc = ace_add_reorder(pntsd, npntsd, bufsize, facesptr,
				numfaces, cacesptr, numcaces, ace_kind);
		break;
	default:
		fprintf(stderr, "%s: Invalid action: %d\n", __func__, maction);
		break;
	}

	return rc;
}

static void
setcifsacl_usage(const char *prog)
{
	fprintf(stderr,
	"%s: Alter components of CIFS/NTFS security descriptor of a file object\n",
		prog);
	fprintf(stderr, "Usage: %s option [<list_of_ACEs>|<SID>] <file_name>\n",
		prog);
	fprintf(stderr, "Valid options:\n");
	fprintf(stderr, "\t-v	Version of the program\n");
	fprintf(stderr, "\t-U	Used in combination with -a, -D, -M, -S in order to ");
	fprintf(stderr, "\n\t	apply the actions to SALC (aUdit ACL); if not specified, ");
	fprintf(stderr, "\n\t	the actions apply to DACL\n");
	fprintf(stderr, "\n\t-a	Add ACE(s), separated by a comma, to an ACL\n");
	fprintf(stderr,
	"\tsetcifsacl -a \"ACL:Administrator:ALLOWED/0x0/FULL\" <file_name>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "\t-A	Add ACE(s) and reorder, separated by a comma, to an ACL\n");
	fprintf(stderr,
	"\tsetcifsacl -A \"ACL:Administrator:ALLOWED/0x0/FULL\" <file_name>\n");
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
	struct cifs_ctrl_acl *aclptr = NULL;
	struct cifs_ace **cacesptr = NULL, **facesptr = NULL;
	struct cifs_ntsd *ntsdptr = NULL;
	struct cifs_sid sid;
	char *attrname = ATTRNAME_ACL;
	ace_kinds ace_kind = ACE_KIND_DACL;

	while ((c = getopt(argc, argv, "hvD:M:a:A:S:o:g:U")) != -1) {
		switch (c) {
		case 'U':
			ace_kind = ACE_KIND_SACL;
			attrname = ATTRNAME_NTSD_FULL;
			break;
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
		case 'A':
			maction = ActAddReorder;
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
	}

	/* We expect 1 required and one optional argument in addition to the option */
	if (argc < 4 || argc > 5) {
		setcifsacl_usage(basename(argv[0]));
		return -1;
	}
	filename = argv[argc-1];

	if (!ace_list && maction != ActSetOwner && maction != ActSetGroup) {
		fprintf(stderr, "%s: No valid ACEs specified\n", __func__);
		return -1;
	}

	if (!sid_str && (maction == ActSetOwner || maction == ActSetGroup)) {
		fprintf(stderr, "%s: No valid SIDs specified\n", __func__);
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
		if (ace_kind == ACE_KIND_SACL) {
			fprintf(stderr, "WARNING: disregarding -U when setting"
					" owner/group\n");
			ace_kind = ACE_KIND_DACL;
		}
		/* parse the sid */
		if (setcifsacl_str_to_sid(sid_str, &sid)) {
			fprintf(stderr, "%s: failed to parce \'%s\' as SID\n",
				__func__, sid_str);
			goto setcifsacl_numcaces_ret;
		}
	} else {
		numcaces = get_numcaces(ace_list);

		arrptr = parse_cmdline_aces(ace_list, numcaces);
		if (!arrptr)
			goto setcifsacl_numcaces_ret;

		cacesptr = build_cmdline_aces(arrptr, numcaces, ace_kind);
		if (!cacesptr)
			goto setcifsacl_cmdlineparse_ret;
	}
cifsacl:
	if (bufsize >= XATTR_SIZE_MAX) {
		fprintf(stderr, "%s: Buffer size %zd exceeds max size of %d\n",
				__func__, bufsize, XATTR_SIZE_MAX);
		goto setcifsacl_cmdlineverify_ret;
	}

	attrval = malloc(bufsize * sizeof(char));
	if (!attrval) {
		fprintf(stderr, "error allocating memory for attribute value "
			"buffer\n");
		goto setcifsacl_cmdlineverify_ret;
	}

	attrlen = getxattr(filename, attrname, attrval, bufsize);
	if (attrlen == -1) {
		if (errno == ERANGE) {
			free(attrval);
			bufsize += BUFSIZE;
			goto cifsacl;
		} else {
			fprintf(stderr, "getxattr error: %d\n", errno);
			goto setcifsacl_getx_ret;
		}
	}

	if (maction == ActSetOwner || maction == ActSetGroup) {
		struct cifs_ntsd *pfntsd = (struct cifs_ntsd *)attrval;
		int dacloffset = le32toh(pfntsd->dacloffset);
		struct cifs_ctrl_acl *daclinfo;
		int numaces, acessize;
		size_t faceoffset, naceoffset;
		char *faceptr, *naceptr;
		/*
		 * dacloffset of 0 means "no DACL - all access for everyone"
		 * if dacloffset is not 0, it is still possible that DACL is
		 * empty - numaces is zero - "no access for anyone"
		 */
		if (dacloffset) {
			daclinfo = (struct cifs_ctrl_acl *)(attrval + dacloffset);
			numaces = le16toh(daclinfo->num_aces);
			acessize = le32toh(daclinfo->size);
		} else {
			daclinfo = NULL;
			numaces = 0;
			acessize = 0;
		}
		/*
		 * this allocates large enough buffer for max sid size and the
		 * dacl info from the fetched security descriptor
		 */
		rc = alloc_sec_desc(pfntsd, &ntsdptr, numaces, &faceoffset,
				ACE_KIND_DACL);
		if (rc)
			goto setcifsacl_numcaces_ret;

		/*
		 * copy the control structures from the fetched descriptor, the
		 * sid specified by the user, and adjust the offsets/move dacl
		 * control structure if needed
		 */
		bufsize = copy_sec_desc_with_sid(pfntsd, ntsdptr, &sid,
				maction);

		/* copy DACL aces verbatim as they have not changed */
		if (dacloffset) {
			faceptr = attrval + faceoffset;
			naceoffset = le32toh(ntsdptr->dacloffset) +
				sizeof(struct cifs_ctrl_acl);
			naceptr = (char *)ntsdptr + naceoffset;
			memcpy(naceptr, faceptr, acessize);
		}
	} else {
		bufsize = 0;

		numfaces = get_numfaces((struct cifs_ntsd *)attrval, attrlen,
				&aclptr, ace_kind);
		if (!numfaces && (maction != ActAdd && maction != ActAddReorder)) {
			/* if we are not adding aces */
			fprintf(stderr, "%s: Empty DACL\n", __func__);
			goto setcifsacl_facenum_ret;
		}

		facesptr = build_fetched_aces((char *)aclptr, numfaces);
		if (!facesptr)
			goto setcifsacl_facenum_ret;

		rc = setacl_action((struct cifs_ntsd *)attrval, &ntsdptr,
				&bufsize, facesptr, numfaces, cacesptr,
				numcaces, maction, ace_kind);
		if (rc)
			goto setcifsacl_action_ret;
	}

	attrlen = setxattr(filename, attrname, ntsdptr, bufsize, 0);
	if (attrlen == -1) {
		fprintf(stderr, "%s: setxattr error: %s\n", __func__,
			strerror(errno));
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
