/*
 * smbinfo
 *
 * Copyright (C) Ronnie Sahlberg (lsahlberg@redhat.com) 2018
 * Copyright (C) Aurelien Aptel (aaptel@suse.com) 2018
 *
 * Display SMB-specific file information using cifs IOCTL
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

#include <endian.h>
#include <errno.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>

#define CIFS_IOCTL_MAGIC 0xCF

/* query_info flags */
#define PASSTHRU_QUERY_INFO     0x00000000
#define PASSTHRU_FSCTL          0x00000001

struct smb_query_info {
	uint32_t   info_type;
	uint32_t   file_info_class;
	uint32_t   additional_information;
	uint32_t   flags;
	uint32_t   input_buffer_length;
	uint32_t   output_buffer_length;
	/* char buffer[]; */
} __packed;

#define CIFS_QUERY_INFO _IOWR(CIFS_IOCTL_MAGIC, 7, struct smb_query_info)
#define INPUT_BUFFER_LENGTH 16384

int verbose;

static void
usage(char *name)
{
	fprintf(stderr, "Usage: %s [-V] <command> <file>\n"
		"-V for verbose output\n"
		"Commands are\n"
		"  fileaccessinfo:\n"
		"      Prints FileAccessInfo for a cifs file.\n"
		"  filealigninfo:\n"
		"      Prints FileAlignInfo for a cifs file.\n"
		"  fileallinfo:\n"
		"      Prints FileAllInfo for a cifs file.\n"
		"  filebasicinfo:\n"
		"      Prints FileBasicInfo for a cifs file.\n"
		"  fileeainfo:\n"
		"      Prints FileEAInfo for a cifs file.\n"
		"  filefsfullsizeinfo:\n"
		"      Prints FileFsFullSizeInfo for a cifs share.\n"
		"  fileinternalinfo:\n"
		"      Prints FileInternalInfo for a cifs file.\n"
		"  filemodeinfo:\n"
		"      Prints FileModeInfo for a cifs file.\n"
		"  filepositioninfo:\n"
		"      Prints FilePositionInfo for a cifs file.\n"
		"  filestandardinfo:\n"
		"      Prints FileStandardInfo for a cifs file.\n"
		"  fsctl-getobjid:\n"
		"      Prints the objectid of the file and GUID of the underlying volume.\n"
		"  list-snapshots:\n"
		"      List the previous versions of the volume that backs this file.\n"
		"  quota:\n"
		"      Prints the quota for a cifs file.\n"
		"  secdesc:\n"
		"      Prints the security descriptor for a cifs file.\n",
		name);
	exit(1);
}

static void
win_to_timeval(uint64_t smb2_time, struct timeval *tv)
{
	tv->tv_usec = (smb2_time / 10) % 1000000;
	tv->tv_sec  = (smb2_time - 116444736000000000) / 10000000;
}

struct bit_string {
	unsigned int bit;
	char *string;
};

struct bit_string directory_access_mask[] = {
	{ 0x00000001, "LIST_DIRECTORY" },
	{ 0x00000002, "ADD_FILE" },
	{ 0x00000004, "ADD_SUBDIRECTORY" },
	{ 0x00000008, "READ_EA" },
	{ 0x00000010, "WRITE_EA" },
	{ 0x00000020, "TRAVERSE" },
	{ 0x00000040, "DELETE_CHILD" },
	{ 0x00000080, "READ_ATTRIBUTES" },
	{ 0x00000100, "WRITE_ATTRIBUTES" },
	{ 0x00010000, "DELETE" },
	{ 0x00020000, "READ_CONTROL" },
	{ 0x00040000, "WRITE_DAC" },
	{ 0x00080000, "WRITE_OWNER" },
	{ 0x00100000, "SYNCHRONIZER" },
	{ 0x01000000, "ACCESS_SYSTEM_SECURITY" },
	{ 0x02000000, "MAXIMUM_ALLOWED" },
	{ 0x10000000, "GENERIC_ALL" },
	{ 0x20000000, "GENERIC_EXECUTE" },
	{ 0x40000000, "GENERIC_WRITE" },
	{ 0x80000000, "GENERIC_READ" },
	{ 0, NULL }
};

struct bit_string file_access_mask[] = {
	{ 0x00000001, "READ_DATA" },
	{ 0x00000002, "WRITE_DATA" },
	{ 0x00000004, "APPEND_DATA" },
	{ 0x00000008, "READ_EA" },
	{ 0x00000010, "WRITE_EA" },
	{ 0x00000020, "EXECUTE" },
	{ 0x00000040, "DELETE_CHILD" },
	{ 0x00000080, "READ_ATTRIBUTES" },
	{ 0x00000100, "WRITE_ATTRIBUTES" },
	{ 0x00010000, "DELETE" },
	{ 0x00020000, "READ_CONTROL" },
	{ 0x00040000, "WRITE_DAC" },
	{ 0x00080000, "WRITE_OWNER" },
	{ 0x00100000, "SYNCHRONIZER" },
	{ 0x01000000, "ACCESS_SYSTEM_SECURITY" },
	{ 0x02000000, "MAXIMUM_ALLOWED" },
	{ 0x10000000, "GENERIC_ALL" },
	{ 0x20000000, "GENERIC_EXECUTE" },
	{ 0x40000000, "GENERIC_WRITE" },
	{ 0x80000000, "GENERIC_READ" },
	{ 0, NULL }
};

static void
print_bits(uint32_t mask, struct bit_string *bs)
{
	int first = 1;

	if (!verbose)
		return;

	while (bs->string) {
		if (mask & bs->bit) {
			printf("%s%s", first?"":",", bs->string);
			first = 0;
		}
		bs++;
	}
	if (!first)
		printf(" ");
}

static void
print_guid(uint8_t *sd)
{
	uint32_t u32;
	uint16_t u16;
	int i;

	memcpy(&u32, &sd[0], 4);
	printf("%08x-", le32toh(u32));

	memcpy(&u16, &sd[4], 2);
	printf("%04x-", le16toh(u16));

	memcpy(&u16, &sd[6], 2);
	printf("%04x-", le16toh(u16));

	printf("%02x%02x-", sd[8], sd[9]);
	for (i = 0; i < 6; i++)
		printf("%02x", sd[10 + i]);
}

static void
print_objidbuf(uint8_t *sd)
{
	printf("Object-ID: ");
	print_guid(&sd[0]);
	printf("\n");

	printf("Birth-Volume-ID: ");
	print_guid(&sd[16]);
	printf("\n");

	printf("Birth-Object-ID: ");
	print_guid(&sd[32]);
	printf("\n");

	printf("Domain-ID: ");
	print_guid(&sd[48]);
	printf("\n");
}

static void
fsctlgetobjid(int f)
{
	struct smb_query_info *qi;
	struct stat st;

	fstat(f, &st);

	qi = malloc(sizeof(struct smb_query_info) + 64);
	memset(qi, 0, sizeof(qi) + 64);
	qi->info_type = 0x9009c;
	qi->file_info_class = 0;
	qi->additional_information = 0;
	qi->input_buffer_length = 64;
	qi->flags = PASSTHRU_FSCTL;

	if (ioctl(f, CIFS_QUERY_INFO, qi) < 0) {
		fprintf(stderr, "ioctl failed with %s\n", strerror(errno));
		exit(1);
	}
	print_objidbuf((uint8_t *)(&qi[1]));

	free(qi);
}

static void
print_fileaccessinfo(uint8_t *sd, int type)
{
	uint32_t access_flags;

	memcpy(&access_flags, &sd[0], 4);
	access_flags = le32toh(access_flags);

	if (type == S_IFDIR) {
		printf("Directory access flags 0x%08x: ", access_flags);
		print_bits(access_flags, directory_access_mask);
	} else {
		printf("File/Printer access flags 0x%08x: ", access_flags);
		print_bits(access_flags, file_access_mask);
	}
	printf("\n");
}

static void
fileaccessinfo(int f)
{
	struct smb_query_info *qi;
	struct stat st;

	fstat(f, &st);

	qi = malloc(sizeof(struct smb_query_info) + 4);
	memset(qi, 0, sizeof(qi) + 4);
	qi->info_type = 0x01;
	qi->file_info_class = 8;
	qi->additional_information = 0;
	qi->input_buffer_length = 4;

	if (ioctl(f, CIFS_QUERY_INFO, qi) < 0) {
		fprintf(stderr, "ioctl failed with %s\n", strerror(errno));
		exit(1);
	}

	print_fileaccessinfo((uint8_t *)(&qi[1]), st.st_mode & S_IFMT);
	free(qi);
}

static void
print_filealigninfo(uint8_t *sd)
{
	uint32_t mask;

	memcpy(&mask, &sd[0], 4);
	mask = le32toh(mask);

	printf("File alignment: ");
	if (mask == 0)
		printf("BYTE_ALIGNMENT");
	else if (mask == 1)
		printf("WORD_ALIGNMENT");
	else if (mask == 3)
		printf("LONG_ALIGNMENT");
	else if (mask == 7)
		printf("QUAD_ALIGNMENT");
	else if (mask == 15)
		printf("OCTA_ALIGNMENT");
	else if (mask == 31)
		printf("32_bit_ALIGNMENT");
	else if (mask == 63)
		printf("64_bit_ALIGNMENT");
	else if (mask == 127)
		printf("128_bit_ALIGNMENT");
	else if (mask == 255)
		printf("254_bit_ALIGNMENT");
	else if (mask == 511)
		printf("512_bit_ALIGNMENT");

	printf("\n");
}

static void
filealigninfo(int f)
{
	struct smb_query_info *qi;

	qi = malloc(sizeof(struct smb_query_info) + 4);
	memset(qi, 0, sizeof(qi) + 4);
	qi->info_type = 0x01;
	qi->file_info_class = 17;
	qi->additional_information = 0;
	qi->input_buffer_length = 4;

	if (ioctl(f, CIFS_QUERY_INFO, qi) < 0) {
		fprintf(stderr, "ioctl failed with %s\n", strerror(errno));
		exit(1);
	}

	print_filealigninfo((uint8_t *)(&qi[1]));
	free(qi);
}

struct bit_string file_attributes_mask[] = {
	{ 0x00000001, "READ_ONLY" },
	{ 0x00000002, "HIDDEN" },
	{ 0x00000004, "SYSTEM" },
	{ 0x00000010, "DIRECTORY" },
	{ 0x00000020, "ARCHIVE" },
	{ 0x00000080, "NORMAL" },
	{ 0x00000100, "TEMPORARY" },
	{ 0x00000200, "SPARSE_FILE" },
	{ 0x00000400, "REPARSE_POINT" },
	{ 0x00000800, "COMPRESSED" },
	{ 0x00001000, "OFFLINE" },
	{ 0x00002000, "NOT_CONTENT_INDEXED" },
	{ 0x00004000, "ENCRYPTED" },
	{ 0x00008000, "INTEGRITY_STREAM" },
	{ 0x00020000, "NO_SCRUB_DATA" },
	{ 0, NULL }
};

static void
print_filebasicinfo(uint8_t *sd)
{
	struct timeval tv;
	uint64_t u64;
	uint32_t u32;

	memcpy(&u64, &sd[0], 8);
	win_to_timeval(le64toh(u64), &tv);
	printf("Creation Time %s", ctime(&tv.tv_sec));

	memcpy(&u64, &sd[8], 8);
	win_to_timeval(le64toh(u64), &tv);
	printf("Last Access Time %s", ctime(&tv.tv_sec));

	memcpy(&u64, &sd[16], 8);
	win_to_timeval(le64toh(u64), &tv);
	printf("Last Write Time %s", ctime(&tv.tv_sec));

	memcpy(&u64, &sd[24], 8);
	win_to_timeval(le64toh(u64), &tv);
	printf("Last Change Time %s", ctime(&tv.tv_sec));

	memcpy(&u32, &sd[32], 4);
	u32 = le32toh(u32);
	printf("File Attributes 0x%08x: ", u32);
	print_bits(u32, file_attributes_mask);
	printf("\n");
}

static void
filebasicinfo(int f)
{
	struct smb_query_info *qi;

	qi = malloc(sizeof(struct smb_query_info) + 40);
	memset(qi, 0, sizeof(qi) + 40);
	qi->info_type = 0x01;
	qi->file_info_class = 4;
	qi->additional_information = 0;
	qi->input_buffer_length = 40;

	if (ioctl(f, CIFS_QUERY_INFO, qi) < 0) {
		fprintf(stderr, "ioctl failed with %s\n", strerror(errno));
		exit(1);
	}

	print_filebasicinfo((uint8_t *)(&qi[1]));
	free(qi);
}

static void
print_filestandardinfo(uint8_t *sd)
{
	uint64_t u64;
	uint32_t u32;

	memcpy(&u64, &sd[0], 8);
	printf("Allocation Size %" PRIu64 "\n", le64toh(u64));

	memcpy(&u64, &sd[8], 8);
	printf("End Of File %" PRIu64 "\n", le64toh(u64));

	memcpy(&u32, &sd[16], 4);
	printf("Number Of Links %" PRIu32 "\n", le32toh(u32));

	printf("Delete Pending %d\n", sd[20]);
	printf("Delete Directory %d\n", sd[21]);
}

static void
filestandardinfo(int f)
{
	struct smb_query_info *qi;

	qi = malloc(sizeof(struct smb_query_info) + 24);
	memset(qi, 0, sizeof(qi) + 24);
	qi->info_type = 0x01;
	qi->file_info_class = 5;
	qi->additional_information = 0;
	qi->input_buffer_length = 24;

	if (ioctl(f, CIFS_QUERY_INFO, qi) < 0) {
		fprintf(stderr, "ioctl failed with %s\n", strerror(errno));
		exit(1);
	}

	print_filestandardinfo((uint8_t *)(&qi[1]));
	free(qi);
}

static void
print_fileinternalinfo(uint8_t *sd)
{
	uint64_t u64;

	memcpy(&u64, &sd[0], 8);
	printf("Index Number %" PRIu64 "\n", le64toh(u64));
}

static void
fileinternalinfo(int f)
{
	struct smb_query_info *qi;

	qi = malloc(sizeof(struct smb_query_info) + 8);
	memset(qi, 0, sizeof(qi) + 8);
	qi->info_type = 0x01;
	qi->file_info_class = 6;
	qi->additional_information = 0;
	qi->input_buffer_length = 8;

	if (ioctl(f, CIFS_QUERY_INFO, qi) < 0) {
		fprintf(stderr, "ioctl failed with %s\n", strerror(errno));
		exit(1);
	}

	print_fileinternalinfo((uint8_t *)(&qi[1]));
	free(qi);
}

struct bit_string file_mode_mask[] = {
	{ 0x00000002, "WRITE_THROUGH" },
	{ 0x00000004, "SEQUENTIAL_ONLY" },
	{ 0x00000008, "NO_INTERMEDIATE_BUFFERING" },
	{ 0x00000010, "SYNCHRONOUS_IO_ALERT" },
	{ 0x00000020, "SYNCHRONOUS_IO_NONALERT" },
	{ 0x00001000, "DELETE_ON_CLOSE" },
	{ 0, NULL }
};

static void
print_filemodeinfo(uint8_t *sd)
{
	uint32_t u32;

	memcpy(&u32, &sd[32], 4);
	u32 = le32toh(u32);
	printf("Mode 0x%08x: ", u32);
	print_bits(u32, file_mode_mask);
	printf("\n");
}

static void
filemodeinfo(int f)
{
	struct smb_query_info *qi;

	qi = malloc(sizeof(struct smb_query_info) + 4);
	memset(qi, 0, sizeof(qi) + 4);
	qi->info_type = 0x01;
	qi->file_info_class = 16;
	qi->additional_information = 0;
	qi->input_buffer_length = 4;

	if (ioctl(f, CIFS_QUERY_INFO, qi) < 0) {
		fprintf(stderr, "ioctl failed with %s\n", strerror(errno));
		exit(1);
	}

	print_filemodeinfo((uint8_t *)(&qi[1]));
	free(qi);
}

static void
print_filepositioninfo(uint8_t *sd)
{
	uint64_t u64;

	memcpy(&u64, &sd[0], 8);
	printf("Current Byte Offset %" PRIu64 "\n", le64toh(u64));
}

static void
filepositioninfo(int f)
{
	struct smb_query_info *qi;

	qi = malloc(sizeof(struct smb_query_info) + 8);
	memset(qi, 0, sizeof(qi) + 8);
	qi->info_type = 0x01;
	qi->file_info_class = 14;
	qi->additional_information = 0;
	qi->input_buffer_length = 8;

	if (ioctl(f, CIFS_QUERY_INFO, qi) < 0) {
		fprintf(stderr, "ioctl failed with %s\n", strerror(errno));
		exit(1);
	}

	print_filepositioninfo((uint8_t *)(&qi[1]));
	free(qi);
}

static void
print_fileeainfo(uint8_t *sd)
{
	uint32_t u32;

	memcpy(&u32, &sd[0], 4);
	printf("Ea Size %" PRIu32 "\n", le32toh(u32));
}

static void
fileeainfo(int f)
{
	struct smb_query_info *qi;

	qi = malloc(sizeof(struct smb_query_info) + 4);
	memset(qi, 0, sizeof(qi) + 4);
	qi->info_type = 0x01;
	qi->file_info_class = 7;
	qi->additional_information = 0;
	qi->input_buffer_length = 4;

	if (ioctl(f, CIFS_QUERY_INFO, qi) < 0) {
		fprintf(stderr, "ioctl failed with %s\n", strerror(errno));
		exit(1);
	}

	print_fileeainfo((uint8_t *)(&qi[1]));
	free(qi);
}

static void
print_filefullsizeinfo(uint8_t *sd)
{
	uint32_t u32;
	uint64_t u64;

	memcpy(&u64, &sd[0], 8);
	printf("Total Allocation Units: %" PRIu64 "\n", le64toh(u64));

	memcpy(&u64, &sd[8], 8);
	printf("Caller Available Allocation Units: %" PRIu64 "\n",
	       le64toh(u64));

	memcpy(&u64, &sd[16], 8);
	printf("Actual Available Allocation Units: %" PRIu64 "\n",
	       le64toh(u64));

	memcpy(&u32, &sd[24], 4);
	printf("Sectors Per Allocation Unit: %" PRIu32 "\n", le32toh(u32));

	memcpy(&u32, &sd[28], 4);
	printf("Bytes Per Sector: %" PRIu32 "\n", le32toh(u32));
}

static void
filefsfullsizeinfo(int f)
{
	struct smb_query_info *qi;

	qi = malloc(sizeof(struct smb_query_info) + 32);
	memset(qi, 0, sizeof(qi) + 32);
	qi->info_type = 0x02;
	qi->file_info_class = 7;
	qi->additional_information = 0;
	qi->input_buffer_length = 32;

	if (ioctl(f, CIFS_QUERY_INFO, qi) < 0) {
		fprintf(stderr, "ioctl failed with %s\n", strerror(errno));
		exit(1);
	}

	print_filefullsizeinfo((uint8_t *)(&qi[1]));
	free(qi);
}

static void
fileallinfo(int f)
{
	struct smb_query_info *qi;
	struct stat st;

	fstat(f, &st);

	qi = malloc(sizeof(struct smb_query_info) + INPUT_BUFFER_LENGTH);
	memset(qi, 0, sizeof(qi) + INPUT_BUFFER_LENGTH);
	qi->info_type = 0x01;
	qi->file_info_class = 18;
	qi->additional_information = 0;
	qi->input_buffer_length = INPUT_BUFFER_LENGTH;

	if (ioctl(f, CIFS_QUERY_INFO, qi) < 0) {
		fprintf(stderr, "ioctl failed with %s\n", strerror(errno));
		exit(1);
	}

	print_filebasicinfo((uint8_t *)(&qi[1]));
	print_filestandardinfo((uint8_t *)(&qi[1]) + 40);
	print_fileinternalinfo((uint8_t *)(&qi[1]) + 64);
	print_fileeainfo((uint8_t *)(&qi[1]) + 72);
	print_fileaccessinfo((uint8_t *)(&qi[1]) + 76, st.st_mode & S_IFMT);
	print_filepositioninfo((uint8_t *)(&qi[1]) + 80);
	print_filemodeinfo((uint8_t *)(&qi[1]) + 88);
	print_filealigninfo((uint8_t *)(&qi[1]) + 92);
	// SMB2 servers like Win16 does not seem to return name info
	free(qi);
}

static void
print_sid(unsigned char *sd)
{
	int i;
	uint32_t subauth;
	uint64_t idauth;

	if (sd[0] != 1) {
		fprintf(stderr, "Unknown SID revision\n");
		return;
	}

	idauth = 0;
	for (i = 0; i < 6; i++)
		idauth = (idauth << 8) | sd[2 + i];

	printf("S-1-%" PRIu64, idauth);
	for (i = 0; i < sd[1]; i++) {
		memcpy(&subauth, &sd[8 + 4 * i], 4);
		subauth = le32toh(subauth);
		printf("-%u", subauth);
	}
}

static void
print_ace_type(uint8_t t)
{
	switch(t) {
	case 0x00: printf("ALLOWED"); break;
	case 0x01: printf("DENIED"); break;
	case 0x02: printf("AUDIT"); break;
	case 0x03: printf("ALARM"); break;
	case 0x04: printf("ALLOWED_COMPOUND"); break;
	case 0x05: printf("ALLOWED_OBJECT"); break;
	case 0x06: printf("DENIED_OBJECT"); break;
	case 0x07: printf("AUDIT_OBJECT"); break;
	case 0x08: printf("ALARM_OBJECT"); break;
	case 0x09: printf("ALLOWED_CALLBACK"); break;
	case 0x0a: printf("DENIED_CALLBACK"); break;
	case 0x0b: printf("ALLOWED_CALLBACK_OBJECT"); break;
	case 0x0c: printf("DENIED_CALLBACK_OBJECT"); break;
	case 0x0d: printf("AUDIT_CALLBACK"); break;
	case 0x0e: printf("ALARM_CALLBACK"); break;
	case 0x0f: printf("AUDIT_CALLBACK_OBJECT"); break;
	case 0x10: printf("ALARM_CALLBACK_OBJECT"); break;
	case 0x11: printf("MANDATORY_LABEL"); break;
	case 0x12: printf("RESOURCE_ATTRIBUTE"); break;
	case 0x13: printf("SCOPED_POLICY_ID"); break;
	default: printf("<UNKNOWN>");
	}
	printf(" ");
}

struct bit_string ace_flags_mask[] = {
	{ 0x80, "FAILED_ACCESS" },
	{ 0x40, "SUCCESSFUL_ACCESS" },
	{ 0x10, "INHERITED" },
	{ 0x08, "INHERIT_ONLY" },
	{ 0x04, "NO_PROPAGATE_INHERIT" },
	{ 0x02, "CONTAINER_INHERIT" },
	{ 0x01, "OBJECT_INHERIT" },
	{ 0, NULL }
};

static void
print_mask_sid_ace(unsigned char *sd, int type)
{
	uint32_t u32;

	memcpy(&u32, &sd[0], 4);
	printf("Mask:0x%08x ", le32toh(u32));
	if (type == S_IFDIR)
		print_bits(le32toh(u32), directory_access_mask);
	else
		print_bits(le32toh(u32), file_access_mask);
	printf("SID:");
	print_sid(&sd[4]);
	printf("\n");
}

static int
print_ace(unsigned char *sd, int type)
{
	uint16_t size;
	int i;

	printf("Type:0x%02x ", sd[0]);
	if (verbose) {
		print_ace_type(sd[0]);
	}

	printf("Flags:0x%02x ", sd[1]);
	print_bits(sd[1], ace_flags_mask);

	memcpy(&size, &sd[2], 2);
	size = le16toh(size);

	switch (sd[0]) {
	case 0x00:
	case 0x01:
	case 0x02:
		print_mask_sid_ace(&sd[4], type);
		break;
	default:
		for (i = 0; i < size; i++)
			printf("%02x", sd[4 + i]);
	}

	printf("\n");
	return size;
}

static void
print_acl(unsigned char *sd, int type)
{
	int i, off;
	uint16_t count;

	if ((sd[0] != 2) && (sd[0] != 4)) {
		fprintf(stderr, "Unknown ACL revision\n");
		return;
	}

	memcpy(&count, &sd[4], 2);
	count = le16toh(count);
	off = 8;
	for (i = 0; i < count; i++)
		off += print_ace(&sd[off], type);
}

struct bit_string control_bits_mask[] = {
	{ 0x8000, "SR" },
	{ 0x4000, "RM" },
	{ 0x2000, "PS" },
	{ 0x1000, "PD" },
	{ 0x0800, "SI" },
	{ 0x0400, "DI" },
	{ 0x0200, "SC" },
	{ 0x0100, "DC" },
	{ 0x0080, "DT" },
	{ 0x0040, "SS" },
	{ 0x0020, "SD" },
	{ 0x0010, "SP" },
	{ 0x0008, "DD" },
	{ 0x0004, "DP" },
	{ 0x0002, "GD" },
	{ 0x0001, "OD" },
	{ 0, NULL }
};

static void
print_control(uint16_t c)
{
	printf("Control: 0x%04x ", c);
	print_bits(c, control_bits_mask);
	printf("\n");
}

static void
print_sd(uint8_t *sd, int type)
{
	int offset_owner, offset_group, offset_dacl;
	uint16_t u16;

	printf("Revision:%d\n", sd[0]);
	if (sd[0] != 1) {
		fprintf(stderr, "Unknown SD revision\n");
		exit(1);
	}

	memcpy(&u16, &sd[2], 2);
	print_control(le16toh(u16));

	memcpy(&offset_owner, &sd[4], 4);
	offset_owner = le32toh(offset_owner);
	memcpy(&offset_group, &sd[8], 4);
	offset_group = le32toh(offset_group);
	memcpy(&offset_dacl, &sd[16], 4);
	offset_dacl = le32toh(offset_dacl);

	if (offset_owner) {
		printf("Owner: ");
		print_sid(&sd[offset_owner]);
		printf("\n");
	}
	if (offset_group) {
		printf("Group: ");
		print_sid(&sd[offset_group]);
		printf("\n");
	}
	if (offset_dacl) {
		printf("DACL:\n");
		print_acl(&sd[offset_dacl], type);
	}
}

static void
secdesc(int f)
{
	struct smb_query_info *qi;
	struct stat st;

	fstat(f, &st);

	qi = malloc(sizeof(struct smb_query_info) + INPUT_BUFFER_LENGTH);
	memset(qi, 0, sizeof(qi) + INPUT_BUFFER_LENGTH);
	qi->info_type = 0x03;
	qi->file_info_class = 0;
	qi->additional_information = 0x00000007; /* Owner, Group, Dacl */
	qi->input_buffer_length = INPUT_BUFFER_LENGTH;

	if (ioctl(f, CIFS_QUERY_INFO, qi) < 0) {
		fprintf(stderr, "ioctl failed with %s\n", strerror(errno));
		exit(1);
	}

	print_sd((uint8_t *)(&qi[1]), st.st_mode & S_IFMT);
	free(qi);
}

static void
print_quota(unsigned char *sd)
{
	uint32_t u32, neo;
	uint64_t u64;
	struct timeval tv;
	int i, off = 0;

one_more:
	memcpy(&u32, &sd[off], 4);
	neo = le32toh(u32);

	memcpy(&u32, &sd[off + 4], 4);
	u32 = le32toh(u32);
	printf("SID Length %d\n", u32);

	memcpy(&u64, &sd[off + 8], 8);
	win_to_timeval(le64toh(u64), &tv);
	printf("Change Time %s", ctime(&tv.tv_sec));

	memcpy(&u64, &sd[off + 16], 8);
	u64 = le32toh(u64);
	printf("Quota Used %" PRIu64 "\n", u64);

	memcpy(&u64, &sd[off + 24], 8);
	u64 = le64toh(u64);
	if (u64 == 0xffffffffffffffff)
		printf("Quota Threshold NO THRESHOLD\n");
	else
		printf("Quota Threshold %" PRIu64 "\n", u64);

	memcpy(&u64, &sd[off + 32], 8);
	u64 = le64toh(u64);
	if (u64 == 0xffffffffffffffff)
		printf("Quota Limit NO LIMIT\n");
	else
		printf("Quota Limit %" PRIu64 "\n", u64);

	printf("SID: S-1");
	u64 = 0;
	for (i = 0; i < 6; i++)
		u64 = (u64 << 8) | sd[off + 42 + i];
	printf("-%" PRIu64, u64);

	for (i = 0; i < sd[off + 41]; i++) {
		memcpy(&u32, &sd[off + 48 + 4 * i], 4);
		u32 = le32toh(u32);
		printf("-%u", u32);
	}
	printf("\n\n");
	off += neo;

	if (neo != 0)
		goto one_more;
}

static void
quota(int f)
{
	struct smb_query_info *qi;
	char *buf;
	int i;

	qi = malloc(sizeof(struct smb_query_info) + INPUT_BUFFER_LENGTH);
	memset(qi, 0, sizeof(struct smb_query_info) + INPUT_BUFFER_LENGTH);
	qi->info_type = 0x04;
	qi->file_info_class = 0;
	qi->additional_information = 0; /* Owner, Group, Dacl */
	qi->input_buffer_length = INPUT_BUFFER_LENGTH;

	buf = (char *)&qi[1];
	buf[0] = 0; /* return single */
	buf[1] = 1; /* restart scan */

	/* sid list length */
	i = 0;
	memcpy(&buf[4], &i, 4);

	qi->output_buffer_length = 16;

	if (ioctl(f, CIFS_QUERY_INFO, qi) < 0) {
		fprintf(stderr, "ioctl failed with %s\n", strerror(errno));
		exit(1);
	}

	print_quota((unsigned char *)(&qi[1]));
	free(qi);
}


struct smb_snapshot_array {
	int32_t	number_of_snapshots;
	int32_t	number_of_snapshots_returned;
	int32_t	snapshot_array_size;
	char snapshot_data[0];
};


#define GMT_NAME_LEN 24 /* length of a @GMT- name */
#define GMT_FORMAT "@GMT-%Y.%m.%d-%H.%M.%S"

#define NTFS_TIME_OFFSET ((unsigned long long)(369*365 + 89) * 24 * 3600 * 10000000)

static void print_snapshots(struct smb_snapshot_array *psnap)
{
	int current_snapshot_entry = 0;
	char gmt_token[GMT_NAME_LEN + 1] = {0};
	int i;
	int j = 0;
	struct tm tm;
	unsigned long long dce_time;

	printf("Number of snapshots: %d Number of snapshots returned: %d\n",
		psnap->number_of_snapshots,
		psnap->number_of_snapshots_returned);
	printf("Snapshot list in GMT (Coordinated UTC Time) and SMB format (100 nanosecond units needed for snapshot mounts):");
	for (i = 0; i < psnap->snapshot_array_size; i++) {
		if (psnap->snapshot_data[i] == '@') {
			j = 0;
			current_snapshot_entry++;
			printf("\n%d) GMT:", current_snapshot_entry);
		}
		if (psnap->snapshot_data[i] != 0) {
			gmt_token[j] = psnap->snapshot_data[i];
			j++;
		}
		if (j == GMT_NAME_LEN) {
			printf("%s", gmt_token);
			j = 0;
			strptime(gmt_token, GMT_FORMAT, &tm);
			dce_time = timegm(&tm) * 10000000 + NTFS_TIME_OFFSET;
			printf("\n   SMB3:%llu", dce_time);
		}
	}
	printf("\n");
}

#define CIFS_ENUMERATE_SNAPSHOTS _IOR(CIFS_IOCTL_MAGIC, 6, struct smb_snapshot_array)

#define MIN_SNAPSHOT_ARRAY_SIZE 16 /* See MS-SMB2 section 3.3.5.15.1 */

static void
list_snapshots(int f)
{

	struct smb_snapshot_array snap_inf;
	struct smb_snapshot_array *buf;

	/*
	 * When first field in structure we pass in here is zero, cifs.ko can
	 * recognize that this is the first query and that it must set the SMB3
	 * FSCTL response buffer size (in the request) to exactly 16 bytes
	 * (which is required by some servers to process the initial query)
	 */
	snap_inf.number_of_snapshots = 0;
	snap_inf.number_of_snapshots_returned = 0;
	snap_inf.snapshot_array_size = sizeof(struct smb_snapshot_array);

	/* Query the number of snapshots so we know how much to allocate */
	if (ioctl(f, CIFS_ENUMERATE_SNAPSHOTS, &snap_inf) < 0) {
		fprintf(stderr, "Querying snapshots failed with %s\n", strerror(errno));
		exit(1);
	}

	if (snap_inf.number_of_snapshots == 0)
		return;

	/* Now that we know the size, query the list from the server */

	buf = malloc(snap_inf.snapshot_array_size + MIN_SNAPSHOT_ARRAY_SIZE);

	if (buf == NULL) {
		printf("Failed, out of memory.\n");
		exit(1);
	}
	/*
	 * first parm is non-zero which allows cifs.ko to recognize that this is
	 * the second query (it has to set response buf size larger)
	 */
	buf->number_of_snapshots = snap_inf.number_of_snapshots;

	buf->snapshot_array_size = snap_inf.snapshot_array_size;

	if (ioctl(f, CIFS_ENUMERATE_SNAPSHOTS, buf) < 0) {
		fprintf(stderr, "Querying snapshots failed with %s\n", strerror(errno));
		exit(1);
	}

	print_snapshots(buf);
	free(buf);
}

int main(int argc, char *argv[])
{
	int c;
	int f;

	while ((c = getopt_long(argc, argv, "vV", NULL, NULL)) != -1) {
		switch (c) {
		case 'v':
			printf("smbinfo version %s\n", VERSION);
			return 0;
		case 'V':
			verbose = 1;
			break;
		default:
			usage(argv[0]);
		}
	}

	if (optind >= argc - 1)
		usage(argv[0]);

	if ((f = open(argv[optind + 1], O_RDONLY)) < 0) {
		fprintf(stderr, "Failed to open %s\n", argv[optind + 1]);
		exit(1);
	}

	if (!strcmp(argv[optind], "fileaccessinfo"))
		fileaccessinfo(f);
	else if (!strcmp(argv[optind], "filealigninfo"))
		filealigninfo(f);
	else if (!strcmp(argv[optind], "fileallinfo"))
		fileallinfo(f);
	else if (!strcmp(argv[optind], "filebasicinfo"))
		filebasicinfo(f);
	else if (!strcmp(argv[optind], "fileeainfo"))
		fileeainfo(f);
	else if (!strcmp(argv[optind], "filefsfullsizeinfo"))
		filefsfullsizeinfo(f);
	else if (!strcmp(argv[optind], "fileinternalinfo"))
		fileinternalinfo(f);
	else if (!strcmp(argv[optind], "filemodeinfo"))
		filemodeinfo(f);
	else if (!strcmp(argv[optind], "filepositioninfo"))
		filepositioninfo(f);
	else if (!strcmp(argv[optind], "filestandardinfo"))
		filestandardinfo(f);
	else if (!strcmp(argv[optind], "fsctl-getobjid"))
		fsctlgetobjid(f);
	else if (!strcmp(argv[optind], "list-snapshots"))
		list_snapshots(f);
	else if (!strcmp(argv[optind], "quota"))
		quota(f);
	else if (!strcmp(argv[optind], "secdesc"))
		secdesc(f);
	else {
		fprintf(stderr, "Unknown command %s\n", argv[optind]);
		exit(1);
	}

	close(f);
	return 0;
}
