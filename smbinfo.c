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

static void
usage(char *name)
{
        fprintf(stderr, "Usage: %s <command> <file>\n"
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
                "  fileinternalinfo:\n"
                "      Prints FileInternalInfo for a cifs file.\n"
                "  filemodeinfo:\n"
                "      Prints FileModeInfo for a cifs file.\n"
                "  filepositioninfo:\n"
                "      Prints FilePositionInfo for a cifs file.\n"
                "  filestandardinfo:\n"
                "      Prints FileStandardInfo for a cifs file.\n"
                "  secdesc:\n"
                "      Prints the security descriptor for a cifs file.\n"
                "  quota:\n"
                "      Prints the quota for a cifs file.\n",
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
        while (bs->string) {
                if (mask & bs->bit)
                    printf("%s ", bs->string);
                bs++;
        }
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
                printf("-%d", subauth);
        }
}

static void
print_acl(unsigned char *sd)
{
        int i, j, off;
        uint16_t count, size;

        if (sd[0] != 2) {
                fprintf(stderr, "Unknown ACL revision\n");
                return;
        }

        memcpy(&count, &sd[4], 2);
        count = le16toh(count);
        off = 8;
        for (i = 0; i < count; i++) {
                printf("Type:%02x Flags:%02x ", sd[off], sd[off + 1]);
                memcpy(&size, &sd[off + 2], 2);
                size = le16toh(size);

                for (j = 0; j < size; j++)
                        printf("%02x", sd[off + 4 + j]);

                off += size;
                printf("\n");
        }
}

static void
print_sd(uint8_t *sd)
{
        int offset_owner, offset_group, offset_dacl;

        printf("Revision:%d\n", sd[0]);
        if (sd[0] != 1) {
                fprintf(stderr, "Unknown SD revision\n");
                exit(1);
        }

        printf("Control: %02x%02x\n", sd[2], sd[3]);

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
                print_acl(&sd[offset_dacl]);
        }
}

static void
secdesc(int f)
{
        struct smb_query_info *qi;

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

        print_sd((uint8_t *)(&qi[1]));
        free(qi);
}

static void
print_quota(unsigned char *sd)
{
        uint32_t u32, neo;
        uint64_t u64;
        struct timeval tv;
        struct tm;
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
        if (u64 == 0xffffffffffffffff) {
                printf("Quota Threshold NO THRESHOLD\n");
        } else {
                printf("Quota Threshold %" PRIu64 "\n", u64);
        }

        memcpy(&u64, &sd[off + 32], 8);
        u64 = le64toh(u64);
        if (u64 == 0xffffffffffffffff) {
                printf("Quota Limit NO LIMIT\n");
        } else {
                printf("Quota Limit %" PRIu64 "\n", u64);
        }

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

        if (neo != 0) {
                goto one_more;
        }
}

static void
quota(int f)
{
        struct smb_query_info *qi;
        char *buf;
        int i;

        qi = malloc(sizeof(struct smb_query_info) + 16384);
        memset(qi, 0, sizeof(struct smb_query_info) + 16384);
        qi->info_type = 0x04;
        qi->file_info_class = 0;
        qi->additional_information = 0; /* Owner, Group, Dacl */
        qi->input_buffer_length = 16384;

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

int main(int argc, char *argv[])
{
        int c;
        int f;

        while ((c = getopt_long(argc, argv, "v", NULL, NULL)) != -1) {
                switch (c) {
                case 'v':
                        printf("smbinfo version %s\n", VERSION);
                        return 0;
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


        if (!strcmp(argv[1], "fileaccessinfo"))
                fileaccessinfo(f);
        else if (!strcmp(argv[1], "filealigninfo"))
                filealigninfo(f);
        else if (!strcmp(argv[1], "fileallinfo"))
                fileallinfo(f);
        else if (!strcmp(argv[1], "filebasicinfo"))
                filebasicinfo(f);
        else if (!strcmp(argv[1], "fileeainfo"))
                fileeainfo(f);
        else if (!strcmp(argv[1], "fileinternalinfo"))
                fileinternalinfo(f);
        else if (!strcmp(argv[1], "filemodeinfo"))
                filemodeinfo(f);
        else if (!strcmp(argv[1], "filepositioninfo"))
                filepositioninfo(f);
        else if (!strcmp(argv[1], "filestandardinfo"))
                filestandardinfo(f);
        else if (!strcmp(argv[1], "secdesc"))
                secdesc(f);
        else if (!strcmp(argv[1], "quota"))
                quota(f);
        else {
                fprintf(stderr, "Unknown command %s\n", argv[optind]);
                exit(1);
        }


        close(f);
        return 0;
}
