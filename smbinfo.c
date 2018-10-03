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
                "  secdesc:\n"
                "      Prints the security descriptor for a cifs file.\n"
                "  quota:\n"
                "      Prints the quota for a cifs file.\n",
                name);
        exit(1);
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

void secdesc(int f) {
        struct smb_query_info *qi;

        qi = malloc(sizeof(struct smb_query_info) + INPUT_BUFFER_LENGTH);
        qi->info_type = 0x03;
        qi->file_info_class = 0;
        qi->additional_information = 0x00000007; /* Owner, Group, Dacl */
        qi->input_buffer_length = INPUT_BUFFER_LENGTH;

        if (ioctl(f, CIFS_QUERY_INFO, qi) < 0) {
                fprintf(stderr, "ioctl failed with %s\n", strerror(errno));
                exit(1);
        }

        print_sd((uint8_t *)(&qi[1]));
}

void
win_to_timeval(uint64_t smb2_time, struct timeval *tv)
{
  tv->tv_usec = (smb2_time / 10) % 1000000;
  tv->tv_sec  = (smb2_time - 116444736000000000) / 10000000;
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

void quota(int f) {
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


        if (!strcmp(argv[1], "secdesc")) {
                secdesc(f);
        } else if (!strcmp(argv[1], "quota")) {
                quota(f);
        } else {
                fprintf(stderr, "Unknown command %s\n", argv[optind]);
                exit(1);
        }


        close(f);
        return 0;
}
