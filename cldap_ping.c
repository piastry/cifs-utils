/*
 * CLDAP Ping to find closest ClientSiteName
 *
 * Copyright (C) 2024 David Voit (david.voit@gmail.com)
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

#include <talloc.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <resolv.h>
#include <stdbool.h>
#include "data_blob.h"
#include "asn1.h"
#include "cldap_ping.h"

#define LDAP_DNS_DOMAIN "DnsDomain"
#define LDAP_DNS_DOMAIN_LEN strlen(LDAP_DNS_DOMAIN)
#define LDAP_NT_VERSION "NtVer"
#define LDAP_NT_VERSION_LEN strlen(LDAP_NT_VERSION)
#define LDAP_ATTRIBUTE_NETLOGON "NetLogon"
#define LDAP_ATTRIBUTE_NETLOGON_LEN strlen(LDAP_ATTRIBUTE_NETLOGON)


// Parse a ASN.1 BER tag size-field, returns start of payload of tag
char *parse_ber_size(char *buf, size_t *tag_size) {
	size_t size = *buf & 0xff;
	char *ret = (buf + 1);
	if (size >= 0x81) {
		switch (size) {
			case 0x81:
				size = *ret & 0xff;
				ret += 1;
				break;
			case 0x82:
				size = (*ret << 8) | (*(ret + 1) & 0xff);
				ret += 2;
				break;
			case 0x83:
				size = (*ret << 16) | (*(ret + 1) << 8) | (*(ret + 2) & 0xff);
				ret += 3;
				break;
			case 0x84:
				size = (*ret << 24) | (*(ret + 1) << 16) | (*(ret + 2) << 8) | (*(ret + 3) & 0xff);
				ret += 4;
				break;
			default:
				return NULL;
		}
	}

	*tag_size = size;
	return ret;
}

// simple wrapper over dn_expand which also calculates the new offset for the next compressed dn
int read_dns_string(char *buf, size_t buf_size, char *dest, size_t dest_size, size_t *offset) {
	int compressed_length = dn_expand((u_char *)buf, (u_char *)buf+buf_size, (u_char *)buf + *offset, dest, (int)dest_size);
	if (compressed_length < 0) {
		return -1;
	}

	*offset = *offset+compressed_length;

	return 0;
}

// LDAP request for: (&(DnsDomain=DOMAIN_HERE)(NtVer=\\06\\00\\00\\00))
ASN1_DATA *generate_cldap_query(char *domain) {
	ASN1_DATA *data;
	TALLOC_CTX *mem_ctx = talloc_init("cldap");

	data = asn1_init(mem_ctx);
	asn1_push_tag(data, ASN1_SEQUENCE(0));

	// Message id
	asn1_push_tag(data, ASN1_INTEGER);
	asn1_write_uint8(data, 1);
	asn1_pop_tag(data);

	// SearchRequest
	asn1_push_tag(data, ASN1_APPLICATION(3));

	// empty baseObject
	asn1_push_tag(data, ASN1_OCTET_STRING);
	asn1_pop_tag(data);

	// scope 0 = baseObject
	asn1_push_tag(data, ASN1_ENUMERATED);
	asn1_write_uint8(data, 0);
	asn1_pop_tag(data);

	// derefAliasses 0=neverDerefAlias
	asn1_push_tag(data, ASN1_ENUMERATED);
	asn1_write_uint8(data, 0);
	asn1_pop_tag(data);

	// sizeLimit
	asn1_push_tag(data, ASN1_INTEGER);
	asn1_write_uint8(data, 0);
	asn1_pop_tag(data);

	// timeLimit
	asn1_push_tag(data, ASN1_INTEGER);
	asn1_write_uint8(data, 0);
	asn1_pop_tag(data);

	// typesOnly
	asn1_push_tag(data, ASN1_BOOLEAN);
	asn1_write_uint8(data, 0);
	asn1_pop_tag(data);

	// AND
	asn1_push_tag(data, ASN1_CONTEXT(0));
	// equalityMatch
	asn1_push_tag(data, ASN1_CONTEXT(3));
	asn1_write_OctetString(data, LDAP_DNS_DOMAIN, LDAP_DNS_DOMAIN_LEN);
	asn1_write_OctetString(data, domain, strlen(domain));
	asn1_pop_tag(data);

	// equalityMatch
	asn1_push_tag(data, ASN1_CONTEXT(3));
	asn1_write_OctetString(data, LDAP_NT_VERSION, LDAP_NT_VERSION_LEN);
	// Bitmask NETLOGON_NT_VERSION_5 & NETLOGON_NT_VERSION_5EX -> To get NETLOGON_SAM_LOGON_RESPONSE_EX as response
	asn1_write_OctetString(data, "\x06\x00\x00\x00", 4);
	asn1_pop_tag(data);

	// End AND
	asn1_pop_tag(data);

	asn1_push_tag(data, ASN1_SEQUENCE(0));
	asn1_write_OctetString(data, LDAP_ATTRIBUTE_NETLOGON, LDAP_ATTRIBUTE_NETLOGON_LEN);
	asn1_pop_tag(data);

	// End SearchRequest
	asn1_pop_tag(data);
	// End Sequence
	asn1_pop_tag(data);

	return data;
}

// Input is a cldap response, output is a pointer to the NETLOGON_SAM_LOGON_RESPONSE_EX payload
ssize_t extract_netlogon_section(char *buffer, size_t buffer_size, char **netlogon_payload) {
	size_t ber_size;
	size_t netlogon_payload_size;
	// Not enough space to read initial sequence - not an correct cldap response
	if (buffer_size < 7) {
		return CLDAP_PING_PARSE_ERROR_LDAP;
	}

	// Sequence tag
	if (*buffer != 0x30) {
		return CLDAP_PING_PARSE_ERROR_LDAP;
	}

	char *message_id_tag = parse_ber_size(buffer + 1, &ber_size);

	if (ber_size > buffer_size) {
		return CLDAP_PING_PARSE_ERROR_LDAP;
	}

	if (*message_id_tag != 0x02) {
		return CLDAP_PING_PARSE_ERROR_LDAP;
	}

	char *message_id = parse_ber_size(message_id_tag + 1, &ber_size);

	if (ber_size != 1 || *message_id != 1) {
		return CLDAP_PING_PARSE_ERROR_LDAP;
	}

	// SearchResultEntry
	if (*(message_id+1) != 0x64) {
		return CLDAP_PING_PARSE_ERROR_LDAP;
	}

	char *object_name_tag = parse_ber_size(message_id+2, &ber_size);
	if (object_name_tag == NULL) {
		return CLDAP_PING_PARSE_ERROR_LDAP;
	}

	char *object_name = parse_ber_size(object_name_tag+1, &ber_size);
	if (object_name == NULL) {
		return CLDAP_PING_PARSE_ERROR_LDAP;
	}

	if (*object_name_tag != 4 || ber_size != 0) {
		return CLDAP_PING_PARSE_ERROR_LDAP;
	}

	char *partial_attribute_list_tag = parse_ber_size(object_name+1, &ber_size);
	if (partial_attribute_list_tag == NULL) {
		return CLDAP_PING_PARSE_ERROR_LDAP;
	}

	if (*partial_attribute_list_tag != 0x30) {
		return CLDAP_PING_PARSE_ERROR_LDAP;
	}


	char *partial_attribute_tag = parse_ber_size(partial_attribute_list_tag+1, &ber_size);
	if (partial_attribute_tag == NULL) {
		return CLDAP_PING_PARSE_ERROR_LDAP;
	}

	char *attribute_name = parse_ber_size(partial_attribute_tag+1, &ber_size);
	if (attribute_name == NULL) {
		return CLDAP_PING_PARSE_ERROR_LDAP;
	}

	if (ber_size != LDAP_ATTRIBUTE_NETLOGON_LEN) {
		return CLDAP_PING_PARSE_ERROR_LDAP;
	}

	if (strncasecmp(LDAP_ATTRIBUTE_NETLOGON, attribute_name, LDAP_ATTRIBUTE_NETLOGON_LEN) != 0) {
		return CLDAP_PING_PARSE_ERROR_LDAP;
	}

	// SET
	if (*(attribute_name+LDAP_ATTRIBUTE_NETLOGON_LEN) != 0x31) {
		return CLDAP_PING_PARSE_ERROR_LDAP;
	}

	char *start_of_data = parse_ber_size(attribute_name+LDAP_ATTRIBUTE_NETLOGON_LEN+1, &ber_size);
	if (start_of_data == NULL) {
		return CLDAP_PING_PARSE_ERROR_LDAP;
	}

	// octat-string of NetLogon data
	if (*start_of_data != '\x04') {
		return CLDAP_PING_PARSE_ERROR_LDAP;
	}

	*netlogon_payload = parse_ber_size(start_of_data + 1, &netlogon_payload_size);

	if (*netlogon_payload == NULL) {
		*netlogon_payload = NULL;
		return CLDAP_PING_PARSE_ERROR_LDAP;
	}

	return (ssize_t)netlogon_payload_size;
}

int netlogon_get_client_site(char *netlogon_response, size_t netlogon_size, char *sitename) {
	// 24 mandatory bytes
	if (netlogon_size < 25) {
		return CLDAP_PING_PARSE_ERROR_NETLOGON;
	}

	// LOGON_SAM_PAUSE_RESPONSE_EX -> Netlogon service is not in-sync try next dc instead
	if (*netlogon_response == 0x18 && *(netlogon_response + 1) == 0x00) {
		return CLDAP_PING_TRYNEXT;
	}

	// NETLOGON_SAM_LOGON_RESPONSE_EX Opcode: 0x17
	if (*netlogon_response != 0x17 || *(netlogon_response + 1) != 0x00) {
		return CLDAP_PING_PARSE_ERROR_NETLOGON;
	}

	// skip over sbz, ds_flags and domain_guid
	// and start directly at variable string portion of NETLOGON_SAM_LOGON_RESPONSE_EX
	size_t offset = 24;

	for (int i=0; i < 8; i++) {
		// iterate over DnsForestName, DnsDomainName, NetbiosDomainName, NetbiosComputerName, UserName, DcSiteName
		// to finally get to our desired ClientSiteName field
		if (read_dns_string(netlogon_response, netlogon_size, sitename, MAXCDNAME, &offset) < 0) {
			return CLDAP_PING_PARSE_ERROR_NETLOGON;
		}
	}

	return 0;
}

int cldap_ping(char *domain, sa_family_t family, void *addr, char *site_name) {
	char buffer[8196];
	ssize_t response_size;
	char *netlogon_response;
	ssize_t netlogon_size;
	struct sockaddr_storage socketaddr;
	size_t addr_size;
	int sock = socket(family, SOCK_DGRAM, 0);
	if (sock < 0) {
		return CLDAP_PING_NETWORK_ERROR;
	}

	ASN1_DATA *data = generate_cldap_query(domain);

	if (family == AF_INET6) {
		addr_size = sizeof(struct sockaddr_in6);
		bzero((void *) &socketaddr, addr_size);
		socketaddr.ss_family = AF_INET6;
		((struct sockaddr_in6 *)&socketaddr)->sin6_addr = *((struct in6_addr*)addr);
		((struct sockaddr_in6 *)&socketaddr)->sin6_port = htons(389);
	} else {
		addr_size = sizeof(struct sockaddr_in);
		bzero((void *) &socketaddr, addr_size);
		socketaddr.ss_family = AF_INET;
		((struct sockaddr_in *)&socketaddr)->sin_addr = *((struct in_addr*)addr);
		((struct sockaddr_in *)&socketaddr)->sin_port = htons(389);
	}

	struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
	if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
		return CLDAP_PING_NETWORK_ERROR;
	}
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
		return CLDAP_PING_NETWORK_ERROR;
	}

	if (sendto(sock, data->data, data->length, 0, (struct sockaddr *)&socketaddr, addr_size) < 0) {
		close(sock);
		return CLDAP_PING_TRYNEXT;
	}

	asn1_free(data);
	response_size = recv(sock, buffer, sizeof(buffer), 0);
	close(sock);

	if (response_size < 0) {
		return CLDAP_PING_TRYNEXT;
	}

	netlogon_size = extract_netlogon_section(buffer, response_size, &netlogon_response);
	if (netlogon_size < 0) {
		return (int)netlogon_size;
	}

	return netlogon_get_client_site(netlogon_response, netlogon_size, site_name);
}
