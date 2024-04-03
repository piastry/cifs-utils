/*
 * resolving DNS hostname routine
 *
 * Copyright (C) 2010 Jeff Layton (jlayton@samba.org)
 * Copyright (C) 2010 Igor Druzhinin (jaxbrigs@gmail.com)
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <resolv.h>
#include "mount.h"
#include "util.h"
#include "cldap_ping.h"
#include "resolve_host.h"

/*
 * resolve hostname to comma-separated list of address(es)
 */
int resolve_host(const char *host, char *addrstr) {
	int rc;
	/* 10 for max width of decimal scopeid */
	char tmpbuf[NI_MAXHOST + 1 + 10 + 1];
	const char *ipaddr;
	size_t len;
	struct addrinfo *addrlist, *addr;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	size_t count_v4 = 0, count_v6 = 0;

	rc = getaddrinfo(host, NULL, NULL, &addrlist);
	if (rc != 0)
		return EX_USAGE;

	addr = addrlist;
	while (addr) {
		/* skip non-TCP entries */
		if (addr->ai_socktype != SOCK_STREAM ||
		    addr->ai_protocol != IPPROTO_TCP) {
			addr = addr->ai_next;
			continue;
		}

		switch (addr->ai_addr->sa_family) {
			case AF_INET6:
				count_v6++;
				if (count_v6 + count_v4 > MAX_ADDRESSES) {
					addr = addr->ai_next;
					continue;
				}

				sin6 = (struct sockaddr_in6 *) addr->ai_addr;
				ipaddr = inet_ntop(AF_INET6, &sin6->sin6_addr, tmpbuf,
								   sizeof(tmpbuf));
				if (!ipaddr) {
					rc = EX_SYSERR;
					goto resolve_host_out;
				}


				if (sin6->sin6_scope_id) {
					len = strnlen(tmpbuf, sizeof(tmpbuf));
					snprintf(tmpbuf + len, sizeof(tmpbuf) - len, "%%%u",
							 sin6->sin6_scope_id);
				}
				break;
			case AF_INET:
				count_v4++;
				if (count_v6 + count_v4 > MAX_ADDRESSES) {
					addr = addr->ai_next;
					continue;
				}
				sin = (struct sockaddr_in *) addr->ai_addr;
				ipaddr = inet_ntop(AF_INET, &sin->sin_addr, tmpbuf,
								   sizeof(tmpbuf));
				if (!ipaddr) {
					rc = EX_SYSERR;
					goto resolve_host_out;
				}
				break;
			default:
				addr = addr->ai_next;
				continue;
		}

		if (addr == addrlist)
			*addrstr = '\0';
		else
			strlcat(addrstr, ",", MAX_ADDR_LIST_LEN);

		strlcat(addrstr, tmpbuf, MAX_ADDR_LIST_LEN);
		addr = addr->ai_next;
	}


	// Is this a DFS domain where we need to do a cldap ping to find the closest node?
	if (count_v4 > 1 || count_v6 > 1) {
		int res;
		ns_msg global_domain_handle;
		unsigned char global_domain_lookup[4096];
		ns_msg site_domain_handle;
		unsigned char site_domain_lookup[4096];
		char dname[MAXCDNAME];
		int srv_cnt;

		res = res_init();
		if (res != 0)
			goto resolve_host_out;

		res = snprintf(dname, MAXCDNAME, "_ldap._tcp.dc._msdcs.%s", host);
		if (res < 0)
			goto resolve_host_out;

		res = res_query(dname, C_IN, ns_t_srv, global_domain_lookup, sizeof(global_domain_lookup));
		if (res < 0)
			goto resolve_host_out;

		// res is also the size of the response_buffer
		res = ns_initparse(global_domain_lookup, res, &global_domain_handle);
		if (res < 0)
			goto resolve_host_out;

		srv_cnt = ns_msg_count (global_domain_handle, ns_s_an);

		// No or just one DC we are done
		if (srv_cnt < 2)
			goto resolve_host_out;

		char site_name[MAXCDNAME];
		// We assume that AD always sends the ip addresses in the addtional data block
		for (int i = 0; i < ns_msg_count(global_domain_handle, ns_s_ar); i++) {
			ns_rr rr;
			res = ns_parserr(&global_domain_handle, ns_s_ar, i, &rr);
			if (res < 0)
				goto resolve_host_out;

			switch (ns_rr_type(rr)) {
				case ns_t_aaaa:
					if (ns_rr_rdlen(rr) != NS_IN6ADDRSZ)
						continue;
					res = cldap_ping((char *) host, AF_INET6, (void *)ns_rr_rdata(rr), site_name);
					break;
				case ns_t_a:
					if (ns_rr_rdlen(rr) != NS_INADDRSZ)
						continue;
					res = cldap_ping((char *) host, AF_INET, (void *)ns_rr_rdata(rr), site_name);
					break;
				default:
					continue;
			}

			if (res == CLDAP_PING_TRYNEXT) {
				continue;
			}

			if (res < 0) {
				goto resolve_host_out;
			}

			if (site_name[0] == '\0') {
				goto resolve_host_out;
			} else {
				// site found - leave loop
				break;
			}
		}

		res = snprintf(dname, MAXCDNAME, "_ldap._tcp.%s._sites.dc._msdcs.%s", site_name, host);
		if (res < 0) {
			goto resolve_host_out;
		}

		res = res_query(dname, C_IN, ns_t_srv, site_domain_lookup, sizeof(site_domain_lookup));
		if (res < 0)
			goto resolve_host_out;

		// res is also the size of the response_buffer
		res = ns_initparse(site_domain_lookup, res, &site_domain_handle);
		if (res < 0)
			goto resolve_host_out;

		int number_addresses = 0;
		for (int i = 0; i < ns_msg_count(site_domain_handle, ns_s_ar); i++) {
			if (i > MAX_ADDRESSES)
				break;

			ns_rr rr;
			res = ns_parserr(&site_domain_handle, ns_s_ar, i, &rr);
			if (res < 0)
				goto resolve_host_out;

			switch (ns_rr_type(rr)) {
				case ns_t_aaaa:
					if (ns_rr_rdlen(rr) != NS_IN6ADDRSZ)
						continue;
					ipaddr = inet_ntop(AF_INET6, ns_rr_rdata(rr), tmpbuf,
									   sizeof(tmpbuf));
					if (!ipaddr) {
						rc = EX_SYSERR;
						goto resolve_host_out;
					}
					break;
				case ns_t_a:
					if (ns_rr_rdlen(rr) != NS_INADDRSZ)
						continue;
					ipaddr = inet_ntop(AF_INET, ns_rr_rdata(rr), tmpbuf,
									   sizeof(tmpbuf));
					if (!ipaddr) {
						rc = EX_SYSERR;
						goto resolve_host_out;
					}
					break;
				default:
					continue;
			}

			number_addresses++;

			if (i == 0)
				*addrstr = '\0';
			else
				strlcat(addrstr, ",", MAX_ADDR_LIST_LEN);

			strlcat(addrstr, tmpbuf, MAX_ADDR_LIST_LEN);
		}

		// Preferred site ips is now the first entry in addrstr, fill up with other sites till MAX_ADDRESS
		for (int i = 0; i < ns_msg_count(global_domain_handle, ns_s_ar); i++) {
			if (number_addresses > MAX_ADDRESSES)
				break;

			ns_rr rr;
			res = ns_parserr(&global_domain_handle, ns_s_ar, i, &rr);
			if (res < 0)
				goto resolve_host_out;

			switch (ns_rr_type(rr)) {
				case ns_t_aaaa:
					if (ns_rr_rdlen(rr) != NS_IN6ADDRSZ)
						continue;
					ipaddr = inet_ntop(AF_INET6, ns_rr_rdata(rr), tmpbuf,
									   sizeof(tmpbuf));
					if (!ipaddr) {
						rc = EX_SYSERR;
						goto resolve_host_out;
					}
					break;
				case ns_t_a:
					if (ns_rr_rdlen(rr) != NS_INADDRSZ)
						continue;
					ipaddr = inet_ntop(AF_INET, ns_rr_rdata(rr), tmpbuf,
									   sizeof(tmpbuf));
					if (!ipaddr) {
						rc = EX_SYSERR;
						goto resolve_host_out;
					}
					break;
				default:
					continue;
			}

			char *found = strstr(addrstr, tmpbuf);

			if (found) {
				// We only have a real match if the substring is between  ',' or it's the last/first entry in the list
				char previous_seperator = found > addrstr ? *(found-1) : '\0';
				char next_seperator = *(found+strlen(tmpbuf));

				if ((next_seperator == ',' || next_seperator == '\0')
					&& (previous_seperator == ',' || previous_seperator == '\0')) {
					continue;
				}
			}

			number_addresses++;
			strlcat(addrstr, ",", MAX_ADDR_LIST_LEN);
			strlcat(addrstr, tmpbuf, MAX_ADDR_LIST_LEN);
		}
	}

resolve_host_out:
	freeaddrinfo(addrlist);
	return rc;
}
