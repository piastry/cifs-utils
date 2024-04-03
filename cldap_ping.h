#ifndef _CLDAP_PING_H_
#define _CLDAP_PING_H_

#define CLDAP_PING_NETWORK_ERROR -1
#define CLDAP_PING_TRYNEXT -2
#define CLDAP_PING_PARSE_ERROR_LDAP -3
#define CLDAP_PING_PARSE_ERROR_NETLOGON -4

// returns CLDAP_PING_TRYNEXT if you should use another dc
// any other error code < 0 is a fatal error
// site_name must be of MAXCDNAME size!
int cldap_ping(char *domain, sa_family_t family, void *addr, char *site_name);

#endif /* _CLDAP_PING_H_ */
