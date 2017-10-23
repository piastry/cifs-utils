=========
cifscreds
=========

-----------------------------------------
manage NTLM credentials in kernel keyring
-----------------------------------------

:Manual section: 1

********
SYNOPSIS
********


cifscreds add|clear|clearall|update [-u username] [-d] host|domain


***********
DESCRIPTION
***********


The \ **cifscreds**\  program is a tool for managing credentials (username
and password) for the purpose of establishing sessions in multiuser
mounts.

When a cifs filesystem is mounted with the "multiuser" option, and does
not use krb5 authentication, it needs to be able to get the credentials
for each user from somewhere. The \ **cifscreds**\  program is the tool used
to provide these credentials to the kernel.

The first non-option argument to cifscreds is a command (see the
\ **COMMANDS**\  section below). The second non-option argument is a hostname
or address, or an NT domain name.


********
COMMANDS
********



\ **add**\ 
 
 Add credentials to the kernel to be used for connecting to the given server, or servers in the given domain.
 


\ **clear**\ 
 
 Clear credentials for a particular host or domain from the kernel.
 


\ **clearall**\ 
 
 Clear all cifs credentials from the kernel.
 


\ **update**\ 
 
 Update stored credentials in the kernel with a new username and
 password.
 



*******
OPTIONS
*******



\ **-d**\ , \ **--domain**\ 
 
 The provided host/domain argument is a NT domainname.
 
 Ordinarily the second argument provided to cifscreds is treated as a
 hostname or IP address. This option causes the cifscreds program to
 treat that argument as an NT domainname instead.
 
 If there are not host specific credentials for the mounted server, then
 the kernel will next look for a set of domain credentials equivalent to
 the domain= option provided at mount time.
 


\ **-u**\ , \ **--username**\ 
 
 Ordinarily, the username is derived from the unix username of the user
 adding the credentials. This option allows the user to substitute a
 different username.
 



*****
NOTES
*****


The cifscreds utility requires a kernel built with support for the
\ **login**\  key type. That key type was added in v3.3 in mainline Linux
kernels.

Since \ **cifscreds**\  adds keys to the session keyring, it is highly
recommended that one use \ **pam_keyinit**\  to ensure that a session keyring
is established at login time.


********
SEE ALSO
********


pam_keyinit(8)


*******
AUTHORS
*******


The cifscreds program was originally developed by Igor Druzhinin
<jaxbrigs@gmail.com>. This manpage and a redesign of the code was done
by Jeff Layton <jlayton@samba.org>.

