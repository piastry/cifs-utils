=============
pam_cifscreds
=============

-------------------------------------------------------
PAM module to manage NTLM credentials in kernel keyring
-------------------------------------------------------
:Manual section: 8


********
SYNOPSIS
********


Edit the PAM configuration files for the systems that you want to
automatically register NTLM credentials for, e.g. /etc/pam.d/login,
and modify as follows:


.. code-block:: perl

         ...
         auth       substack     system-auth
     +++ auth       optional     pam_cifscreds.so
         auth       include      postlogin
         ...
 
         ...
         session    include      system-auth
     +++ session    optional     pam_cifscreds.so domain=DOMAIN
         session    include      postlogin
         ...


Change DOMAIN to the name of you Windows domain, or use host= as
described below.


***********
DESCRIPTION
***********


The \ **pam_cifscreds**\  PAM module is a tool for automatically adding
credentials (username and password) for the purpose of establishing
sessions in multiuser mounts.

When a cifs filesystem is mounted with the "multiuser" option, and does
not use krb5 authentication, it needs to be able to get the credentials
for each user from somewhere. The \ **pam_cifscreds**\  module can be used
to provide these credentials to the kernel automatically at login.

In the session section of the PAM configuration file, the module can
either an NT domain name or a list of hostname or addresses.


*******
OPTIONS
*******


\ **pam_cifscreds**\  supports a couple options which can be set in the PAM
configuration files.  You must have one (and only one) of domain= or
host=.


\ **debug**\ 
 
 Turns on some extra debug logging.
 


\ **domain**\ =<NT domain name>
 
 Credentials will be added for the specified NT domain name.
 


\ **host**\ =<hostname or IP address>[,...]
 
 Credentials will be added for the specified hostnames or IP addresses.
 



*****
NOTES
*****


The pam_cifscreds PAM module requires a kernel built with support for
the \ **login**\  key type. That key type was added in v3.3 in mainline Linux
kernels.

Since \ **pam_cifscreds**\  adds keys to the session keyring, it is highly
recommended that one use \ **pam_keyinit**\  to ensure that a session keyring
is established at login time.


********
SEE ALSO
********


cifscreds(1), pam_keyinit(8)


******
AUTHOR
******


The pam_cifscreds PAM module was developed by Orion Poplawski
<orion@nwra.com>.

