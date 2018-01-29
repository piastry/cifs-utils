==========
mount.cifs
==========

--------------------------------------------------
mount using the Common Internet File System (CIFS)
--------------------------------------------------
:Manual section: 8

********
SYNOPSIS
********

  mount.cifs {service} {mount-point} [-o options]

This tool is part of the cifs-utils suite.

``mount.cifs`` mounts a Linux CIFS filesystem. It is usually invoked
indirectly by the mount(8) command when using the "-t cifs"
option. This command only works in Linux, and the kernel must support
the cifs filesystem. The CIFS protocol is the successor to the SMB
protocol and is supported by most Windows servers and many other
commercial servers and Network Attached Storage appliances as well as
by the popular Open Source server Samba.

The mount.cifs utility attaches the UNC name (exported network
resource) specified as service (using ``//server/share`` syntax, where
"server" is the server name or IP address and "share" is the name of
the share) to the local directory mount-point.

Options to mount.cifs are specified as a comma-separated list of
``key=value`` pairs. It is possible to send options other than those
listed here, assuming that the cifs filesystem kernel module
(``cifs.ko``) supports them. Unrecognized cifs mount options passed to
the cifs vfs kernel code will be logged to the kernel log.

``mount.cifs`` causes the cifs vfs to launch a thread named
cifsd. After mounting it keeps running until the mounted resource is
unmounted (usually via the ``umount`` utility).

``mount.cifs -V`` command displays the version of cifs mount helper.

``modinfo cifs`` command displays the version of cifs module.


*******
OPTIONS
*******


username=arg|user=arg
  specifies the username to connect as. If this is not
  given, then the environment variable USER is used.

  Earlier versions of mount.cifs also allowed one to specify the
  username in a ``user%password`` or ``workgroup/user`` or
  ``workgroup/user%password`` to allow the password and workgroup to
  be specified as part of the username. Support for those alternate
  username formats is now deprecated and should no longer be
  used. Users should use the discrete ``password=`` and ``domain=`` to
  specify those values. While some versions of the cifs kernel module
  accept ``user=`` as an abbreviation for this option, its use can
  confuse the standard mount program into thinking that this is a
  non-superuser mount. It is therefore recommended to use the full
  ``username=`` option name.

password=arg|pass=arg
  specifies the CIFS password. If this option is not given then the
  environment variable PASSWD is used. If the password is not specified
  directly or indirectly via an argument to mount, mount.cifs will
  prompt for a password, unless the guest option is specified.

  Note that a password which contains the delimiter character (i.e. a
  comma ',') will fail to be parsed correctly on the command
  line. However, the same password defined in the PASSWD environment
  variable or via a credentials file (see below) or entered at the
  password prompt will be read correctly.

credentials=filename|cred=filename
  specifies a file that contains a username and/or password and
  optionally the name of the workgroup. The format of the file is::

   username=value
   password=value
   domain=value

 This is preferred over having passwords in plaintext in a shared file,
 such as ``/etc/fstab`` . Be sure to protect any credentials file
 properly.

uid=arg
  sets the uid that will own all files or directories on the mounted
  filesystem when the server does not provide ownership information. It
  may be specified as either a username or a numeric uid. When not
  specified, the default is uid 0. The mount.cifs helper must be at
  version 1.10 or higher to support specifying the uid in non-numeric
  form. See the section on `FILE AND DIRECTORY OWNERSHIP AND PERMISSIONS`_
  below for more information.

forceuid
  instructs the client to ignore any uid provided by the server for
  files and directories and to always assign the owner to be the value
  of the uid= option. See the section on
  `FILE AND DIRECTORY OWNERSHIP AND PERMISSIONS`_ below for more information.

cruid=arg
  sets the uid of the owner of the credentials cache. This is primarily
  useful with ``sec=krb5``. The default is the real uid of the process
  performing the mount. Setting this parameter directs the upcall to
  look for a credentials cache owned by that user.

gid=arg
  sets the gid that will own all files or directories on the mounted
  filesystem when the server does not provide ownership information. It
  may be specified as either a groupname or a numeric gid. When not
  specified, the default is gid 0. The mount.cifs helper must be at
  version 1.10 or higher to support specifying the gid in non-numeric
  form. See the section on `FILE AND DIRECTORY OWNERSHIP AND PERMISSIONS`_
  below for more information.

forcegid
  instructs the client to ignore any gid provided by the server for
  files and directories and to always assign the owner to be the value
  of the gid= option. See the section on `FILE AND DIRECTORY OWNERSHIP
  AND PERMISSIONS`_ below for more information.

port=arg
  sets the port number on which the client will attempt to contact the
  CIFS server. If this value is specified, look for an existing
  connection with this port, and use that if one exists. If one doesn't
  exist, try to create a new connection on that port. If that connection
  fails, return an error. If this value isn't specified, look for an
  existing connection on port 445 or 139. If no such connection exists,
  try to connect on port 445 first and then port 139 if that
  fails. Return an error if both fail.

servernetbiosname=arg
  Specify the server netbios name (RFC1001 name) to use when attempting
  to setup a session to the server. Although rarely needed for mounting
  to newer servers, this option is needed for mounting to some older
  servers (such as OS/2 or Windows 98 and Windows ME) since when
  connecting over port 139 they, unlike most newer servers, do not
  support a default server name. A server name can be up to 15
  characters long and is usually uppercased.

servern=arg
  Synonym for ``servernetbiosname``

netbiosname=arg
  When mounting to servers via port 139, specifies the RFC1001 source
  name to use to represent the client netbios machine name when doing
  the RFC1001 netbios session initialize.

file_mode=arg
  If the server does not support the CIFS Unix extensions this overrides
  the default file mode.

dir_mode=arg
  If the server does not support the CIFS Unix extensions this overrides
  the default mode for directories.

ip=arg|addr=arg
  sets the destination IP address. This option is set automatically if
  the server name portion of the requested UNC name can be resolved so
  rarely needs to be specified by the user.

domain=arg|dom=arg|workgroup=arg
  sets the domain (workgroup) of the user.

guest
  don't prompt for a password.

iocharset
  Charset used to convert local path names to and from Unicode. Unicode
  is used by default for network path names if the server supports
  it. If ``iocharset`` is not specified then the ``nls_default`` specified
  during the local client kernel build will be used. If server does not
  support Unicode, this parameter is unused.

ro
  mount read-only.

rw
  mount read-write.

setuids
  If the CIFS Unix extensions are negotiated with the server the client
  will attempt to set the effective uid and gid of the local process on
  newly created files, directories, and devices (create, mkdir,
  mknod). If the CIFS Unix Extensions are not negotiated, for newly
  created files and directories instead of using the default uid and gid
  specified on the the mount, cache the new file's uid and gid locally
  which means that the uid for the file can change when the inode is
  reloaded (or the user remounts the share).

nosetuids
  The client will not attempt to set the uid and gid on on newly created
  files, directories, and devices (create, mkdir, mknod) which will
  result in the server setting the uid and gid to the default (usually
  the server uid of the user who mounted the share). Letting the server
  (rather than the client) set the uid and gid is the default. If the
  CIFS Unix Extensions are not negotiated then the uid and gid for new
  files will appear to be the uid (gid) of the mounter or the uid (gid)
  parameter specified on the mount.

perm
  Client does permission checks (vfs_permission check of uid and gid of
  the file against the mode and desired operation), Note that this is in
  addition to the normal ACL check on the target machine done by the
  server software. Client permission checking is enabled by default.

noperm
  Client does not do permission checks. This can expose files on this
  mount to access by other users on the local client system. It is
  typically only needed when the server supports the CIFS Unix
  Extensions but the UIDs/GIDs on the client and server system do not
  match closely enough to allow access by the user doing the mount. Note
  that this does not affect the normal ACL check on the target machine
  done by the server software (of the server ACL against the user name
  provided at mount time).

dynperm
  Instructs the server to maintain ownership and permissions in memory
  that can't be stored on the server. This information can disappear
  at any time (whenever the inode is flushed from the cache), so while
  this may help make some applications work, it's behavior is somewhat
  unreliable. See the section below on `FILE AND DIRECTORY OWNERSHIP
  AND PERMISSIONS`_ for more information.

cache=arg
  Cache mode. See the section below on `CACHE COHERENCY`_ for
  details. Allowed values are:

  - ``none`` - do not cache file data at all
  - ``strict`` - follow the CIFS/SMB2 protocol strictly
  - ``loose`` - allow loose caching semantics

  The default in kernels prior to 3.7 was ``loose``. As of kernel 3.7 the
  default is ``strict``.

directio
  Do not do inode data caching on files opened on this mount. This
  precludes mmaping files on this mount. In some cases with fast
  networks and little or no caching benefits on the client (e.g. when
  the application is doing large sequential reads bigger than page size
  without rereading the same data) this can provide better performance
  than the default behavior which caches reads (readahead) and writes
  (writebehind) through the local Linux client pagecache if oplock
  (caching token) is granted and held. Note that direct allows write
  operations larger than page size to be sent to the server. On some
  kernels this requires the cifs.ko module to be built with the
  ``CIFS_EXPERIMENTAL`` configure option.

  This option is will be deprecated in 3.7. Users should use
  ``cache=none`` instead on more recent kernels.

strictcache
  Use for switching on strict cache mode. In this mode the client reads
  from the cache all the time it has *Oplock Level II* , otherwise -
  read from the server. As for write - the client stores a data in the
  cache in *Exclusive Oplock* case, otherwise - write directly to the
  server.

  This option is will be deprecated in 3.7. Users should use
  ``cache=strict`` instead on more recent kernels.

rwpidforward
  Forward pid of a process who opened a file to any read or write
  operation on that file. This prevent applications like wine(1) from
  failing on read and write if we use mandatory brlock style.

mapchars
  Translate six of the seven reserved characters (not backslash, but
  including the colon, question mark, pipe, asterik, greater than and
  less than characters) to the remap range (above 0xF000), which also
  allows the CIFS client to recognize files created with such characters
  by Windows's POSIX emulation. This can also be useful when mounting to
  most versions of Samba (which also forbids creating and opening files
  whose names contain any of these seven characters). This has no effect
  if the server does not support Unicode on the wire. Please note that
  the files created with ``mapchars`` mount option may not be accessible
  if the share is mounted without that option.

nomapchars
  (default) Do not translate any of these seven characters.

intr
  currently unimplemented.

nointr
  (default) currently unimplemented.

hard
  The program accessing a file on the cifs mounted file system will hang
  when the server crashes.

soft
  (default) The program accessing a file on the cifs mounted file system
  will not hang when the server crashes and will return errors to the
  user application.

noacl
  Do not allow POSIX ACL operations even if server would support them.

  The CIFS client can get and set POSIX ACLs (getfacl, setfacl) to Samba
  servers version 3.0.10 and later. Setting POSIX ACLs requires enabling
  both ``CIFS_XATTR`` and then ``CIFS_POSIX`` support in the CIFS
  configuration options when building the cifs module. POSIX ACL support
  can be disabled on a per mount basis by specifying ``noacl`` on mount.

cifsacl
  This option is used to map CIFS/NTFS ACLs to/from Linux permission
  bits, map SIDs to/from UIDs and GIDs, and get and set Security
  Descriptors.

  See section on `CIFS/NTFS ACL, SID/UID/GID MAPPING, SECURITY DESCRIPTORS`_
  for more information.

backupuid=arg
  File access by this user shall be done with the backup intent flag
  set. Either a name or an id must be provided as an argument, there are
  no default values.

  See section `ACCESSING FILES WITH BACKUP INTENT`_ for more details.

backupgid=arg
  File access by users who are members of this group shall be done with
  the backup intent flag set. Either a name or an id must be provided as
  an argument, there are no default values.

  See section `ACCESSING FILES WITH BACKUP INTENT`_ for more details.

nocase
  Request case insensitive path name matching (case sensitive is the default if the
  server supports it).

ignorecase
  Synonym for ``nocase``.

sec=arg
  Security mode. Allowed values are:

  - ``none`` - attempt to connection as a null user (no name)
  - ``krb5`` - Use Kerberos version 5 authentication
  - ``krb5i`` - Use Kerberos authentication and forcibly enable packet signing
  - ``ntlm`` - Use NTLM password hashing
  - ``ntlmi`` - Use NTLM password hashing and force packet signing
  - ``ntlmv2`` - Use NTLMv2 password hashing
  - ``ntlmv2i`` - Use NTLMv2 password hashing and force packet signing
  - ``ntlmssp`` - Use NTLMv2 password hashing encapsulated in Raw NTLMSSP message
  - ``ntlmsspi`` - Use NTLMv2 password hashing encapsulated in Raw NTLMSSP message, and force packet signing

  The default in mainline kernel versions prior to v3.8 was
  ``sec=ntlm``. In v3.8, the default was changed to ``sec=ntlmssp``.

  If the server requires signing during protocol negotiation, then it
  may be enabled automatically. Packet signing may also be enabled
  automatically if it's enabled in */proc/fs/cifs/SecurityFlags*.

seal
  Request encryption at the SMB layer. Encryption is only supported in
  SMBv3 and above. The encryption algorithm used is AES-128-CCM.

nobrl
  Do not send byte range lock requests to the server. This is necessary
  for certain applications that break with cifs style mandatory byte
  range locks (and most cifs servers do not yet support requesting
  advisory byte range locks).

sfu
  When the CIFS Unix Extensions are not negotiated, attempt to create
  device files and fifos in a format compatible with Services for Unix
  (SFU). In addition retrieve bits 10-12 of the mode via the
  ``SETFILEBITS`` extended attribute (as SFU does). In the future the
  bottom 9 bits of the mode mode also will be emulated using queries of
  the security descriptor (ACL). [NB: requires version 1.39 or later of
  the CIFS VFS. To recognize symlinks and be able to create symlinks in
  an SFU interoperable form requires version 1.40 or later of the CIFS
  VFS kernel module.

mfsymlinks
  Enable support for Minshall+French symlinks (see
  `http://wiki.samba.org/index.php/UNIX_Extensions#Minshall.2BFrench_symlinks <http://wiki.samba.org/index.php/UNIX_Extensions#Minshall.2BFrench_symlinks>`_). This
  option is ignored when specified together with the ``sfu``
  option. Minshall+French symlinks are used even if the server supports
  the CIFS Unix Extensions.

echo_interval=n
  sets the interval at which echo requests are sent to the server on an
  idling connection. This setting also affects the time required for a
  connection to an unresponsive server to timeout. Here n is the echo
  interval in seconds. The reconnection happens at twice the value of the
  echo_interval set for an unresponsive server.
  If this option is not given then the default value of 60 seconds is used.
  The minimum tunable value is 1 second and maximum can go up to 600 seconds.

serverino
  Use inode numbers (unique persistent file identifiers) returned by the
  server instead of automatically generating temporary inode numbers on
  the client. Although server inode numbers make it easier to spot
  hardlinked files (as they will have the same inode numbers) and inode
  numbers may be persistent (which is useful for some software), the
  server does not guarantee that the inode numbers are unique if
  multiple server side mounts are exported under a single share (since
  inode numbers on the servers might not be unique if multiple
  filesystems are mounted under the same shared higher level
  directory). Note that not all servers support returning server inode
  numbers, although those that support the CIFS Unix Extensions, and
  Windows 2000 and later servers typically do support this (although not
  necessarily on every local server filesystem). Parameter has no effect
  if the server lacks support for returning inode numbers or
  equivalent. This behavior is enabled by default.

noserverino
  Client generates inode numbers itself rather than using the actual
  ones from the server.

  See section `INODE NUMBERS`_ for more information.

nounix
  Disable the CIFS Unix Extensions for this mount. This can be useful in
  order to turn off multiple settings at once. This includes POSIX acls,
  POSIX locks, POSIX paths, symlink support and retrieving
  uids/gids/mode from the server. This can also be useful to work around
  a bug in a server that supports Unix Extensions.

  See section `INODE NUMBERS`_ for more information.

nouser_xattr
  Do not allow getfattr/setfattr to get/set xattrs, even if server would
  support it otherwise. The default is for xattr support to be enabled.

rsize=bytes
  Maximum amount of data that the kernel will request in a read request
  in bytes. Prior to kernel 3.2.0, the default was 16k, and the maximum
  size was limited by the ``CIFSMaxBufSize`` module parameter. As of
  kernel 3.2.0, the behavior varies according to whether POSIX
  extensions are enabled on the mount and the server supports large
  POSIX reads. If they are, then the default is 1M, and the maximum is
  16M. If they are not supported by the server, then the default is 60k
  and the maximum is around 127k. The reason for the 60k is because it's
  the maximum size read that windows servers can fill. Note that this
  value is a maximum, and the client may settle on a smaller size to
  accommodate what the server supports. In kernels prior to 3.2.0, no
  negotiation is performed.

wsize=bytes
  Maximum amount of data that the kernel will send in a write request in
  bytes. Prior to kernel 3.0.0, the default and maximum was 57344 (14 \*
  4096 pages). As of 3.0.0, the default depends on whether the client
  and server negotiate large writes via POSIX extensions. If they do,
  then the default is 1M, and the maximum allowed is 16M. If they do
  not, then the default is 65536 and the maximum allowed is 131007. Note
  that this value is just a starting point for negotiation in 3.0.0 and
  up. The client and server may negotiate this size downward according
  to the server's capabilities. In kernels prior to 3.0.0, no
  negotiation is performed. It can end up with an existing superblock if
  this value isn't specified or it's greater or equal than the existing
  one.

fsc
  Enable local disk caching using FS-Cache for CIFS. This option could
  be useful to improve performance on a slow link, heavily loaded server
  and/or network where reading from the disk is faster than reading from
  the server (over the network). This could also impact the scalability
  positively as the number of calls to the server are reduced. But, be
  warned that local caching is not suitable for all workloads, for e.g.,
  read-once type workloads. So, you need to consider carefully the
  situation/workload before using this option. Currently, local disk
  caching is enabled for CIFS files opened as read-only.

  **NOTE**: This feature is available only in the recent kernels that
  have been built with the kernel config option
  ``CONFIG_CIFS_FSCACHE``. You also need to have ``cachefilesd``
  daemon installed and running to make the cache operational.

multiuser
  Map user accesses to individual credentials when accessing the
  server. By default, CIFS mounts only use a single set of user
  credentials (the mount credentials) when accessing a share. With this
  option, the client instead creates a new session with the server using
  the user's credentials whenever a new user accesses the mount.
  Further accesses by that user will also use those credentials. Because
  the kernel cannot prompt for passwords, multiuser mounts are limited
  to mounts using ``sec=`` options that don't require passwords.

  With this change, it's feasible for the server to handle permissions
  enforcement, so this option also implies ``noperm`` . Furthermore, when
  unix extensions aren't in use and the administrator has not overridden
  ownership using the ``uid=`` or ``gid=`` options, ownership of files is
  presented as the current user accessing the share.

actimeo=arg
  The time (in seconds) that the CIFS client caches attributes of a file or
  directory before it requests attribute information from a server. During this
  period the changes that occur on the server remain undetected until the client
  checks the server again.

  By default, the attribute cache timeout is set to 1 second. This means
  more frequent on-the-wire calls to the server to check whether
  attributes have changed which could impact performance. With this
  option users can make a tradeoff between performance and cache
  metadata correctness, depending on workload needs. Shorter timeouts
  mean better cache coherency, but frequent increased number of calls to
  the server. Longer timeouts mean a reduced number of calls to the
  server but looser cache coherency. The ``actimeo`` value is a positive
  integer that can hold values between 0 and a maximum value of 2^30 \*
  HZ (frequency of timer interrupt) setting.

noposixpaths
  If unix extensions are enabled on a share, then the client will
  typically allow filenames to include any character besides '/' in a
  pathname component, and will use forward slashes as a pathname
  delimiter. This option prevents the client from attempting to
  negotiate the use of posix-style pathnames to the server.

posixpaths
  Inverse of ``noposixpaths`` .

prefixpath=arg
  It's possible to mount a subdirectory of a share. The preferred way to
  do this is to append the path to the UNC when mounting. However, it's
  also possible to do the same by setting this option and providing the
  path there.

vers=arg
  SMB protocol version. Allowed values are:

  - 1.0 - The classic CIFS/SMBv1 protocol.
  - 2.0 - The SMBv2.002 protocol. This was initially introduced in
    Windows Vista Service Pack 1, and Windows Server 2008. Note that
    the initial release version of Windows Vista spoke a slightly
    different dialect (2.000) that is not supported.
  - 2.1 - The SMBv2.1 protocol that was introduced in Microsoft Windows 7 and Windows Server 2008R2.
  - 3.0 - The SMBv3.0 protocol that was introduced in Microsoft Windows 8 and Windows Server 2012.
  - 3.1.1 or 3.11 - The SMBv3.1.1 protocol that was introduced in Microsoft Windows Server 2016.

  Note too that while this option governs the protocol version used, not
  all features of each version are available.

  The default since v4.13.5 is for the client and server to negotiate
  the highest possible version greater than or equal to ``2.1``. In
  kernels prior to v4.13, the default was ``1.0``. For kernels
  between v4.13 and v4.13.5 the default is ``3.0``.

--verbose
  Print additional debugging information for the mount. Note that this
  parameter must be specified before the ``-o`` . For example::

    mount -t cifs //server/share /mnt --verbose -o user=username


*********************************
SERVICE FORMATTING AND DELIMITERS
*********************************

It's generally preferred to use forward slashes (/) as a delimiter in
service names. They are considered to be the "universal delimiter"
since they are generally not allowed to be embedded within path
components on Windows machines and the client can convert them to
backslashes (\) unconditionally. Conversely, backslash characters are
allowed by POSIX to be part of a path component, and can't be
automatically converted in the same way.

``mount.cifs`` will attempt to convert backslashes to forward slashes
where it's able to do so, but it cannot do so in any path component
following the sharename.


*************
INODE NUMBERS
*************


When Unix Extensions are enabled, we use the actual inode number
provided by the server in response to the POSIX calls as an inode
number.

When Unix Extensions are disabled and ``serverino`` mount option is
enabled there is no way to get the server inode number. The client
typically maps the server-assigned ``UniqueID`` onto an inode number.

Note that the ``UniqueID`` is a different value from the server inode
number. The ``UniqueID`` value is unique over the scope of the entire
server and is often greater than 2 power 32. This value often makes
programs that are not compiled with LFS (Large File Support), to
trigger a glibc ``EOVERFLOW`` error as this won't fit in the target
structure field. It is strongly recommended to compile your programs
with LFS support (i.e. with ``-D_FILE_OFFSET_BITS=64``) to prevent this
problem. You can also use ``noserverino`` mount option to generate
inode numbers smaller than 2 power 32 on the client. But you may not
be able to detect hardlinks properly.

***************
CACHE COHERENCY
***************

With a network filesystem such as CIFS or NFS, the client must contend
with the fact that activity on other clients or the server could
change the contents or attributes of a file without the client being
aware of it. One way to deal with such a problem is to mandate that
all file accesses go to the server directly. This is performance
prohibitive however, so most protocols have some mechanism to allow
the client to cache data locally.

The CIFS protocol mandates (in effect) that the client should not
cache file data unless it holds an opportunistic lock (aka oplock) or
a lease. Both of these entities allow the client to guarantee certain
types of exclusive access to a file so that it can access its contents
without needing to continually interact with the server. The server
will call back the client when it needs to revoke either of them and
allow the client a certain amount of time to flush any cached data.

The cifs client uses the kernel's pagecache to cache file data. Any
I/O that's done through the pagecache is generally page-aligned. This
can be problematic when combined with byte-range locks as Windows'
locking is mandatory and can block reads and writes from occurring.

``cache=none`` means that the client never utilizes the cache for
normal reads and writes. It always accesses the server directly to
satisfy a read or write request.

``cache=strict`` means that the client will attempt to follow the
CIFS/SMB2 protocol strictly. That is, the cache is only trusted when
the client holds an oplock. When the client does not hold an oplock,
then the client bypasses the cache and accesses the server directly to
satisfy a read or write request. By doing this, the client avoids
problems with byte range locks. Additionally, byte range locks are
cached on the client when it holds an oplock and are "pushed" to the
server when that oplock is recalled.

``cache=loose`` allows the client to use looser protocol semantics
which can sometimes provide better performance at the expense of cache
coherency. File access always involves the pagecache. When an oplock
or lease is not held, then the client will attempt to flush the cache
soon after a write to a file. Note that that flush does not
necessarily occur before a write system call returns.

In the case of a read without holding an oplock, the client will
attempt to periodically check the attributes of the file in order to
ascertain whether it has changed and the cache might no longer be
valid. This mechanism is much like the one that NFSv2/3 use for cache
coherency, but it particularly problematic with CIFS. Windows is
quite "lazy" with respect to updating the ``LastWriteTime`` field that
the client uses to verify this. The effect is that ``cache=loose`` can
cause data corruption when multiple readers and writers are working on
the same files.

Because of this, when multiple clients are accessing the same set of
files, then ``cache=strict`` is recommended. That helps eliminate
problems with cache coherency by following the CIFS/SMB2 protocols
more strictly.

Note too that no matter what caching model is used, the client will
always use the pagecache to handle mmap'ed files. Writes to mmap'ed
files are only guaranteed to be flushed to the server when msync() is
called, or on close().

The default in kernels prior to 3.7 was ``loose``. As of 3.7, the
default is ``strict``.

********************************************************
CIFS/NTFS ACL, SID/UID/GID MAPPING, SECURITY DESCRIPTORS
********************************************************

This option is used to work with file objects which posses Security
Descriptors and CIFS/NTFS ACL instead of UID, GID, file permission
bits, and POSIX ACL as user authentication model. This is the most
common authentication model for CIFS servers and is the one used by
Windows.

Support for this requires both CIFS_XATTR and CIFS_ACL support in the
CIFS configuration options when building the cifs module.

A CIFS/NTFS ACL is mapped to file permission bits using an algorithm
specified in the following Microsoft TechNet document:

`http://technet.microsoft.com/en-us/library/bb463216.aspx <http://technet.microsoft.com/en-us/library/bb463216.aspx>`_

In order to map SIDs to/from UIDs and GIDs, the following is required:

- a kernel upcall to the ``cifs.idmap`` utility set up via request-key.conf(5)
- winbind support configured via nsswitch.conf(5) and smb.conf(5)

Please refer to the respective manpages of cifs.idmap(8) and
winbindd(8) for more information.

Security descriptors for a file object can be retrieved and set
directly using extended attribute named ``system.cifs_acl``. The
security descriptors presented via this interface are "raw" blobs of
data and need a userspace utility to either parse and format or to
assemble it such as getcifsacl(1) and setcifsacl(1)
respectively.

Some of the things to consider while using this mount option:

- There may be an increased latency when handling metadata due to
  additional requests to get and set security descriptors.
- The mapping between a CIFS/NTFS ACL and POSIX file permission bits
  is imperfect and some ACL information may be lost in the
  translation.
- If either upcall to cifs.idmap is not setup correctly or winbind is
  not configured and running, ID mapping will fail. In that case uid
  and gid will default to either to those values of the share or to
  the values of uid and/or gid mount options if specified.

**********************************
ACCESSING FILES WITH BACKUP INTENT
**********************************

For an user on the server, desired access to a file is determined by
the permissions and rights associated with that file. This is
typically accomplished using ownership and ACL. For a user who does
not have access rights to a file, it is still possible to access that
file for a specific or a targeted purpose by granting special rights.
One of the specific purposes is to access a file with the intent to
either backup or restore i.e. backup intent. The right to access a
file with the backup intent can typically be granted by making that
user a part of the built-in group *Backup Operators*. Thus, when
this user attempts to open a file with the backup intent, open request
is sent by setting the bit ``FILE_OPEN_FOR_BACKUP_INTENT`` as one of
the ``CreateOptions``.

As an example, on a Windows server, a user named *testuser*, cannot open
this file with such a security descriptor::

    REVISION:0x1
    CONTROL:0x9404
    OWNER:Administrator
    GROUP:Domain Users
    ACL:Administrator:ALLOWED/0x0/FULL

But the user *testuser*, if it becomes part of the *Backup Operators*
group, can open the file with the backup intent.

Any user on the client side who can authenticate as such a user on the
server, can access the files with the backup intent. But it is
desirable and preferable for security reasons amongst many, to
restrict this special right.

The mount option ``backupuid`` is used to restrict this special right
to a user which is specified by either a name or an id. The mount
option ``backupgid`` is used to restrict this special right to the
users in a group which is specified by either a name or an id. Only
users matching either backupuid or backupgid shall attempt to access
files with backup intent. These two mount options can be used
together.

********************************************
FILE AND DIRECTORY OWNERSHIP AND PERMISSIONS
********************************************

The core CIFS protocol does not provide unix ownership information or
mode for files and directories. Because of this, files and directories
will generally appear to be owned by whatever values the ``uid=`` or
``gid=`` options are set, and will have permissions set to the default
``file_mode`` and ``dir_mode`` for the mount. Attempting to change these
values via chmod/chown will return success but have no effect.

When the client and server negotiate unix extensions, files and
directories will be assigned the uid, gid, and mode provided by the
server. Because CIFS mounts are generally single-user, and the same
credentials are used no matter what user accesses the mount, newly
created files and directories will generally be given ownership
corresponding to whatever credentials were used to mount the share.

If the uid's and gid's being used do not match on the client and
server, the ``forceuid`` and ``forcegid`` options may be helpful. Note
however, that there is no corresponding option to override the
mode. Permissions assigned to a file when ``forceuid`` or ``forcegid``
are in effect may not reflect the the real permissions.

When unix extensions are not negotiated, it's also possible to emulate
them locally on the server using the ``dynperm`` mount option. When
this mount option is in effect, newly created files and directories
will receive what appear to be proper permissions. These permissions
are not stored on the server however and can disappear at any time in
the future (subject to the whims of the kernel flushing out the inode
cache). In general, this mount option is discouraged.

It's also possible to override permission checking on the client
altogether via the ``noperm`` option. Server-side permission checks
cannot be overridden. The permission checks done by the server will
always correspond to the credentials used to mount the share, and not
necessarily to the user who is accessing the share.

*********************
ENVIRONMENT VARIABLES
*********************

The variable ``USER`` may contain the username of the person to be used
to authenticate to the server. The variable can be used to set both
username and password by using the format ``username%password``.

The variable ``PASSWD`` may contain the password of the person using
the client.

The variable ``PASSWD_FILE`` may contain the pathname of a file to read
the password from. A single line of input is read and used as the
password.

*****
NOTES
*****

This command may be used only by root, unless installed setuid, in
which case the noexec and nosuid mount flags are enabled. When
installed as a setuid program, the program follows the conventions set
forth by the mount program for user mounts, with the added restriction
that users must be able to chdir() into the mountpoint prior to the
mount in order to be able to mount onto it.

Some samba client tools like smbclient(8) honour client-side
configuration parameters present in *smb.conf*. Unlike those client
tools, ``mount.cifs`` ignores *smb.conf* completely.

*************
CONFIGURATION
*************

The primary mechanism for making configuration changes and for reading
debug information for the cifs vfs is via the Linux /proc
filesystem. In the directory */proc/fs/cifs* are various
configuration files and pseudo files which can display debug
information. There are additional startup options such as maximum
buffer size and number of buffers which only may be set when the
kernel cifs vfs (cifs.ko module) is loaded. These can be seen by
running the ``modinfo`` utility against the file cifs.ko which will
list the options that may be passed to cifs during module installation
(device driver load). For more information see the kernel file
*fs/cifs/README*.

****
BUGS
****

Mounting using the CIFS URL specification is currently not supported.

The credentials file does not handle usernames or passwords with
leading space.

Note that the typical response to a bug report is a suggestion to try
the latest version first. So please try doing that first, and always
include which versions you use of relevant software when reporting
bugs (minimum: mount.cifs (try ``mount.cifs -V``), kernel (see
*/proc/version*) and server type you are trying to contact.

*******
VERSION
*******

This man page is correct for version 1.74 of the cifs vfs filesystem
(roughly Linux kernel 3.0).

********
SEE ALSO
********

cifs.upcall(8), getcifsacl(1), setcifsacl(1)

*Documentation/filesystems/cifs.txt* and *fs/cifs/README* in the
Linux kernel source tree may contain additional options and
information.

******
AUTHOR
******

Steve French

The maintainer of the Linux cifs vfs and the userspace tool mount.cifs
is Steve French. The Linux CIFS Mailing list is the preferred place to
ask questions regarding these programs.
