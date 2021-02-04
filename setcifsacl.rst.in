==========
setcifsacl
==========

-------------------------------------------------------------------------------------------------------------------
Userspace helper to alter components of a security descriptor for Common Internet File System (CIFS)
-------------------------------------------------------------------------------------------------------------------
:Manual section: 1

********
SYNOPSIS
********

  setcifsacl [-v|-U|-a|-A|-D|-M|-S|-o|-g] "{one or more ACEs or a SID}" {file system object}

***********
DESCRIPTION
***********

This tool is part of the cifs-utils suite.

``setcifsacl`` is a userspace helper program for the Linux CIFS client
file system. It is intended to alter an ACL or set owner/group SID of a security descriptor
for a file system object. Whether a security descriptor to be set is
applied or not is determined by the CIFS/SMB server.

This program uses a plugin to handle the mapping of user and group
names to SIDs. *@pluginpath@* should be a symlink that points to the
correct plugin to use.

*******
OPTIONS
*******

-h
  Print usage message and exit.

-v
  Print version number and exit.

-U
  Apply ACE editing actions (-a, -D, -M, -S) to SACL (aUdit ACL). The actions are
  appliend to DACL if -U is not specified.

-a
  Add one or more ACEs to an ACL of a security descriptor.  An ACE is
  added even if the same ACE exists in the ACL.

-A
  Add one or more ACEs to the ACL of a security descriptor, while maintaining
  the preferred order of the ACEs.
  The preferred order of ACEs are described in the following documentation:
  https://docs.microsoft.com/en-us/windows/win32/secauthz/order-of-aces-in-a-dacl

-D
 Delete one or more ACEs from an ACL of a security descriptor.  Entire
 ACE has to match in an existing ACL for the listed ACEs to be deleted.

-M
  Modify one or more ACEs from an ACL of a security descriptor.  SID and
  type are used to match for existing ACEs to be modified with the list
  of ACEs specified.

-S
  Set an ACL of security descriptor with the list of ACEs Existing ACL
  is replaced entirely with the specified ACEs.

-o
  Set owner SID to one specified as a command line argument.

-g
  Set group SID to one specified as a command line argument.

  The owner/group SID can be specified as a name or a raw SID value.
  Every ACE entry starts with "ACL:" One or more ACEs are specified
  within double quotes.  Multiple ACEs are separated by a comma.

  Following fields of a DACL ACE can be modified with possible values:

  - ``SID`` - Either a name or a raw SID value.
  - ``type`` - ALLOWED (0x0), DENIED (0x1), OBJECT_ALLOWED (0x5), OBJECT_DENIED (0x6)
  - ``flags`` - OBJECT_INHERIT_FLAG (OI or 0x1),
    CONTAINER_INHERIT_FLAG (CI or 0x2), NO_PROPAGATE_INHERIT_FLAG (NI
    or 0x4), INHERIT_ONLY_FLAG (IO or 0x8), INHERITED_ACE_FLAG (IA or
    0x10) or a combination/OR of these values.
  - ``mask``  - Either one of FULL, CHANGE, READ, a combination of R W X D P O, or a hex value.

  Following fields of a SACL ACE can be modified with possible values:

  - ``SID`` - Either a name or a raw SID value.
  - ``type`` - AUDIT (0x2), AUDIT_OBJECT (0x7), AUDIT_CALLBACK (0xD), AUDIT_CALLBACK_OBJECT (0xF),
    MANDATORY_LABEL (0x11), RESOURCE_ATTRIBUTE (0x12), SCOPED_POLICY_ID (0x13)
  - ``flags`` - SUCCESSFULL_ACCESS (SA or 0x40), FAILED_ACCESS (FA or 0x80)
  - ``mask``  - Either one of FULL, CHANGE, READ, a combination of R W X D P O, or a hex value.

********
EXAMPLES
********

Add an ACE
==========

  setcifsacl -a "ACL:CIFSTESTDOM\\user2:DENIED/0x1/D" <file_name>

  setcifsacl -a "ACL:CIFSTESTDOM\\user1:ALLOWED/OI|CI|NI/D" <file_name>

  setcifsacl -U -a "ACL:CIFSTESTDOM\\user1:AUDIT/SA/D" <file_name>

Add an ACE and reorder ACL
==========================

  setcifsacl -A "ACL:CIFSTESTDOM\user3:ALLOWED/OI/FULL" <file_name>
  setcifsacl -A "ACL:CIFSTESTDOM\user2:DENIED/0x1/D" <file_name>
  setcifsacl -A "ACL:CIFSTESTDOM\user1:ALLOWED/OI|CI|NI/D" <file_name>

  After setting above mentioned ACEs, below is output of getcifsacl:
  ACL:CIFSTESTDOM\user2:DENIED/0x1/D
  ACL:CIFSTESTDOM\user3:ALLOWED/OI/FULL
  ACL:CIFSTESTDOM\user1:ALLOWED/OI|CI|NI/D

Delete an ACE
=============

  setcifsacl -D "ACL:S-1-1-0:0x1/OI/0x1201ff" <file_name>

  setcifsacl -U -D "ACL:S-1-1-0:0x2/FA/0xf01ff" <file_name>

Modify an ACE
=============

  setcifsacl -M "ACL:CIFSTESTDOM\\user1:ALLOWED/0x1f/CHANGE" <file_name>

  setcifsacl -U -M "ACL:CIFSTESTDOM\\user1:AUDIT_OBJECT/SA/CHANGE" <file_name>

Set an ACL
==========

  setcifsacl -S "ACL:CIFSTESTDOM\\Administrator:0x0/0x0/FULL,ACL:CIFSTESTDOM\\user2:0x0/0x0/FULL" <file_name>

  setcifsacl -U -S "ACL:CIFSTESTDOM\\Administrator:AUDIT/SA/FULL,ACL:CIFSTESTDOM\\user2:0x7/0x80/FULL" <file_name>

Set owner SID
=============

  setcifsacl -o "S-1-5-21-3338130290-3403600371-1423429424-2102" <file_name>

Set group SID
=============

  setcifsacl -g "Administrators@BUILTIN" <file_name>

*****
NOTES
*****

Kernel support for getcifsacl/setcifsacl utilities was initially
introduced in the 2.6.37 kernel.

********
SEE ALSO
********

mount.cifs(8), getcifsacl(1)

******
AUTHOR
******

Shirish Pargaonkar wrote the setcifsacl program.

The Linux CIFS Mailing list is the preferred place to ask questions
regarding these programs.
