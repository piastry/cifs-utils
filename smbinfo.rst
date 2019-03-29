============
smbinfo
============

-----------------------------------------------------------------------------------------------------
Userspace helper to display SMB-specific file information for the Linux SMB client file system (CIFS)
-----------------------------------------------------------------------------------------------------
:Manual section: 1

********
SYNOPSIS
********

  smbinfo [-v] [-V] {command} {file system object}

***********
DESCRIPTION
***********

This tool is part of the cifs-utils suite.

`smbinfo` is a userspace helper program for the Linux SMB
client file system (CIFS). It is intended to display SMB-specific file
informations such as Security Descriptors and Quota.

This tool works by making an CIFS_QUERY_INFO IOCTL call to the Linux
SMB client which in turn issues a SMB Query Info request and returns
the result. This differs from `getcifsacl` which uses extended file
attributes.

*******
OPTIONS
*******

-v
  Print version number and exit.

-V
  Verbose output.

*******
COMMAND
*******

`fileaccessinfo`: Prints the FileAccessInformation class

`filealigninfo`: Prints the FileAlignmentInformation class

`fileallinfo`: Prints the FileAllInformation class

`filebasicinfo`: Prints the FileBasicInformation class

`fileeainfo`: Prints the FileEaInformation class

`filefsfullsizeinfo`: Prints the FileFsFullSizeInformation class

`fileinternalinfo`: Prints the FileInternalInformation class

`filemodeinfo`: Prints the FileModeInformation class

`filepositioninfo`: Prints the FilePositionInformation class

`filestandardinfo`: Prints the FileStandardInformation class

`fsctl-getobjid`: Prints the ObjectID

`list-snapshots`: Lists the previous versions of the volume that backs this file

`quota`: Print the quota for the volume in the form
- SID Length
- Change Time
- Quota Used
- Quota Threshold
- Quota Limit
- SID

`secdesc`: Print the security descriptor in the form
- Revision
- Control
- Owner SID
- Group SID
- ACL
- File types
- File flags

*****
NOTES
*****

Kernel support for smbinfo utilities requires the CIFS_QUERY_INFO
IOCTL which was initially introduced in the 4.20 kernel and is only
implemented for mount points using SMB2 or above (see mount.cifs(8)
`vers` option).

********
SEE ALSO
********

mount.cifs(8), getcifsacl(1)

******
AUTHOR
******

Ronnie Sahlberg wrote the smbinfo program.

The Linux CIFS Mailing list is the preferred place to ask questions
regarding these programs.
