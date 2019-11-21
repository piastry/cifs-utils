============
smb2-quota
============

-----------------------------------------------------------------------------------------------------
Userspace helper to display quota information for the Linux SMB client file system (CIFS)
-----------------------------------------------------------------------------------------------------
:Manual section: 1

********
SYNOPSIS
********

  smb2-quota [-h] {options} {file system object}

***********
DESCRIPTION
***********

This tool is part of the cifs-utils suite.

`smb2-quota` is a userspace helper program for the Linux SMB
client file system (CIFS).

This tool works by making an CIFS_QUERY_INFO IOCTL call to the Linux
SMB client which in turn issues a SMB Query Info request and returns
the result.

*******
OPTIONS
*******
`--help/-h`: Print help explaining the command line options.

`--tabular/-t`: Print quota information for the volume in tabular format.
Amount Used | Quota Limit | Warning Level | Percent Used | Status | SID

`--csv/-c`: Print quota information for the volume in csv format.
SID,Amount Used,Quota Limit,Warning Level

`--list/-l`: Print quota information for the volume in raw format.
- SID
- Quota Used
- Quota Threshold
- Quota Limit

`--tabular/-t` is the default action if none is given.

*****
NOTES
*****

Kernel support for smb2-quota requires the CIFS_QUERY_INFO
IOCTL which was initially introduced in the 4.20 kernel and is only
implemented for mount points using SMB2 or above (see mount.cifs(8)
`vers` option).

********
SEE ALSO
********

smbinfo(1)

******
AUTHOR
******

Kenneth D'souza <kdsouza@redhat.com>

The Linux CIFS Mailing list is the preferred place to ask questions
regarding these programs.
