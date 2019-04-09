#!/usr/bin/env python
# coding: utf-8

import array
import enum
import fcntl
import os
import struct
import stat
import sys
from Tkinter import *

FULL_CONTROL = 0x001f01ff
EWRITE = 0x00000116
ALL_READ_BITS = 0x00020089
EREAD = 0x001200a9
CHANGE = 0x001301bf

TRAV_EXEC = 0x00100020
LIST_READ = 0x00100001
READ_ATTR = 0x00100080
READ_XATT = 0x00100008
CREA_WRIT = 0x00100002
CREA_APPE = 0x00100004
WRIT_ATTR = 0x00100100
WRIT_XATT = 0x00100010
DELE = 0x00110000
READ_PERM = 0x00120000
CHAN_PERM = 0x00140000
TAKE_OWNR = 0x00180000

class App:
	def __init__(self, root, sd, is_dir):
		self.sd = sd
		self.is_dir = is_dir
		self.tf = Frame(bd=1)
		self.tf.grid(columnspan=5, rowspan=5, padx=5, pady=5)

		# Owner
		Label(self.tf, text='Owner: %s' % (self.sd.owner)).grid(row=0, column=0, columnspan=6, sticky='W')

		# Group
		Label(self.tf, text='Group: %s' % (self.sd.group)).grid(row=1, column=0, columnspan=6, sticky='W')

		self.sb = Scrollbar(self.tf, orient=VERTICAL)
		self.lb = Listbox(self.tf, height=5, selectmode=SINGLE,
				yscrollcommand=self.sb.set)
		self.sb.config(command=self.lb.yview)
		self.sb.grid(row=2, column=1, sticky='NS')
		self.lb.grid(row=2, column=0, sticky='W')

		max = 0
		for idx, item in enumerate(self.sd.dacl.ace):
			if item.type != 0 and item.type != 1:
				continue
			sid = '%s %s' % ("ALLOW" if item.type == 0 else "DENY", item.sid)
			if max > len(sid):
				max = len(sid)
			self.lb.insert(idx, sid)
			if not self.lb.curselection():
				self.lb.selection_set(idx)
		self.lb.config(width=max)
		self.lb.bind("<Double-Button-1>", self.select_sid)

		self.bas = Button(self.tf, text='Basic', relief=SUNKEN,
			command=self.click_bas)
		self.bas.grid(row=2, column=2, sticky='NW')

		self.adv = Button(self.tf, text='Advanced',
			command=self.click_adv)
		self.adv.grid(row=2, column=3, sticky='NW')

		# Basic Panel
		self.bf_bas = Frame(master=self.tf, bd=1)
		self.bf_bas.grid(row=3, column=0, columnspan=4, padx=5, pady=5)
		self.bf_bas_name = Label(self.bf_bas, text='')
		self.bf_bas_name.grid(row=0, column=0, columnspan=2, sticky='W')

		row = 1
		self.bf_bas_fc=Checkbutton(self.bf_bas, text='Full Control')
		self.bf_bas_fc.grid(row=row, column=0, sticky='W')
		self.bf_bas_fc.config(state=DISABLED)
		row += 1

		self.bf_bas_mo=Checkbutton(self.bf_bas, text='Modify')
		self.bf_bas_mo.grid(row=row, column=0, sticky='W')
		self.bf_bas_mo.config(state=DISABLED)
		row += 1

		self.bf_bas_re=Checkbutton(self.bf_bas, text='Read & Execute')
		self.bf_bas_re.grid(row=row, column=0, sticky='W')
		self.bf_bas_re.config(state=DISABLED)
		row += 1

		self.bf_bas_rd=Checkbutton(self.bf_bas, text='Read')
		self.bf_bas_rd.grid(row=row, column=0, sticky='W')
		self.bf_bas_rd.config(state=DISABLED)
		row += 1

		self.bf_bas_wr=Checkbutton(self.bf_bas, text='Write')
		self.bf_bas_wr.grid(row=row, column=0, sticky='W')
		self.bf_bas_wr.config(state=DISABLED)
		row += 1

		self.bf_bas_sp=Checkbutton(self.bf_bas, text='Special')
		self.bf_bas_sp.grid(row=row, column=0, sticky='W')
		self.bf_bas_sp.config(state=DISABLED)
		row += 1

		self.show_bas = True
		self.update_bf_bas()

		# Advanced Panel
		self.bf_adv = Frame(master=self.tf, bd=1)
		self.bf_adv.grid(row=3, column=0, columnspan=4, padx=5, pady=5)
		self.bf_adv_name = Label(self.bf_adv, text='')
		self.bf_adv_name.grid(row=0, column=0, columnspan=2, sticky='W')

		row = 1
		self.bf_adv_fc=Checkbutton(self.bf_adv, text='Full Control')
		self.bf_adv_fc.grid(row=row, column=0, sticky='W')
		self.bf_adv_fc.config(state=DISABLED)
		row += 1

		self.bf_adv_te=Checkbutton(self.bf_adv, text='Traverse-folder/execute-file')
		self.bf_adv_te.grid(row=row, column=0, sticky='W')
		self.bf_adv_te.config(state=DISABLED)
		row += 1

		self.bf_adv_lr=Checkbutton(self.bf_adv, text='List-folder/read-data')
		self.bf_adv_lr.grid(row=row, column=0, sticky='W')
		self.bf_adv_lr.config(state=DISABLED)
		row += 1

		self.bf_adv_ra=Checkbutton(self.bf_adv, text='Read-Attributes')
		self.bf_adv_ra.grid(row=row, column=0, sticky='W')
		self.bf_adv_ra.config(state=DISABLED)
		row += 1

		self.bf_adv_re=Checkbutton(self.bf_adv, text='Read-Extended-Attributes')
		self.bf_adv_re.grid(row=row, column=0, sticky='W')
		self.bf_adv_re.config(state=DISABLED)
		row += 1

		self.bf_adv_cw=Checkbutton(self.bf_adv, text='Create-files/write-data')
		self.bf_adv_cw.grid(row=row, column=0, sticky='W')
		self.bf_adv_cw.config(state=DISABLED)
		row += 1

		self.bf_adv_ca=Checkbutton(self.bf_adv, text='Create-folders/append-data')
		self.bf_adv_ca.grid(row=row, column=0, sticky='W')
		self.bf_adv_ca.config(state=DISABLED)
		row += 1

		row = 1
		self.bf_adv_wa=Checkbutton(self.bf_adv, text='Write-Attributes')
		self.bf_adv_wa.grid(row=row, column=1, sticky='W')
		self.bf_adv_wa.config(state=DISABLED)
		row += 1

		self.bf_adv_we=Checkbutton(self.bf_adv, text='Write-Extended-Attributes')
		self.bf_adv_we.grid(row=row, column=1, sticky='W')
		self.bf_adv_we.config(state=DISABLED)
		row += 1

		self.bf_adv_de=Checkbutton(self.bf_adv, text='Delete')
		self.bf_adv_de.grid(row=row, column=1, sticky='W')
		self.bf_adv_de.config(state=DISABLED)
		row += 1

		self.bf_adv_rp=Checkbutton(self.bf_adv, text='Read-Permissions')
		self.bf_adv_rp.grid(row=row, column=1, sticky='W')
		self.bf_adv_rp.config(state=DISABLED)
		row += 1

		self.bf_adv_cp=Checkbutton(self.bf_adv, text='Change-Permissions')
		self.bf_adv_cp.grid(row=row, column=1, sticky='W')
		self.bf_adv_cp.config(state=DISABLED)
		row += 1

		self.bf_adv_to=Checkbutton(self.bf_adv, text='Take-Ownership')
		self.bf_adv_to.grid(row=row, column=1, sticky='W')
		self.bf_adv_to.config(state=DISABLED)
		row += 1

		self.bf_adv.grid_remove()

	def select_sid(self, event):
		self.click_bas()

	def click_bas(self):
		self.adv.config(relief=RAISED)
		self.bas.config(relief=SUNKEN)
		self.bf_adv.grid_remove()
		self.update_bf_bas()
		self.bf_bas.grid()
		self.show_bas = True

	def click_adv(self):
		self.adv.config(relief=SUNKEN)
		self.bas.config(relief=RAISED)
		self.bf_bas.grid_remove()
		self.update_bf_adv()
		self.bf_adv.grid()
		self.show_bas = False

	def update_bf_adv(self):
		ace = self.sd.dacl.ace[self.lb.curselection()[0]]
		self.bf_adv_name.config(text='Advanced Permissions for %s' % (ace.sid))
		if ace.mask == FULL_CONTROL:
			self.bf_adv_fc.select()
		else:
			self.bf_adv_fc.deselect()
		if ace.mask & TRAV_EXEC == TRAV_EXEC:
			self.bf_adv_te.select()
		else:
			self.bf_adv_te.deselect()
		if ace.mask & LIST_READ == LIST_READ:
			self.bf_adv_lr.select()
		else:
			self.bf_adv_lr.deselect()
		if ace.mask & READ_ATTR == READ_ATTR:
			self.bf_adv_ra.select()
		else:
			self.bf_adv_ra.deselect()
		if ace.mask & READ_XATT == READ_XATT:
			self.bf_adv_re.select()
		else:
			self.bf_adv_re.deselect()
		if ace.mask & CREA_WRIT == CREA_WRIT:
			self.bf_adv_cw.select()
		else:
			self.bf_adv_cw.deselect()
		if ace.mask & CREA_APPE == CREA_APPE:
			self.bf_adv_ca.select()
		else:
			self.bf_adv_ca.deselect()
		if ace.mask & WRIT_ATTR == WRIT_ATTR:
			self.bf_adv_wa.select()
		else:
			self.bf_adv_wa.deselect()
		if ace.mask & WRIT_XATT == WRIT_XATT:
			self.bf_adv_we.select()
		else:
			self.bf_adv_we.deselect()
		if ace.mask & DELE == DELE:
			self.bf_adv_de.select()
		else:
			self.bf_adv_de.deselect()
		if ace.mask & READ_PERM == READ_PERM:
			self.bf_adv_rp.select()
		else:
			self.bf_adv_rp.deselect()
		if ace.mask & CHAN_PERM == CHAN_PERM:
			self.bf_adv_rp.select()
		else:
			self.bf_adv_rp.deselect()
		if ace.mask & TAKE_OWNR == TAKE_OWNR:
			self.bf_adv_to.select()
		else:
			self.bf_adv_to.deselect()

	def update_bf_bas(self):
		ace = self.sd.dacl.ace[self.lb.curselection()[0]]
		self.bf_bas_name.config(text='Permissions for %s' % (ace.sid))
		tmp = ace.mask
		if ace.mask == FULL_CONTROL:
			self.bf_bas_fc.select()
			tmp &= ~FULL_CONTROL
		else:
			self.bf_bas_fc.deselect()
		if ace.mask & CHANGE == CHANGE:
			self.bf_bas_mo.select()
			tmp &= ~CHANGE
		else:
			self.bf_bas_mo.deselect()
		if ace.mask & EREAD == EREAD:
			self.bf_bas_re.select()
			tmp &= ~EREAD
		else:
			self.bf_bas_re.deselect()
		if ace.mask & ALL_READ_BITS == ALL_READ_BITS:
			self.bf_bas_rd.select()
			tmp &= ~ALL_READ_BITS
		else:
			self.bf_bas_rd.deselect()
		if ace.mask & EWRITE == EWRITE:
			self.bf_bas_wr.select()
			tmp &= ~EWRITE
		else:
			self.bf_bas_wr.deselect()
		if tmp:
			self.bf_bas_sp.select()
		else:
			self.bf_bas_sp.deselect()

CIFS_QUERY_INFO = 0xc018cf07

def usage():
	print "Usage: %s <filename>" % (sys.argv[0])
	sys.exit()


class SID:
	'''
	SID implements a Windows Security Identifier as per MS-DTYP:2.4.2.
	'''
	def __init__(self, buf):
		self.sub_authority_count = buf[1]
		self.buffer = buf[:8 + self.sub_authority_count * 4]
		self.revision = self.buffer[0]
		if self.revision != 1:
			raise ValueError('SID Revision %d not supported' %
					 (self.revision))
		self.identifier_authority = 0
		for x in self.buffer[2:8]:
			self.identifier_authority = self.identifier_authority * 256 + x
		self.sub_authority = []
		for i in range(self.sub_authority_count):
			self.sub_authority.append(struct.unpack_from('<I', self.buffer, 8 + 4 * i)[0])

	def __str__(self):
		s = "S-%u-%u" % (self.revision, self.identifier_authority)

		for x in self.sub_authority:
			s += '-%u' % x
		return s


class ACE:
	'''
	ACE implements a Windows ACE as per MS-DTYP:2.4.4.
	'''
	def __init__(self, buf):
		self.type = buf[0]
		self.flags = buf[1]
		self.size = struct.unpack_from('<H', buf, 2)[0]
		self.raw = buf[:self.size]
		if self.type in [0, 1]:
			self.mask = struct.unpack_from('<I', buf, 4)[0]
			self.sid = SID(buf[8:])

	def __str__(self):
		s = 'Type:0x%02x ' % (self.type)
		s += 'Flags:0x%02x ' % (self.flags)
		if self.type in [0, 1]:
			s += 'Mask:0x%02x SID:%s' % (self.mask, self.sid)
		else:
			for i in self.raw[4:]:
				s += '%02x' % (i)

		return s

	class Type(enum.Enum):
		ALLOWED = 0
		DENIED = 1

		def __str__(self):
			return self.name


class ACL:
	'''
	ACL implements a Windows ACL as per MS-DTYP:2.4.5.
	'''
	def __init__(self, buf):
		self.revision = buf[0]
		if self.revision != 2 and self.revision != 4:
			raise ValueError('ACL Revision %d '
					 'not supported' % (self.revision))
		acl = buf[8:8 + struct.unpack_from('<H', buf, 2)[0]]
		self.ace = []
		for i in range(struct.unpack_from('<H', buf, 4)[0]):
			ace = ACE(acl)
			self.ace.append(ace)
			acl = acl[ace.size:]

	def __str__(self):
		s = 'Revision:0x%02x\n' % (self.revision)
		for ace in self.ace:
			s += '%s\n' % (ace)
		return s


class SecurityDescriptor:
	'''
	SecurityDescriptor implements a Windows Security Descriptor as per
	MS-DTYP:2.4.6.
	'''
	def __init__(self, buf):
		self.revision = buf[0]
		if self.revision != 1:
			raise ValueError('Security Descriptor Revision %d '
					 'not supported' % (self.revision))
		self.control = struct.unpack_from('<H', buf, 2)

		self.owner = SID(buf[struct.unpack_from('<I', buf, 4)[0]:])
		self.group = SID(buf[struct.unpack_from('<I', buf, 8)[0]:])

		self.dacl = ACL(buf[struct.unpack_from('<I', buf, 16)[0]:])

	def __str__(self):
		s = 'Revision:%u\n' % (self.revision)
		s += 'Control:0x%04x\n' % (self.control)
		s += 'Owner:%s\n' % (self.owner)
		s += 'Group:%s\n' % (self.group)
		s += 'DACL:\n%s' % (self.dacl)
		return s


def main():
	if len(sys.argv) != 2:
		usage()

	buf = array.array('B', [0] * 16384)

	struct.pack_into('<I', buf, 0, 3) # InfoType: Security
	struct.pack_into('<I', buf, 8, 7) # AddInfo: Group/Owner/Dacl
	struct.pack_into('<I', buf, 16, 16384) # InputBufferLength

	f = os.open(sys.argv[1], os.O_RDONLY)
	st = os.fstat(f)
	fcntl.ioctl(f, CIFS_QUERY_INFO, buf, 1)
	os.close(f)

	s = struct.unpack_from('<I', buf, 16)

	sd = SecurityDescriptor(buf[24:24 + s[0]])

	root = Tk()
	app = App(root, sd, stat.S_ISDIR(st.st_mode))
	root.mainloop()


if __name__ == "__main__":
	main()
