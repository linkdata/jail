#!/usr/bin/python
"""Shadow filesystem.

Caches os.lstat() and allows file metadata changes in
the shadowed and actual filesystems.
"""

__copyright__ = "Copyright \302\251 2012 Johan Lindh"
__license__ = "GPL"
__author__ = "Johan Lindh <johan@linkdata.se>"

import sys, os, stat, errno, time, pwd, grp

def default_readable_fn(path, command_text):
	if command_text:
		print >> sys.stderr, command_text
	return True

def default_writable_fn(path, command_text):
	if command_text:
		print >> sys.stderr, '# {0!r} ({1!r})'.format(command_text, path)
	return False

class Stat(object):
	"""Shadowed filesystem node. Caches os.lstat(). Manipulates metadata.

	Also acts as a node for the shadowed directory tree, with links
	to it's parent node and, if it is directory, to child nodes.
	"""
	_st_attr = (
		'st_mode', 'st_ino', 'st_dev', 'st_nlink',
		'st_uid', 'st_gid', 'st_size',
		'st_atime', 'st_mtime', 'st_ctime',
		'st_blocks', 'st_blksize', 'st_rdev',
		'st_flags'
		)
	_st_fmtname = {
		0: 'none',
		stat.S_IFREG: 'file',
		stat.S_IFDIR: 'dir',
		stat.S_IFLNK: 'link',
		stat.S_IFCHR: 'chrdev',
		stat.S_IFBLK: 'blkdev',
		stat.S_IFIFO: 'fifo',
		stat.S_IFSOCK: 'sock'
		}
	_utimeformat = '%Y%m%d%H%M.%S'
	_execbits = stat.S_IXOTH | stat.S_IXGRP | stat.S_IXUSR
	__slots__ = ('_root', '_parent', '_name', '_children', '_link') + _st_attr
	_count_statcalls = 0
	_count_accesses = 0
	_os_chown = os.lchown if hasattr(os, 'lchown') else os.chown
	readable = default_readable_fn
	writable = default_writable_fn

	@classmethod
	def os_lstat(cls, path):
		cls._count_statcalls += 1
		try:
			return os.lstat(path)
		except OSError as err:
			if err.errno != errno.ENOENT:
				raise
		return None

	@classmethod
	def count_statcalls(cls):
		return cls._count_statcalls

	@classmethod
	def count_accesses(cls):
		return cls._count_accesses

	@classmethod
	def readable_fn(cls, fn=None):
		if fn is not None:
			cls.readable = fn
		return cls.readable

	@classmethod
	def writable_fn(cls, fn=None):
		if fn is not None:
			cls.writable = fn
		return cls.writable

	def __init__(self, parent, name='', data=None):
		assert parent is None or isinstance(parent, Stat)
		assert '/' not in name
		self._parent = parent
		self._name = name
		self._children = dict()
		self._link = None
		self.st_mode = 0
		self.st_ino = 0
		self.st_dev = 0
		self.st_nlink = 0
		self.st_uid = os.geteuid()
		self.st_gid = os.getegid()
		self.st_size = 0
		self.st_atime = time.time()
		self.st_mtime = self.st_atime
		self.st_ctime = self.st_atime
		self.st_blocks = 0
		self.st_blksize = 0
		self.st_rdev = 0
		self.st_flags = 0
		if self._parent is not None:
			assert self._name
			assert self._name not in self._parent._children
			self._parent._children[self._name] = self
		if isinstance(data, int):
			self.st_mode = data
		else:
			self.refresh(data)
		return

	def clear(self):
		for child in self._children.itervalues():
			child._parent = None
		self._children.clear()
		self._parent = None
		self._link = None
		self._name = None
		for k in self._st_attr:
			setattr(self, k, 0)
		return

	def count_instances(self):
		total = 1
		for child in self._children.itervalues():
			total += child.count_instances()
		return total

	def hitratio(self):
		misspercentage = 0 if not self._count_accesses else \
			(100.0 * self._count_statcalls) / self._count_accesses
		return 100 - misspercentage

	def get(self, path='', root=None, links=None):
		root = self.root() if root is None else root
		links = set() if links is None else links
		node = root if path.startswith('/') else self
		Stat._count_accesses += 1
		for name in path.split('/'):
			# print '# get: node {0!r} name {1!r} root {2!r} links {3!r}'.format(node, name, root, links)
			if node is None:
				break
			if node._link:
				assert node.islnk()
				assert node._parent is not None
				if node in links:
					raise ValueError('{0!r}: recursive symlink, {1!r} unreachable'.format(node, path))
				links.add(node)
				node = node._parent.get(node._link, root, links)
				if node is None:
					break
			if not name or name == '.':
				pass
			elif name in node._children:
				node = node._children[name]
			elif name == '..':
				if node is not root:
					node = node._parent
			else:
				st_data = node.os_lstat(os.path.join(node.path, name))
				node = Stat(node, name, st_data) if st_data else None
		# print '### {0!r} get({1!r}) -> {2!r}'.format(self, path, node)
		return node

	def getdefault(self, path, fmt, root=None, links=None):
		path = '' if path is None else path
		root = self.root() if root is None else root
		links = set() if links is None else links
		(head, tail) = os.path.split(path)
		headstat = self.get(head, root, links)
		if headstat is not None and headstat.islnk():
			headstat = headstat.get('', root, links)
		if headstat is None:
			raise ValueError('{0!r}: missing {1!r}'.format(self, head))
		if tail:
			node = headstat.get(tail, root, links)
			if node is None:
				node = Stat(headstat, tail, fmt)
		else:
			node = headstat
		if fmt and node.fmt() != fmt:
			raise ValueError('{0!r}: expected {1}'.format(node, self.mode_fmtstr(fmt)))
		return node

	def lstat(self, path, fmt=None):
		return self.get(path, self) if fmt is None else self.getdefault(path, fmt, self)

	def stat(self, path, fmt=None):
		links = set()
		node = self.get(path, self, links) if fmt is None else \
			self.getdefault(path, fmt, self, links)
		return None if node is None else node.get('', self, links)

	@property
	def name(self):
		return self._name

	def root(self):
		node = self
		while node._parent is not None:
			node = node._parent
		return node

	@property
	def parent(self):
		return self._parent

	@property
	def path(self):
		node = self
		path = self._name
		while node._parent is not None:
			node = node._parent
			path = node._name + '/' + path
		if not path.startswith('/'):
			path = '/' + path
		# print '#', repr(self._name), 'path:', repr(path)
		return path

	def refresh(self, st_data=None):
		if st_data is None:
			st_data = self.os_lstat(self.path)
		if st_data:
			for key in self._st_attr:
				try:
					value = getattr(st_data, key)
				except AttributeError:
					value = 0
				setattr(self, key, value)
			self._link = os.readlink(self.path) if self.islnk() else None
		return self

	def checkcache(self):
		checklist = ('_link', 'st_mode', 'st_uid', 'st_gid', 'st_rdev')
		if not (self.isdir() or self.islnk()):
			checklist = checklist + ('st_size', 'st_mtime')
		oldattr = dict(((k, getattr(self, k)) for k in checklist))
		if os.path.exists(self.path):
			self.refresh()
		diff = list()
		for k in checklist:
			v = getattr(self, k)
			if isinstance(v, float):
				if abs(v - oldattr[k]) > 0.5:
					diff.append(k + ': ' + str(oldattr[k]) + ' != ' + str(v))
			elif isinstance(v, int):
				if v != oldattr[k]:
					diff.append(k + ': ' + oct(oldattr[k]) + ' != ' + oct(v))
			else:
				if v != oldattr[k]:
					diff.append(k + ': ' + repr(oldattr[k]) + ' != ' + repr(v))
		if diff:
			raise ValueError(repr(self) + ' mismatch vs disk: ' + ', '.join(d for d in diff))
		return True

	def __nonzero__(self):
		return bool(self.st_ino or self.mode())

	def __cmp__(self, other):
		if not self:
			return 1 if other else 0
		elif not other:
			return -1
		diff = self.mode() - other.mode()
		diff = diff or (self.st_uid - other.st_uid)
		diff = diff or (self.st_gid - other.st_gid)
		diff = diff or (self.st_size - other.st_size)
		if not diff:
			if self.islnk():
				if self.readlink() < other.readlink():
					diff = -1
				elif self.readlink() > other.readlink():
					diff = 1
				else:
					diff = 0
			else:
				diff = self.st_mtime - other.st_mtime
				diff = diff if abs(diff) > 0.5 else 0
		return -1 if diff < 0 else 1 if diff > 0 else 0

	def __str__(self):
		return self.path

	def __repr__(self):
		if self.mode():
			return '<{0} {1!r} {2:o} {3}:{4} {5}>'.format(
				self.fmtstr(), self.path,
				self.mode(), self.st_uid, self.st_gid,
				self.st_size
				)
		return '<' + self.fmtstr() + ' ' + repr(self.path) + '>'

	def mode(self):
		return stat.S_IMODE(self.st_mode)
	def fmt(self):
		return stat.S_IFMT(self.st_mode)
	def isdir(self):
		return self.fmt() == stat.S_IFDIR
	def ischr(self):
		return self.fmt() == stat.S_IFCHR
	def isblk(self):
		return self.fmt() == stat.S_IFBLK
	def isreg(self):
		return self.fmt() == stat.S_IFREG
	def isfifo(self):
		return self.fmt() == stat.S_IFIFO
	def islnk(self):
		return self.fmt() == stat.S_IFLNK
	def issock(self):
		return self.fmt() == stat.S_IFSOCK
	def isexecutable(self):
		return self.isreg() and (self.st_mode & self._execbits)
	def fmtstr(self):
		return self.mode_fmtstr(self.st_mode)
	def readlink(self):
		return self._link

	@staticmethod
	def mode_fmtstr(mode):
		fmt = stat.S_IFMT(mode)
		return Stat._st_fmtname.get(fmt, oct(fmt))

	def read_call(self, cmd, func, *args):
		if self.readable(self.path, cmd):
			try:
				return func(*args)
			except (OSError) as err:
				err.strerror = cmd + ': ' + err.strerror
				raise
		return

	def write_call(self, cmd, func, *args):
		if self.writable(self.path, cmd):
			try:
				return func(*args)
			except (OSError) as err:
				err.strerror = cmd + ': ' + err.strerror
				raise
		return

	def listdir(self, path=None):
		node = self if path is None else self.stat(path)
		try:
			entries = set(os.listdir(node.path))
		except OSError, err:
			if err.errno != errno.ENOENT:
				raise
			entries = set()
		entries.update(node._children.iterkeys())
		return sorted(entries)

	def symlink(self, target, path=None):
		dststat = self if path is None else self.getdefault(path, stat.S_IFLNK)
		if not dststat or dststat._link != target:
			cmd = 'ln -sf {0!r} {1!r}'.format(target, dststat.path)
			dststat.write_call(cmd, os.symlink, target, dststat.path)
			dststat.st_mode = stat.S_IFLNK | 0o777
			dststat.st_size = len(target)
			dststat._link = target
		return dststat

	def mkdir(self, path, mode=0750, uid=None, gid=None):
		dststat = self.getdefault(path, stat.S_IFDIR)
		mode = stat.S_IMODE(mode)
		if not dststat:
			cmd = 'mkdir -m {0:o} {1!r}'.format(mode, dststat.path)
			dststat.write_call(cmd, os.mkdir, dststat.path, mode)
			dststat.st_mode = dststat.fmt() | mode
		elif dststat.isdir():
			dststat.chmod(mode)
		else:
			raise ValueError(repr(dststat) + ': expected dir')
		dststat.chown(uid, gid)
		return dststat

	def makedirs(self, path, mode=None, root=None, links=None):
		mode = 0o750 if mode is None else stat.S_IMODE(mode)
		root = self.root() if root is None else root
		links = set() if links is None else links
		node = root if path.startswith('/') else self
		for name in filter(None, path.split('/')):
			child = node.get(name, root, links)
			if child is None:
				child = node.mkdir(name, mode)
			node = child
		return node

	def mknod(self, path, mode, device):
		dststat = self.getdefault(path, stat.S_IFMT(mode))
		if not dststat:
			cmd = 'mknod -m {0:o} {1!r} {2} {3} {4}'.format(
				stat.S_IMODE(mode), dststat.path,
				'c' if stat.S_ISCHR(mode) else 'b' if stat.S_ISBLK(mode) else '?',
				os.major(device), os.minor(device))
			dststat.write_call(cmd, os.mknod, dststat.path, mode, device)
			dststat.st_mode = mode
			dststat.st_rdev = device
		else:
			assert dststat.fmt() == stat.S_IFMT(mode)
			assert dststat.st_rdev == device
			dststat.chmod(mode)
		return dststat

	def copydata(self, dststat):
		if self is dststat:
			return
		byteswritten = 0
		with open(self.path, 'rb') as fsrc:
			with open(dststat.path, 'wb') as fdst:
				while 1:
					buf = fsrc.read(16384)
					if not buf:
						break
					fdst.write(buf)
					byteswritten += len(buf)
		return byteswritten

	def copy2(self, dststat):
		if self is dststat:
			return
		if not self.isreg():
			raise ValueError(cmd + ': source is ' + self.fmtstr())
		if dststat and not dststat.isreg():
			raise ValueError(cmd + ': target is ' + dststat.fmtstr())
		cmd = 'cp -p ' + self.path + ' ' + dststat.path
		dststat.st_size = self.st_size
		dststat.st_uid = self.st_uid
		dststat.st_gid = self.st_gid
		dststat.st_flags = self.st_flags
		dststat.st_mode = self.st_mode
		dststat.st_atime = self.st_atime
		dststat.st_mtime = self.st_mtime
		if dststat.write_call(cmd, self.copydata, dststat):
			self._os_chown(dststat.path, self.st_uid, self.st_gid)
			os.chmod(dststat.path, self.st_mode)
			if hasattr(os, 'chflags'):
				os.chflags(dststat.path, self.st_flags)
			os.utime(dststat.path, (self.st_atime, self.st_mtime))
			dststat.checkcache()
		return dststat

	def cp_p(self, srcpath, dstpath):
		srcstat = self.get(srcpath)
		dststat = self.getdefault(dstpath, srcstat.fmt())
		srcstat.copy2(dststat)
		return dststat

	def remove(self):
		assert not self.isdir()
		cmd = 'rm -f {0!r}'.format(self.path)
		self.write_call(cmd, os.remove, self.path)
		self.clear()
		return

	def rmdir(self):
		assert self.isdir()
		cmd = 'rmdir {0!r}'.format(self.path)
		self.write_call(cmd, os.rmdir, self.path)
		self.clear()
		return

	def rm_rf(self, dstpath=''):
		dststat = self.get(dstpath)
		if dststat:
			if dststat.isdir():
				assert dststat.path.count('/') > 2
				for name in dststat.listdir():
					dststat.rm_rf(name)
				dststat.rmdir()
			else:
				dststat.remove()
		return

	def chown(self, uid, gid):
		uid = self.st_uid if uid < 0 else uid
		gid = self.st_gid if gid < 0 else gid
		if uid != self.st_uid or gid != self.st_gid:
			cmd = 'chown ' + \
				(str(uid) if uid != self.st_uid else '') + \
				(':' + str(gid) if gid != self.st_gid else '') + \
				' ' + repr(self.path)
			self.write_call(cmd, self._os_chown, self.path, uid, gid)
			self.st_uid = uid
			self.st_gid = gid
		return self

	def chmod(self, mode):
		mode = stat.S_IMODE(mode)
		if self.mode() != mode:
			cmd = 'chmod ' + oct(mode) + ' ' + repr(self.path)
			self.write_call(cmd, os.chmod, self.path, mode)
			self.st_mode = self.fmt() | mode
		return self

	def utime(self, mtime=None):
		if mtime is None:
			mtime = time.time()
		elif isinstance(mtime, str):
			mtime = time.mktime(time.strptime(mtime, self._utimeformat))
		if abs(mtime - self.st_mtime) < 0.5:
			return
		if hasattr(os, 'utime'):
			cmd = 'touch -m -t ' + \
				time.strftime(self._utimeformat, time.localtime(mtime)) + \
				' ' + repr(self.path)
			self.write_call(cmd, os.utime, self.path, (mtime, mtime))
		self.st_atime = mtime
		self.st_mtime = mtime
		return self

	def chflags(self, flags):
		flags = int(flags, 0) if isinstance(flags, str) else flags
		if self.st_flags == flags:
			return
		if hasattr(os, 'chflags'):
			cmd = 'chflags ' + oct(flags) + ' ' + repr(self.path)
			self.write_call(cmd, os.chflags, self.path, flags)
		self.st_flags = flags
		return self

	def samefile(self, other):
		return self is other

	def chroot(self, path=None):
		dststat = self.get(path)
		cmd = 'chroot {0!r}'.format(dststat.path)
		dststat._root = True
		dststat.write_call(cmd, os.chroot, dststat.path)
		return dststat

	def chdir(self, path=None):
		dststat = self.get(path)
		cmd = 'cd {0!r}'.format(dststat.path)
		dststat.write_call(cmd, os.chdir, dststat.path)
		return dststat

	@classmethod
	def getgroups(cls, uid):
		username = pwd.getpwuid(uid).pw_name
		group_list = [group.gr_gid for group in grp.getgrall()
			if username in group.gr_mem]
		return group_list

	@classmethod
	def setgroups(cls, group_list):
		cmd = 'setgroups ' + ', '.join(
			(grp.getgrgid(group).gr_name for group in group_list))
		if cls.writable(None, cmd):
			os.setgroups(list(group_list))
		return

	@classmethod
	def setgid(cls, gid):
		if gid < 1 or gid == os.getegid():
			return
		cmd = 'sg ' + grp.getgrgid(gid).gr_name
		if cls.writable(None, cmd):
			os.setgid(gid)
		return

	@classmethod
	def setuid(cls, uid):
		if uid < 1 or uid == os.geteuid():
			return
		cmd = 'su ' + pwd.getpwuid(uid).pw_name
		if cls.writable(None, cmd):
			os.setuid(uid)
		return

	@classmethod
	def umask(cls, mask):
		cmd = 'umask ' + oct(mask)
		if cls.writable(None, cmd):
			os.umask(mask)
		return

	@classmethod
	def execve(cls, program, args, environ):
		cmd = 'env -i ' + \
			' '.join(k + '=' + repr(v) for k, v in environ.iteritems()) + \
			' ' + ' '.join(((repr(a) if ' ' in a else a) for a in args))
		if cls.writable(None, cmd):
			os.execve(program, args, environ)
		return
