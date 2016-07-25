#!/usr/bin/python

__copyright__ = "Copyright \302\251 2012 Johan Lindh"
__license__ = "MIT"
__author__ = "Johan Lindh <johan@linkdata.se>"

import os, sys, subprocess, errno, stat, re, pwd, grp, time
import cli, sfs

JAILBASE  = os.getenv('JAILBASE', 'jailbase')
JAILTMP	  = os.path.abspath(os.getenv('JAILTMP',   '/tmp/' + JAILBASE))
JAILHOME  = os.path.abspath(os.getenv('JAILHOME',  '/var/' + JAILBASE))
JAILMOUNT = os.path.abspath(os.getenv('JAILMOUNT', '/mnt/' + JAILBASE))

class JailError(cli.CommandLineError):
	pass

class JailConfig(object):
	"""Stores configuration for a Jail, and provides some
	CLI handlers.
	"""

	verbose = cli.direct('-v --verbose', False).doc(
		"""Be more verbose.
		""")
	passwd = cli.direct('--passwd', False).doc(
		"""Update or add entries for all users and groups seen in the
		jail */etc/passwd* and */etc/group* files.
		""")
	help = cli.direct('-h --help', False).doc(
		"""Show help text and exit.
		""")
	dns = cli.direct('--dns', False).doc(
		"""Add DNS libraries even if no executables or libraries
		explicitly require them.
		""")
	lazy = cli.direct('--lazy', False).doc(
		"""Causes *--umount* to use *umount* with the *-l* switch.
		For more details, see *man 8 umount*.
		""")
	exec_umask = cli.argtext('value', '_mask_', cli.direct('--umask', 037).doc(
		"""Set the process umask for *--execute*. Defaults to *037*.
		"""))
	exec_chdir = cli.argtext('value', '_path_', cli.direct('--chdir', '/').doc(
		"""Set the current directory inside the jail for *--execute*.
		Defaults to */*.
		"""))

	def __init__(self):
		self.validname_rx = None
		self.writepath_rx = None
		self.user = None
		self.group = None
		self.uid = None
		self.gid = None
		self.test = False
		self.etc = False
		self.etc_text = \
			' --try --add /etc/hostname' \
			' --try --add /etc/hosts' \
			' --try --add /etc/resolv.conf' \
			' --try --add /etc/services' \
			' --try --add /etc/protocols' \
			' --try --add /etc/ld.so.cache' \
			' --try --add /etc/mime.types' \
			' --try --add /etc/timezone' \
			' --try --add /etc/nsswitch.conf' \
			' --try --add /etc/mailname' \
			' --try --clone /etc/localtime {jailhome}/etc/localtime'
		self.defaults = False
		self.defaults_text = \
			'--tmp --dev --etc --passwd' \
			' --try --mkdir ' + JAILTMP + '/{user}' \
			' --try --clone /usr/share {jailhome}/usr/share' \
			' --try --clone /usr/lib {jailhome}/usr/lib' \
			' --try --ln-s ' + JAILBASE + '/.dev {jailhome}/dev' \
			' --try --ln-s ' + JAILBASE + '/.tmp {jailhome}/tmp' \
			' --try --ln-s ../../' + JAILBASE + '/.zoneinfo {jailhome}/usr/share/zoneinfo' \
			' --try --ln-s ../../' + JAILBASE + '/.locale {jailhome}/usr/lib/locale'
		self.binds = [
			('{jailhome}', 'auto', '/'),
			(JAILTMP, 'auto', '/' + JAILBASE)
			]
		self.exec_chuid = None
		self.exec_chdir = '/'

		self.set_validname(r'^[a-z][-a-z0-9_\.\@]*\$?$')
		self.set_writepath(r'^/(tmp|(run|mnt|var)/' + JAILBASE + ')($|/)')
		keyset = set((
			key for key, value in JailConfig.__dict__.iteritems()
			if not key.startswith('_') and not callable(value)))
		keyset.update((
			key for key, value in self.__dict__.iteritems()
			if not key.startswith('_') and not callable(value)))
		self._keylist = sorted(keyset)
		return

	@cli.direct(1)
	@cli.argtext('namespec', '_user_[*:*_group_]')
	def set_namespec(self, namespec):
		"""Set the jail _user_ and optionally _group_.
		If _group_ is omitted, it defaults to _user_.
		They need not be existing system user or group names.
		For more information about jail properties, see *--print*.
		"""
		self.user, self.group = self.namespec(namespec)
		self.uid, self.gid = self.userspec(self.user, self.group)
		if self.gid < 1 and self.uid > 0:
			self.gid = pwd.getpwuid(self.uid).pw_gid
		if self.uid == 0 or self.gid == 0:
			raise JailError('jail UID or GID may not be 0')
		if not self.group:
			if self.gid > 0:
				self.group = grp.getgrgid(self.gid).gr_name
			else:
				self.group = self.user
		return

	@property
	def validname(self):
		"""The regular expression used to validate names."""
		return self.validname_rx.pattern

	@cli.direct('--validname')
	def set_validname(self, regex):
		"""Set the regular expression used to check if a given
		name could be used as a system username.
		"""
		try:
			self.validname_rx = re.compile(regex)
		except re.error, err:
			raise JailError(str(err))
		return

	@property
	def writepath(self):
		"""The regular expression paths must match to be writable.
		"""
		return self.writepath_rx.pattern

	@cli.direct('--writepath')
	def set_writepath(self, regex):
		"""Set the regular expression used to deny or allow writing.
		A command may only make changes if the path matches {writepath}.
		"""
		try:
			self.writepath_rx = re.compile(regex)
		except re.error, err:
			raise JailError(str(err))
		return

	@property
	def jailbase(self):
		"""*/$JAILBASE*, where the content of */tmp/$JAILBASE* is accessible
		inside the jail.
		"""
		return '/' + JAILBASE

	@property
	def jailpriv(self):
		"""*$JAILTMP/{user}*, a tmp directory not world readable.
		Accessible at {jailbase}/{user} inside the jail.
		"""
		if not self.user:
			raise JailError('jail user not set')
		return os.path.join(JAILTMP, self.user)

	@property
	def jailhome(self):
		"""*$JAILHOME/*{group}, the jail root directory storage.
		"""
		if not self.group:
			raise JailError('jail group not set')
		return os.path.join(JAILHOME, self.group)

	@property
	def jailmount(self):
		"""*$JAILMOUNT/*{user}, where {jailhome} will be mounted.
		"""
		if not self.user:
			raise JailError('jail user not set')
		return os.path.join(JAILMOUNT, self.user)

	@property
	def jailtmp(self):
		"""*$JAILTMP/.tmp*, accessible as */tmp* in the jail.
		"""
		return os.path.join(JAILTMP, '.tmp')

	@property
	def jaildev(self):
		"""*$JAILTMP/.dev*, accessible as */dev* in the jail.
		"""
		return os.path.join(JAILTMP, '.dev')

	@property
	def userhome(self):
		"""Home directory of system account {user}.
		"""
		if not self.uid:
			raise JailError(repr(self.user) + ' is not a system account')
		return pwd.getpwuid(self.uid).pw_dir

	@cli.direct('--chuid')
	@cli.argtext('userspec', '_user_[*:*_group_]')
	def set_chuid(self, userspec):
		"""Set the user and primary group to run as for *--execute*.
		Defaults to the jails {uid} and {gid}.
		"""
		self.exec_chuid = userspec
		return

	@cli.direct('-t --test')
	def enable_test(self):
		"""Test mode, only print the equivalent shell commands.
		Since nothing is actually done, there will likely be errors that won't
		occur when running without *--test*, as parent directories may
		not have been created or mounts missing.
		"""
		self.test = True
		return

	@cli.direct('-d --defaults')
	def enable_defaults(self):
		"""Enable jail default options and contents.
		Use *--print {defaults_text}* for more details.
		"""
		if not self.defaults:
			self.defaults = True
			return self.defaults_text.split()
		return

	@cli.direct('--etc')
	def enable_etc(self):
		"""Add a minimal set of files from */etc* to the jail.
		Use *--print {etc_text}* for details.
		"""
		if not self.etc:
			self.etc = True
			return self.etc_text.split()
		return

	@cli.direct('--bind')
	def bind(self, srcpath, bindopts=None, path=None):
		"""If directory _srcpath_ exists when *--mount*:ing the jail,
		mount it at *{jailmount}/*_path_ using the bind options _bindopts_.
		Create a mount point *{jailhome}/*_path_ if needed.
		If omitted, _path_ defaults to _srcpath_.
		If omitted or *auto*, _bindopts_ is set based on _srcpath_.
		If _srcpath_ starts with *$JAILHOME* use *exec,ro*.
		If _srcpath_ allows writing, use *rw*, else use *ro*.
		If *exec* is not explicitly set, set *noexec*.
		Bind options will always contain *nosuid*.
		"""
		self.binds.append(
			(srcpath, bindopts or 'auto', path or srcpath))
		return

	def fmtdict(self):
		return dict((
			(k, self.envstr(v))
			for k, v in self.iteritems()
			if v is not None
			))

	def __str__(self):
		accum = ['### {0!r}: {1}{2} ({3}:{4}) [{5}]'.format(
			self.jailhome if (self.user or self.group) else None,
			self.user, (':' + self.group) if self.group else '',
			self.uid, self.gid, time.asctime())]
		for key, value in self.iteritems():
			if value is True:
				accum.append('--' + key)
		return ' '.join(accum)

	def iteritems(self):
		for key in self._keylist:
			try:
				value = getattr(self, key)
			except JailError:
				value = None
			if value is None or isinstance(value, (bool, int, str)) or \
				hasattr(value, '__iter__'):
				yield key, value
		return

	def iterkeys(self):
		return (k for k, v in self.iteritems())

	def itervalues(self):
		return (v for k, v in self.iteritems())

	def items(self):
		return dict(self.iteritems())

	def keys(self):
		return list(self.iterkeys())

	def values(self):
		return list(self.itervalues())

	def __iter__(self):
		return self.iterkeys()

	def __dir__(self):
		return sorted(self.iterkeys())

	def envstr(self, value):
		if value is None:
			return None
		if isinstance(value, str):
			return value
		if isinstance(value, bool):
			return '1' if value else '0'
		if hasattr(value, '__iter__'):
			return ' '.join((
				(repr(s) if ' ' in s else s)
				for s in (self.envstr(v) for v in value)
				))
		if isinstance(value, int):
			return str(value)
		self.log('envstr(', type(value), '=', repr(value), ') =>', str(value))
		return str(value)

	def namespec(self, user, group=None):
		if isinstance(user, str):
			if group is None:
				user, _, group = user.partition(':')
			user = user or None
			if user and not self.validname_rx.match(user):
				raise JailError('invalid user name ' + repr(user))
		if isinstance(group, str):
			group = group or None
			if group and not self.validname_rx.match(group):
				raise JailError('invalid group name ' + repr(group))
		return user, group

	def userspec(self, user, group=None, uid=None, gid=None):
		user, group = self.namespec(user, group)
		try:
			pwdata = pwd.getpwnam(user)
		except (TypeError, KeyError):
			try:
				pwdata = pwd.getpwuid(
					user if isinstance(user, int) else int(user, 0))
			except (TypeError, ValueError, KeyError):
				pwdata = None
		if pwdata:
			uid = pwdata.pw_uid
			if group is None and gid is None:
				gid = pwdata.pw_gid

		try:
			grdata = grp.getgrnam(group)
		except (TypeError, KeyError):
			try:
				grdata = grp.getgrgid(
					group if isinstance(group, int) else int(group, 0))
			except (TypeError, ValueError, KeyError):
				grdata = None
		if grdata:
			gid = grdata.gr_gid
		return uid, gid

	@cli.queued('--print')
	def cli__print(self, fmtstring=None):
		"""Print the text _fmtstring_ using python's str.format() method.
		If _fmtstring_ is omitted, prints a list of the available properties.
		"""
		fmtdict = self.fmtdict()
		if fmtstring is None:
			for key in dir(self):
				print key, '=', repr(fmtdict.get(key))
		else:
			print fmtstring.decode('string_escape').format(**fmtdict)
		return

class Jail(object):
	"""Manages directory structures suitable for chroot jails.

	You must specify the jail _name_, and you may optionally also
	specify a _group_. Both of these must conform to the rules for
	system usernames.

	Commands are processed in the order they occur. If a command fails
	*jail* logs an error message and exits with a nonzero status.
	With the *--test* option, errors are written to stdout prefixed by *#*
	and processing continues if at all possible.
	"""

	def __init__(self):
		self.start_time = time.time()

		self._srcroot = sfs.Stat(None)
		self._jailhome = None

		self._updated_jailbase = False
		self._updated_passwd = False
		self._ldlist_rx = None
		self._ldlist_cmd = None
		self._library_rx = None
		self._ldconfig_rx = None
		self._ldconfig_cmd = None
		self._ldlist_cache = dict()
		self._ldso_cache = dict()
		self._solinks = dict()
		self._src_done = set()
		self._dst_uids = dict()
		self._dst_gids = dict()

		self.cfg = JailConfig()
		self.opt_try = 0
		self.ldconfig_cmd = '/sbin/ldconfig -p'
		self.ldconfig_rx = r'\s*(\S+).+=>\s*(\S+)\s*'
		self.ldlinux_so = None
		self.ldlist_cmd = '{ldlinux_so} --list {path}'
		self.ldlist_rx = r'\s+(\S+)\s+=>(\s*\S+\s*)?\(0x.+\)'
		self.ldlist_count = 0
		self.library_rx = r'(^|.*/)lib.*\.so(\..*|$)'
		self.dns_added = False
		self.dns_regex = r'^lib(nsl|resolv|nss[_,0-9,a-z]+)\..+'
		self._dns_rx = re.compile(self.dns_regex)
		self.dns_files = set()
		self.thread_added = False
		self.thread_files = set()
		self.thread_regex = r'^lib(pthread|gcc_s)\..+'
		self._thread_rx = re.compile(self.thread_regex)
		return

	def log(self, *args):
		if self.cfg.test or self.cfg.verbose:
			print >> sys.stderr, '##', ' '.join((str(a) for a in args))
		return

	@cli.queued('--dev')
	def jailbase_dev(self):
		"""Create a minimal */dev* for jails at *{jaildev}*.
		"""
		self._srcroot.makedirs(JAILTMP, self._srcroot.mode())
		srcstat = self.srcstat('/dev')
		dststat = self.dststat(self.cfg.jaildev, srcstat.fmt())
		self.clone_stat(srcstat, dststat)
		for devname in ('null', 'zero', 'random', 'urandom'):
			srcstat = self.srcstat(os.path.join('/dev', devname))
			dststat = self.dststat(os.path.join(self.cfg.jaildev, devname), srcstat.fmt())
			self.clone_stat(srcstat, dststat)
		return

	@cli.queued('--tmp')
	def jailbase_tmp(self):
		"""Create a */tmp* for jails at *{jailtmp}*.
		"""
		self._srcroot.makedirs(JAILTMP, self._srcroot.mode())
		srcstat = self.srcstat('/tmp')
		dststat = self.dststat(self.cfg.jailtmp, srcstat.fmt())
		self.clone_stat(srcstat, dststat)
		if self.cfg.user:
			self.mkdir(os.path.join(JAILTMP, self.cfg.user))
		return

	def update_jailbase(self, path, cmd=None):
		if self._updated_jailbase or not (
			path is None or
			path.startswith('/' + JAILBASE) or
			path.startswith(JAILTMP) or
			path.startswith(self.cfg.jailmount + '/' + JAILBASE)
			):
			return False
		self.log('### updating ' + JAILBASE + ' for ' + repr(cmd or path))
		self._updated_jailbase = True
		srcstat = self.srcstat('/')
		self._srcroot.mkdir(JAILTMP, srcstat.st_mode, srcstat.st_uid, srcstat.st_gid)
		self._srcroot.mkdir(JAILHOME, srcstat.st_mode, srcstat.st_uid, srcstat.st_gid)
		self._srcroot.mkdir(JAILMOUNT, srcstat.st_mode, srcstat.st_uid, srcstat.st_gid)
		self.jailbase_tmp()
		self.jailbase_dev()
		self.clone_recurse('/usr/share/zoneinfo', JAILTMP + '/.zoneinfo', True)
		self.clone_recurse('/usr/lib/locale', JAILTMP + '/.locale', True)
		return True

	@cli.direct('--ldconfig-cmd')
	@property
	def ldconfig_cmd(self):
		return ' '.join(self._ldconfig_cmd)
	@ldconfig_cmd.setter
	def ldconfig_cmd(self, command):
		"""Set the command to use when locating the shared object loader.
		Default is *ldconfig -p*.
		"""
		self._ldconfig_cmd = command.split()

	@cli.direct('--ldconfig-rx')
	@property
	def ldconfig_rx(self):
		return self._ldconfig_rx.pattern
	@ldconfig_rx.setter
	def ldconfig_rx(self, regex):
		"""Set the regular expression used to parse the output from
		*--ldconfig-cmd* when locating the shared object loader.
		"""
		try:
			self._ldconfig_rx = re.compile(regex)
		except re.error, err:
			raise JailError(str(err))
		return

	@cli.direct('--ldlist-cmd')
	@property
	def ldlist_cmd(self):
		return self._ldlist_cmd
	@ldlist_cmd.setter
	def ldlist_cmd(self, command):
		"""Set the command template to use when listing shared objects.
		Default is *{ldlinux_so} --list {path}*.
		"""
		self._ldlist_cmd = command

	@cli.direct('--ldlist-rx')
	@property
	def ldlist_rx(self):
		return self._ldlist_rx.pattern
	@ldlist_rx.setter
	def ldlist_rx(self, regex):
		"""Set the regular expression used to parse the output from
		*--ldlist-cmd* when listing shared object dependencies.
		"""
		try:
			self._ldlist_rx = re.compile(regex)
		except re.error, err:
			raise JailError(str(err))
		return

	@property
	def library_rx(self):
		return self._library_rx.pattern
	@library_rx.setter
	def library_rx(self, regex):
		"""Set the regular expression used to identify shared object
		files using their name.
		"""
		try:
			self._library_rx = re.compile(regex)
		except re.error, err:
			raise JailError(str(err))
		return

	@cli.mapper
	def _cli_mapper(self, args):
		retv = []
		for arg in args:
			if len(arg) > 2 and arg[0] == '-' and arg[1] != '-':
				retv.extend(['-'+ch for ch in arg[1:]])
			else:
				retv.append(arg)
		return retv

	def writable(self, dstpath, cmd=None):
		allowed = dstpath is None or self.cfg.writepath_rx.match(dstpath)
		if cmd:
			if not allowed:
				raise ValueError('{0!r}: writepath disallows {1!r}'.format(cmd, dstpath))
			if self.cfg.test:
				print >> sys.stderr, cmd
			elif self.cfg.verbose:
				print >> sys.stderr, '#', cmd
		return False if self.cfg.test else allowed

	def readable(self, srcpath, cmd=None):
		if cmd:
			if self.cfg.test:
				print >> sys.stderr, cmd
			elif self.cfg.verbose:
				print >> sys.stderr, '#', cmd
		return True

	def all_done(self):
		if self.cfg.passwd:
			try:
				self.update_passwd()
			except (IOError, OSError), err:
				raise JailError('--passwd: ' + str(err))

		self.log('### checked {0} files in {1:.2f}s using {2}{3} stat() ({4:.1f}% of {5} cached)'.format(
				self._srcroot.count_instances(), time.time() - self.start_time,
				str(self.ldlist_count) + ' ld-linux and ' if self.ldlist_count else '',
				self._srcroot.count_statcalls(), self._srcroot.hitratio(), self._srcroot.count_accesses()))

		if self.cfg.test or self.cfg.verbose:
			try:
				import resource
				uself = resource.getrusage(resource.RUSAGE_SELF)
				time_used = uself.ru_utime + uself.ru_stime
				mem_used = uself.ru_maxrss * resource.getpagesize()
				self.log('### used {0:.2f} seconds CPU and {1}B RAM'.format(
					time_used, cli.size_t(mem_used) if mem_used else '?'))
			except (ValueError, AttributeError, ImportError):
				pass
		return

	def parse(self, cmd_list):
		cli_debug = 0
		os.nice(20)
		old_umask = os.umask(0)
		self._srcroot.writable_fn(self.writable)
		self._srcroot.readable_fn(self.readable)
		while '--cli-debug' in cmd_list:
			cli_debug += 1
			cmd_list.remove('--cli-debug')
		cli_list = cli.parse(self, cmd_list, cli_debug)
		if self.cfg.help or not cli_list:
			print >> sys.stderr, cli.Usage(self)
			return 0

		self.log(self.cfg)

		for cmd in cli_list:
			if self.opt_try:
				self.opt_try -= 1
			self.log(cmd.text)
			try:
				cmd()
			except (JailError, OSError), err:
				err.strerror = ('--try ' if self.opt_try else '') + err.strerror
				self.log(err.strerror)
				if not self.opt_try:
					raise
		self.all_done()
		return 0

	@cli.queued('--try')
	def cli_try( self ):
		"""The next command will ignore failure.
		"""
		self.opt_try = 2
		return

	@cli.queued('--mount')
	def mount(self):
		"""Mount *{jailhome}* at *{jailmount}*, then mount all *--bind*
		directories. Creates mount point directories in *{jailhome}* as
		needed.
		"""
		srcstat = self.srcstat('/')
		self.mkdir(self.cfg.jailhome, srcstat.st_mode, srcstat.st_uid, srcstat.st_gid)
		self.mkdir(self.cfg.jailmount, srcstat.st_mode, srcstat.st_uid, srcstat.st_gid)

		mounts = self.mounts()
		binds = dict()
		for (srcpath, bindopts, path) in self.cfg.binds:
			srcpath = srcdir = self.srcpath(srcpath)
			srcdir += '' if srcdir.endswith('/') else '/'
			srcstat = self.srcstat(srcpath)
			bindopts = self.bindopts(srcpath, bindopts)
			dstdir = dstpath = self.dstpath('{jailmount}/' + path)
			dstdir += '' if dstdir.endswith('/') else '/'
			dststat = self.dststat(dstpath)
			mountpoint = self.dstpath('{jailhome}/' + path)
			msg = None

			for dstmount, (srcmount, optmount) in mounts.iteritems():
				if (dstmount + '/').startswith(dstdir):
					if dstpath != dstmount:
						msg = 'dstpath subdir {0!r} mounted at {1!r}'.format(
							srcmount, dstmount)
					elif srcmount != srcpath:
						msg = '{0!r} already mounted at {1!r}'.format(
							srcmount, dstpath)
					elif bindopts == optmount:
						# identical
						msg = ''
					break

			if msg is not None:
				pass
			elif srcdir.startswith(dstdir):
				msg = 'parent of srcpath ' + repr(srcpath)
			elif dststat and not stat.S_ISDIR(dststat.st_mode):
				msg = 'dstpath must be directory, not {0}'.format(dststat.fmtstr())
			elif not srcstat:
				msg = 'srcpath not found'
			elif not stat.S_ISDIR(srcstat.st_mode):
				msg = 'srcpath must be directory, not {0}'.format(dststat.fmtstr())
			elif (srcpath).startswith(self.cfg.jailhome + '/'):
				msg = 'inside jailhome ' + repr(self.cfg.jailhome)
			elif (srcpath).startswith(self.cfg.jailmount + '/'):
				msg = 'inside jailmount ' + repr(self.cfg.jailmount)
			elif (self.cfg.jailmount).startswith(srcdir):
				msg = 'parent of jailmount ' + repr(self.cfg.jailmount)
			elif (self.cfg.jailhome).startswith(srcdir):
				msg = 'parent of jailhome ' + repr(self.cfg.jailhome)
			else:
				if dstpath in binds:
					msg = 'replaced ' + repr(binds[dstpath])
				elif dstpath in mounts:
					optmount = mounts[dstpath][1]
					msg = 'change option {0!r} -> {1!r}'.format(
						','.join(optmount.difference(bindopts)),
						','.join(bindopts.difference(optmount)))
				binds[dstpath] = (srcpath, bindopts)

			if self.cfg.test:
				print >> sys.stderr, '## --bind {0!r} {1!r} {2!r}{3}'.format(
					srcpath, ','.join(sorted(bindopts)),
					path, (': ' + msg) if msg else '')

			if not msg and not dststat:
				assert srcstat.path == srcpath
				# self.log('## clone mount point {0!r} -> {1!r}'.format(srcpath, self.dstpath('{jailhome}/' + path)))
				self.clone(srcpath, self.dstpath('{jailhome}/' + path))
				# dststat = self._srcroot.makedirs(self.dstpath('{jailhome}/' + path), srcstat.mode())
				# self.dstpath('{jailhome}/' + path))

		pathlist = sorted(binds.iterkeys(), key=len)
		pathlist.sort(key=lambda s: s.count('/'))
		for dstpath in pathlist:
			srcpath, bindopts = binds[dstpath]
			if dstpath not in mounts:
				self.subcall('/bin/mount', '--bind', srcpath, dstpath)
			self.subcall('/bin/mount', '-o', ','.join(bindopts), dstpath)
		return

	@cli.queued('--umount')
	def umount(self):
		"""Unmount all mounted directories at or below *{jailmount}*.
		"""
		mounts = self.mounts()
		dirs = sorted(mounts.iterkeys(), key=len, reverse=True)
		dirs.sort(key=lambda s: s.count('/'), reverse=True)
		for dstpath in dirs:
			if self.cfg.lazy:
				self.subcall('/bin/umount', '-l', self.dstpath(dstpath))
			else:
				self.subcall('/bin/umount', self.dstpath(dstpath))
		dststat = self.dststat(self.cfg.jailmount)
		if dststat:
			dststat.rmdir()
		return

	@cli.queued('--clean')
	def clean_tmp(self):
		"""Remove all files and directories within {jailpriv}.
		"""
		dstpath = self.dstpath(self.cfg.jailpriv)
		for name in self._srcroot.listdir(dstpath):
			self._srcroot.rm_rf(os.path.join(dstpath, name))
		return

	@cli.queued('--remove')
	def clean(self):
		"""Remove {jailhome} and {jailpriv}. Implies *--umount*.
		"""
		self.umount()
		self._srcroot.rm_rf(self.cfg.jailhome)
		self._srcroot.rm_rf(self.cfg.jailpriv)
		return

	@cli.queued('--add')
	def add(self, *paths):
		"""Add _paths_ and dependencies to the jail.
		*--clone* _path_ {jailhome}/_path_.
		If _path_ is an executable or a library,
		*--add* all libraries it depends on.
		"""
		for srcpath in paths:
			self.add_path(srcpath)
		return

	@cli.queued('--add-from')
	def add_from(self, srcdir, *files):
		"""Add zero or more _files_ from _srcdir_ to the jail. See *--add*.
		"""
		for filename in files:
			self.add_path(os.path.join(srcdir, filename))
		return

	@cli.queued('--add-recurse')
	@cli.argtext('paths', '[*--quick*] [_srcpath_ ...]')
	def add_recurse(self, *paths):
		"""Add _srcpath_, dependencies and directory contents to the jail.
		If _srcpath_ is a directory or a symlink to a directory, for each
		_entry_ except *.* and *..*, *--add-recurse* _srcpath_/_entry_.
		If *--quick* is given, assume directory contents are unchanged
		if the directory date and size are unchanged.
		"""
		quick = False
		if '--quick' in paths:
			paths = list(paths)
			paths.remove('--quick')
			quick = True
		for srcpath in paths:
			self.add_path(srcpath, True, quick)
		return

	@cli.queued('--mknod')
	def mknod(self, dstpath, devtype, major, minor=None):
		"""Create the special device file _dstpath_ of type _devtype_.
		_devtype_ must be *c* or *b*. If _dstpath_ exists,
		ensure it has the same type and device numbers. If _minor_ is
		omitted, _major_ is taken to be a combined device number.
		"""
		if isinstance(devtype, str):
			if devtype == 'c':
				devtype = stat.S_IFCHR
			elif devtype == 'b':
				devtype = stat.S_IFBLK
			else:
				raise JailError('devtype must be c or b')
			devtype |= 0666
		mode = devtype
		major = major if isinstance(major, int) else int(major, 0)
		if minor is None:
			device = major
		else:
			minor = minor if isinstance(minor, int) else int(minor, 0)
			device = os.makedev(major, minor)
		major = os.major(device)
		minor = os.minor(device)
		devtype = 'c' if stat.S_ISCHR(mode) \
			else 'b' if stat.S_ISBLK(mode) else '?'
		dstpath = self.dstpath(dstpath)
		dststat = self.dststat(dstpath, mode)
		if dststat and dststat.st_rdev != device:
			raise JailError(
				'{0!r}: expected device {1!r} {2}.{3}, found {4!r}'.format(
					dstpath, devtype, major, minor, dststat))
		self._srcroot.mknod(dstpath, mode, device)
		return

	@cli.queued('--rmdir')
	def rmdir(self, dstpath):
		"""Remove the empty directory _dstpath_.
		"""
		dststat = self.dststat(self.dstpath(dstpath))
		if dststat:
			dststat.rmdir()
		return

	@cli.queued('--rm')
	def rm(self, dstpath):
		"""Remove the file _dstpath_.
		"""
		dststat = self.dststat(self.dstpath(dstpath))
		if dststat:
			dststat.remove()
		return

	@cli.queued('--mkdir')
	@cli.argtext('user', 'user[:group]')
	@cli.argtext('group', None)
	def mkdir(self, dstpath, mode=0750, user=None, group=None):
		"""Create the directory _dstpath_ with _mode_ permissions and
		optionally set the owning user and group. _mode_ defaults to 0750.
		"""
		mode = stat.S_IMODE(self.decode_mode(mode))
		uid, gid = self.cfg.userspec(user, group, self.cfg.uid, self.cfg.gid)
		dstpath = self.dstpath(dstpath)
		dststat = self.dststat(dstpath, stat.S_IFDIR)
		srcpath = self.srcpath(os.path.dirname(dstpath))
		self.dst_uid(uid)
		self.dst_gid(gid)
		self._srcroot.mkdir(dstpath, mode, uid, gid)
		return

	@cli.queued('--ln-s')
	def symlink(self, target, linkname):
		"""Create the symlink _linkname_ referring to _target_. If _linkname_
		exists it must be a symlink referring to _target_.
		"""
		target = self.subprops(target)
		dstpath = self.dstpath(linkname)
		dststat = self.dststat(dstpath, stat.S_IFLNK)
		if dststat and dststat.readlink() != target:
			raise JailError(
				'{0!r}: expected symlink to {1!r}, got {2!r}'.format(
				dstpath, target, dststat.readlink()))
		# srcpath = self.srcpath(os.path.join(os.path.dirname(dstpath), target))
		self._srcroot.symlink(target, dstpath)
		return

	@cli.queued('--chflags')
	def chflags(self, dstpath, flags):
		"""On systems that support it, change the file flags of
		_dstpath_ to _flags_.
		"""
		dstpath = self.dstpath(dstpath)
		self.dststat(dstpath).chflags(flags)
		return

	@cli.queued('--chmod')
	def chmod(self, dstpath, mode):
		"""Change the permissions of _dstpath_ to _mode_.
		"""
		mode = self.decode_mode(mode)
		dstpath = self.dstpath(dstpath)
		self.dststat(dstpath).chmod(mode)
		return

	def dst_uid(self, uid):
		if uid >= 0 and uid not in self._dst_uids:
			try:
				self._dst_uids[uid] = pwd.getpwuid(uid)
			except KeyError as e:
				self.log(str(e))
				return -1
			self.dst_gid(self._dst_uids[uid].pw_gid)
		return uid

	def dst_gid(self, gid):
		if gid >= 0 and gid not in self._dst_gids:
			try:
				self._dst_gids[gid] = grp.getgrgid(gid)
			except KeyError as e:
				self.log(str(e))
				return -1
		return gid

	@cli.queued('--chown')
	@cli.argtext('user', '_user_[:_group_]')
	@cli.argtext('group', None)
	def chown(self, dstpath, user, group=None):
		"""Change the ownership of _dstpath_ to _user_ and _group_.
		If omitted, _group_ is left unchanged.
		"""
		dstpath = self.dstpath(dstpath)
		uid, gid = self.cfg.userspec(user, group, -1, -1)
		self.dst_uid(uid)
		self.dst_gid(gid)
		self._srcroot.chown(dstpath, uid, gid)
		return

	@cli.queued('--touch')
	def utime(self, dstpath, mtime=None):
		"""Set the modification time of _dstpath_. _dstpath_
		must exist. _mtime_ defaults to the current time.
		Use the time format *%Y%m%d%H%M.%S*.
		"""
		dstpath = self.dstpath(dstpath)
		self.dststat(dstpath).utime(mtime)
		return

	@cli.queued('--clone-recurse')
	@cli.argtext('quick', '*--quick*')
	def clone_recurse(self, srcpath, dstpath, quick=None):
		"""Clone _srcpath_ to _dstpath_. If _srcpath_ is a
		directory, *--clone-recurse* it's contents.
		If *--quick* is given, assume directory contents are unchanged
		if their size and modification times match.
		"""
		if srcpath == '--quick':
			srcpath = dstpath
			dstpath = quick
		elif dstpath == '--quick':
			dstpath = quick
		srcpath = self.srcpath(srcpath)
		srcstat = self.srcstat(srcpath)
		dstpath = self.dstpath(dstpath)
		dststat = self.dststat(dstpath)
		self.clone(srcpath, dstpath)
		if srcstat.isdir() and (not quick or srcstat != dststat):
			for name in self._srcroot.listdir(srcpath):
				self.clone_recurse(
					os.path.join(srcpath, name),
					os.path.join(dstpath, name),
					True if quick else False)
		return

	@cli.queued('--clone-from')
	def clone_from(self, srcpath, dstpath, *files):
		"""Clone _files_ from _srcpath_ to _dstpath_.
		"""
		for filename in files:
			self.clone(
				os.path.join(srcpath, filename),
				os.path.join(dstpath, filename))
		return

	@cli.queued('--clone')
	def clone(self, srcpath, dstpath):
		"""Copy _srcpath_ to _dstpath_, along with data and metadata.
		Symlinks are copied, not followed.
		_srcpath_ must exist. If _dstpath_ exists, it must have the
		same type as _srcpath_ (file, device, directory or symlink).
		Clone parent directories from _srcpath_ to _dstpath_ as needed.
		If _srcpath_ is a regular file, copy the content. Copy flags,
		permissions, ownership and mtime.
		"""
		srcpath = self.srcpath(srcpath)
		srcstat = self.srcstat(srcpath)
		dstpath = self.dstpath(dstpath)
		dstdir = os.path.dirname(dstpath) or '/'
		if not self._srcroot.stat(dstdir):
			self.clone(os.path.dirname(srcpath) or '/', dstdir)
		self.clone_stat(srcstat, self.dststat(dstpath, srcstat.fmt()))
		return

	@cli.final
	@cli.queued('-- --execute')
	@cli.argtext('args', '[_name_*=*_value_ ...] _program_ [_args_ ...]')
	def execute(self, *args):
		"""Execute _program_ inside the jail, replacing the jail script.
		The environment will be cleared except for JAILBASE, PWD, USER,
		HOME, PATH and LANG, and anything provided as _name_=_value_
		before _program_.
		Everything after *--execute* is taken as arguments to _program_.
		*--execute* implies *--passwd* and *--mount*.
		See also *--chuid*, *--umask*, *--chdir*.
		"""
		exec_uid = exec_gid = -1
		if self.cfg.exec_chuid:
			exec_uid, exec_gid = self.cfg.userspec(self.cfg.exec_chuid)
		if exec_gid < 1:
			exec_gid = self.dst_gid(self.cfg.gid or os.getegid())
			if exec_gid < 1:
				raise JailError('disallowed group id ' + repr(exec_gid))
		if exec_uid < 1:
			exec_uid = self.dst_uid(self.cfg.uid or os.geteuid())
			if exec_uid < 1:
				raise JailError('disallowed user id ' + repr(exec_uid))

		exec_groups = set(gid for gid in self._srcroot.getgroups(exec_uid) if self.dst_gid(gid) > 0)
		exec_groups.add(exec_gid)
		exec_chdir = os.path.abspath(self.subprops(self.cfg.exec_chdir));
		exec_paths = list()
		exec_args = list()

		self.all_done()
		self.mount()

		for os_path in os.environ['PATH'].split(':'):
			if os.path.isdir(self.cfg.jailmount + os_path):
				exec_paths.append(os_path)
			elif self.cfg.test and os.path.isdir(self.cfg.jailhome + os_path):
				exec_paths.append(os_path)

		exec_env = {
			'JAILBASE': '/' + JAILBASE,
			'PWD': exec_chdir,
			'USER': self._dst_uids[exec_uid].pw_name,
			'HOME': self._dst_uids[exec_uid].pw_dir,
			'PATH': ':'.join(exec_paths)
			}
		if 'LANG' in os.environ:
			exec_env['LANG'] = os.environ['LANG']

		for arg in args:
			arg = self.subprops(arg)
			if exec_args or '=' not in arg:
				exec_args.append(arg)
				continue
			env_key, _, env_val = arg.partition('=')
			env_key = env_key.upper()
			if re.match(r'[A-Z_][A-Z0-9_]*$', env_key):
				env_keylist = [env_key]
			else:
				env_keylist = [key for key in os.environ
					if re.match(env_key, key)]
			for key in env_keylist:
				value = os.environ.get(key, None) if env_val == '*' else env_val
				if value:
					exec_env[key] = value
				elif key in exec_env:
					del exec_env[key]

		sys.stdout.flush()
		sys.stderr.flush()

		self._srcroot.umask(self.cfg.exec_umask)
		self._srcroot.chdir(self.cfg.jailmount + exec_chdir)
		self._srcroot.chroot(self.cfg.jailmount)
		self._srcroot.setgroups(exec_groups)
		self._srcroot.setgid(exec_gid)
		self._srcroot.setuid(exec_uid)
		self._srcroot.execve(exec_args[0], exec_args, exec_env)
		return

	def subprops(self, fmtstring):
		try:
			return fmtstring.decode('string_escape').format(**self.cfg.fmtdict())
		except (KeyError), err:
			raise JailError(str(err) + ' not set')

	def pcall(self, args):
		if self.cfg.verbose:
			print >> sys.stderr, '#', ' '.join(args)
		process = subprocess.Popen(args, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
		return process.communicate()[0]

	def subcall(self, *args):
		if self.cfg.test:
			print >> sys.stderr, ' '.join(args)
			return ''
		try:
			return self.pcall(args)
		except subprocess.CalledProcessError, err:
			raise JailError(repr(' '.join(args)) + ': ' + err.output.strip())
		return ''

	def bindopts(self, srcpath, bindopts=None):
		if srcpath:
			opts = set(('noexec', 'ro', 'nosuid', 'remount', 'bind', 'noatime'))
		else:
			srcpath = ''
			opts = set(('exec', 'rw', 'suid', 'remount', 'noatime'))
		bindopts = (bindopts or 'auto').lower()
		if bindopts == 'auto':
			if srcpath.startswith(JAILHOME):
				bindopts = 'exec,ro'
			elif self.cfg.writepath_rx.match(srcpath):
				bindopts = 'noexec,rw'
			else:
				bindopts = 'noexec,ro'
		# print '# bindopts', repr(srcpath), repr(self.writable(srcpath)), repr(bindopts)
		for opt in (s.strip() for s in bindopts.split(',')):
			if not opt or opt == 'suid':
				continue
			if opt == 'rw':
				opts.discard('ro')
			elif opt == 'ro':
				opts.discard('rw')
			elif opt.startswith('no'):
				opts.discard(opt[2:])
			else:
				opts.discard('no' + opt)
			opts.add(opt)
		return opts

	def decode_mode(self, mode):
		if isinstance(mode, str):
			try:
				mode = int(mode, 0)
			except TypeError:
				return None
		if isinstance(mode, int):
			return mode
		return None

	def srcpath(self, srcpath):
		srcpath = os.path.abspath(self.subprops(srcpath))
		self.update_jailbase(srcpath, 'srcpath ' + repr(srcpath))
		return '/' if srcpath == '//' else srcpath

	def srcstat(self, path):
		return self._srcroot.lstat(path)

	def dstpath(self, dstpath):
		dstpath = os.path.abspath(self.subprops(dstpath))
		self.writable(dstpath)
		return '/' if dstpath == '//' else dstpath

	def dststat(self, dstpath, reqfmt=None):
		if reqfmt is None:
			dststat = self._srcroot.get(dstpath)
		else:
			reqfmt = stat.S_IFMT(reqfmt)
			assert reqfmt
			dststat = self._srcroot.getdefault(dstpath, reqfmt)
			if dststat is None or stat.S_IFMT(dststat.st_mode) != reqfmt:
				raise ValueError('{0!r}: expected {1}, got {2}'.format(
					dstpath, self._srcroot.mode_fmtstr(reqfmt),
					dststat.fmtstr()))
		if dststat is not None:
			self.dst_uid(dststat.st_uid)
			self.dst_gid(dststat.st_gid)
		return dststat

	def test(self, text, func, args):
		if self.cfg.test:
			print text
			return True
		try:
			func(*args)
		except (IOError, OSError), err:
			raise JailError('test:: ' + text + ': ' + err.strerror)
		return False

	def ldlist(self, path):
		"""Parse the output of *ld-linux.so --list* _path_ to figure out
		the shared object dependencies of an executable. Returns the
		dependent paths in a set.
		"""
		try:
			return self._ldlist_cache[path]
		except KeyError:
			pass
		if not os.path.isabs(path):
			raise ValueError(repr(path) + ': path not absolute')
		cmd = self._ldlist_cmd.format(
			ldlinux_so=self.ldlinux_so, path=path).split()
		try:
			text = self.pcall(cmd)
			self.ldlist_count += 1
		except subprocess.CalledProcessError, err:
			return self._ldlist_cache.setdefault(path, tuple())
		except OSError, err:
			err.strerror = ' '.join(cmd) + ': ' + err.strerror
			raise
		result = set()
		for match in self._ldlist_rx.finditer(text):
			result.update(
				self._ldso_cache.get(match.group(1),
				[match.group(1)]))
		return self._ldlist_cache.setdefault(path, result)

	def add_path(self, srcpath, recurse=False, quick=False):
		srcpath = self.srcpath(srcpath)
		if srcpath in self._src_done:
			return
		self._src_done.add(srcpath)

		srcdir = os.path.dirname(srcpath)
		if srcdir and srcdir not in self._src_done:
			self.add_path(srcdir)

		srcstat = self.srcstat(srcpath)
		if srcstat is None:
			raise JailError('not found: ' + repr(srcpath))
		if self._jailhome is None:
			self._jailhome = self._srcroot.makedirs(self.cfg.jailhome, self._srcroot.mode())

		dststat = self._jailhome.lstat(srcpath, srcstat.fmt())
		# self.log('add_path {0!r} {1!r} -> {2!r}'.format(srcpath, srcstat, dststat))

		if srcstat.islnk():
			srclinkstat = srcstat.get()
			if srclinkstat:
				self.add_path(srclinkstat.path, recurse, quick)
			elif dststat.islnk():
				dstlinkstat = dststat.get()
				if not dstlinkstat:
					self.log('{0!r}: link is broken, so removing {1!r}'.format(
						srcstat, dstlinkstat))
					if dstlinkstat.isdir():
						dstlinkstat.rmdir()
					else:
						dstlinkstat.remove()
		elif srcstat.isreg():
			if self.is_executable(srcpath, srcstat):
				if not self.ldlinux_so:
					self.examine_system()
				if not self.dns_added and (self.cfg.dns or srcpath in self.dns_files):
					self.dns_added = True
					for path in self.dns_files:
						self.add_path(path, recurse=recurse, quick=quick)
				if not self.thread_added and srcpath in self.thread_files:
					self.thread_added = True
					for path in self.thread_files:
						self.add_path(path, recurse=recurse, quick=quick)
				for path in self._solinks.get(srcpath, tuple()):
					self.add_path(path, recurse=recurse, quick=quick)
				for path in self.ldlist(srcpath):
					self.add_path(path, recurse=recurse, quick=quick)

		if srcstat is dststat:
			self.log('same file: {0!r} vs {1!r}'.format(srcstat, dststat))
		elif srcstat == dststat:
			# self.log('unmodified: {0!r} vs {1!r}'.format(srcstat, dststat))
			pass
		elif not self.clone_stat(srcstat, dststat):
			self.log('skipped {0} {1!r}'.format(srcstat.fmtstr(), srcpath))
		elif srcstat != dststat and (srcstat.st_size == dststat.st_size or not srcstat.isdir()):
			self.log('clone failed: {0!r} -> {1!r}'.format(srcstat, dststat))
		elif srcstat.isdir() and recurse:
			for name in srcstat.listdir():
				self.add_path(os.path.join(srcpath, name), recurse=recurse, quick=quick)
			# dststat.utime(srcstat.st_mtime)

		return

	def clone_stat(self, srcstat, dststat):
		# self.log('clone_stat {0!r} -> {1!r}'.format(srcstat, dststat))

		if srcstat is dststat:
			return True

		if srcstat.fmt() != dststat.fmt():
			raise ValueError('{0!r}: expected {1}, got {2}'.format(
				dststat.path, srcstat.fmtstr(), dststat.fmtstr()))

		self.dst_uid(srcstat.st_uid)
		self.dst_gid(srcstat.st_gid)

		if srcstat.isreg():
			srcstat.copy2(dststat)
		elif srcstat.isdir():
			dststat.mkdir(None, srcstat.st_mode, srcstat.st_uid, srcstat.st_gid)
			# self._srcroot.mkdir(dstpath, srcstat.st_mode, srcstat.st_uid, srcstat.st_gid)
			dststat.utime(srcstat.st_mtime)
		elif srcstat.islnk():
			dststat.symlink(srcstat.readlink())
			# self.symlink(srcstat.readlink(), dstpath)
			dststat.chown(srcstat.st_uid, srcstat.st_gid)
		elif srcstat.ischr() or srcstat.isblk():
			dststat.mknod(None, srcstat.st_mode, srcstat.st_rdev)
			# self._srcroot.mknod(dstpath, srcstat.st_mode, srcstat.st_rdev)
			dststat.chown(srcstat.st_uid, srcstat.st_gid)
			dststat.utime(srcstat.st_mtime)
		else:
			return False

		if hasattr(srcstat, 'st_flags'):
			dststat.chflags(srcstat.st_flags)
		return True

	def is_executable(self, srcpath, srcstat=None):
		srcstat = srcstat or self.srcstat(srcpath)
		return srcstat.isexecutable() or self._library_rx.search(srcpath)

	def mounts(self):
		mounts = dict()
		with open('/etc/mtab', 'r') as etcmtab:
			for line in etcmtab:
				parts = line.split()
				if (parts[2] == 'simfs' or 'bind' in parts[3]) \
					and (parts[1] + '/').startswith(self.cfg.jailmount + '/'):
					if parts[1] in mounts:
						self.log(repr(parts[1]) + ' is mounted more than once')
					mounts[parts[1]] = (parts[0], self.bindopts(None, parts[3]))
		return mounts

	def update_passwd(self):
		if self._updated_passwd or not self.cfg.passwd \
			or not self.dststat(self.cfg.jailhome):
			return
		self._updated_passwd = True
		self.clone('/etc', '{jailhome}/etc')
		etcpasswd_path = self.dstpath('{jailhome}/etc/passwd')
		etcpasswd_stat = self.dststat(etcpasswd_path, stat.S_IFREG)
		etcgroup_path = self.dstpath('{jailhome}/etc/group')
		etcgroup_stat = self.dststat(etcgroup_path, stat.S_IFREG)

		if etcpasswd_stat:
			with open(etcpasswd_path, 'r') as etcpasswd:
				for line in etcpasswd:
					parts = line.split(':')
					if len(parts) == 7:
						self.dst_uid(int(parts[2], 0))

		if etcgroup_stat:
			with open(etcgroup_path, 'r') as etcgroup:
				for line in etcgroup:
					parts = line.split(':')
					if len(parts) == 4:
						self.dst_gid(int(parts[2], 0))

		etcpasswd_text = ''
		known_users = set()
		for pw_data in self._dst_uids.itervalues():
			known_users.add(pw_data.pw_name)
			etcpasswd_text += '{0}:{1}:{2}:{3}:{4}:{5}:{6}\n'.format(
					pw_data.pw_name,
					'*' if pw_data.pw_passwd else '',
					pw_data.pw_uid,
					pw_data.pw_gid,
					pw_data.pw_gecos,
					pw_data.pw_dir,
					pw_data.pw_shell)
		cmd = 'cat > {0!r} <<_EOT_\n{1}_EOT_'.format(
			etcpasswd_path, etcpasswd_text)
		if self.writable(etcpasswd_path, cmd):
			with open(etcpasswd_path, 'w') as etcpasswd:
				etcpasswd.write(etcpasswd_text)
		srcstat = self.srcstat('/etc/passwd')
		etcpasswd_stat.chmod(srcstat.st_mode)
		etcpasswd_stat.chown(srcstat.st_uid, srcstat.st_gid)

		etcgroup_text = ''
		for gr_data in self._dst_gids.itervalues():
			etcgroup_text += '{0}:{1}:{2}:{3}\n'.format(
					gr_data.gr_name,
					'*' if gr_data.gr_passwd else '',
					gr_data.gr_gid,
					','.join(known_users.intersection(gr_data.gr_mem)))
		cmd = 'cat > {0!r} <<_EOT_\n{1}_EOT_'.format(
			etcgroup_path, etcgroup_text)
		if self.writable(etcgroup_path, cmd):
			with open(etcgroup_path, 'w') as etcgroup:
				etcgroup.write(etcgroup_text)
		srcstat = self.srcstat('/etc/group')
		etcgroup_stat.chmod(srcstat.st_mode)
		etcgroup_stat.chown(srcstat.st_uid, srcstat.st_gid)
		return

	def examine_system(self):
		try:
			text = self.pcall(self._ldconfig_cmd)
		except OSError, err:
			err.strerror = repr(self.ldconfig_cmd) + ': ' + err.strerror
			raise

		libdirs = set()
		dns_files = dict()
		thread_files = dict()

		for match in self._ldconfig_rx.finditer(text):
			name, path = match.groups()
			self._ldso_cache.setdefault(name, set()).add(path)
			libdirs.add(os.path.dirname(path))
			if not self.ldlinux_so and name.startswith('ld-linux'):
				self.ldlinux_so = os.path.realpath(path)
			if path in dns_files or path in thread_files:
				continue
			if self._dns_rx.search(name):
				dns_files[path] = os.path.realpath(path)
			if self._thread_rx.search(name):
				thread_files[path] = os.path.realpath(path)

		self.dns_files = set(dns_files.itervalues())
		self.thread_files = set(thread_files.itervalues())

		for srcdir in libdirs:
			for srcfile in self._srcroot.listdir(srcdir):
				srcpath = os.path.join(srcdir, srcfile)
				srcstat = self.srcstat(srcpath)
				if stat.S_ISLNK(srcstat.st_mode):
					dstpath = os.path.join(srcdir, os.readlink(srcpath))
					self._solinks.setdefault(dstpath, set()).add(srcpath)
		return
