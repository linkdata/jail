# jail

Jail chroot construction kit. 

Sample usage to generate and start a Teamspeak 3 jail:

```shell
start-stop-daemon --start --background --quiet --user teamspeak3 \
        --startas /usr/local/bin/jail -- \
        teamspeak3 --defaults --verbose --dns \
        --add-from /home/teamspeak3 ts3server_linux_x86 tsdns/tsdnsserver_linux_x86 libts3db_sqlite3.so \
        --bind /run/shm rw \
        --bind {userhome} rw,exec \
        --mount \
        --umask 037 --chdir {userhome} --execute LD_LIBRARY_PATH="." ./ts3server_linux_x86
```

The generated jails will be on separate filesystems that are by default very restricted and will only contain binaries needed. They run as a nonprivileged user, and with a stripped-down `/etc` and minimal `/dev` nodes.

## Usage

The CLI usage message here is generated by the `cli.py` package directly from the `jail.py` source.

```
NAME
    jail - Manages directory structures suitable for chroot jails.

SYNOPSIS
    jail [options] user[:group] [commands]

DESCRIPTION
    You must specify the jail name, and you may optionally also specify
    a group. Both of these must conform to the rules for system
    usernames.

    Commands are processed in the order they occur. If a command fails
    jail logs an error message and exits with a nonzero status. With the
    --test option, errors are written to stdout prefixed by # and
    processing continues if at all possible.

    user[:group]
        Set the jail user and optionally group. If group is omitted, it
        defaults to user. They need not be existing system user or group
        names. For more information about jail properties, see --print.

OPTIONS
    --bind srcpath [bindopts [path]]
        If directory srcpath exists when --mount:ing the jail, mount it
        at {jailmount}/path using the bind options bindopts. Create a
        mount point {jailhome}/path if needed. If omitted, path defaults
        to srcpath. If omitted or auto, bindopts is set based on
        srcpath. If srcpath starts with $JAILHOME use exec,ro. If
        srcpath allows writing, use rw, else use ro. If exec is not
        explicitly set, set noexec. Bind options will always contain
        nosuid.

    --chdir path
        Set the current directory inside the jail for --execute.
        Defaults to /.

    --chuid user[:group]
        Set the user and primary group to run as for --execute. Defaults
        to the jails {uid} and {gid}.

    --defaults, -d
        Enable jail default options and contents. Use --print 
        {defaults_text} for more details.

    --dns
        Add DNS libraries even if no executables or libraries explicitly
        require them.

    --etc
        Add a minimal set of files from /etc to the jail. Use --print 
        {etc_text} for details.

    --help, -h
        Show help text and exit.

    --lazy
        Causes --umount to use umount with the -l switch. For more
        details, see man 8 umount.

    --ldconfig-cmd command
        Set the command to use when locating the shared object loader.
        Default is ldconfig -p.

    --ldconfig-rx regex
        Set the regular expression used to parse the output from
        --ldconfig-cmd when locating the shared object loader.

    --ldlist-cmd command
        Set the command template to use when listing shared objects.
        Default is {ldlinux_so} --list {path}.

    --ldlist-rx regex
        Set the regular expression used to parse the output from
        --ldlist-cmd when listing shared object dependencies.

    --passwd
        Update or add entries for all users and groups seen in the jail
        /etc/passwd and /etc/group files.

    --test, -t
        Test mode, only print the equivalent shell commands. Since
        nothing is actually done, there will likely be errors that won't
        occur when running without --test, as parent directories may not
        have been created or mounts missing.

    --umask mask
        Set the process umask for --execute. Defaults to 037.

    --validname regex
        Set the regular expression used to check if a given name could
        be used as a system username.

    --verbose, -v
        Be more verbose.

    --writepath regex
        Set the regular expression used to deny or allow writing. A
        command may only make changes if the path matches {writepath}.

COMMANDS
    --add [paths ...]
        Add paths and dependencies to the jail. --clone path
        {jailhome}/path. If path is an executable or a library, --add
        all libraries it depends on.

    --add-from srcdir [files ...]
        Add zero or more files from srcdir to the jail. See --add.

    --add-recurse [--quick] [srcpath ...]
        Add srcpath, dependencies and directory contents to the jail. If
        srcpath is a directory or a symlink to a directory, for each
        entry except . and .., --add-recurse srcpath/entry. If --quick
        is given, assume directory contents are unchanged if the
        directory date and size are unchanged.

    --chflags dstpath flags
        On systems that support it, change the file flags of dstpath to
        flags.

    --chmod dstpath mode
        Change the permissions of dstpath to mode.

    --chown dstpath user[:group]
        Change the ownership of dstpath to user and group. If omitted,
        group is left unchanged.

    --clean
        Remove all files and directories within {jailpriv}.

    --clone srcpath dstpath
        Copy srcpath to dstpath, along with data and metadata. Symlinks
        are copied, not followed. srcpath must exist. If dstpath exists,
        it must have the same type as srcpath (file, device, directory
        or symlink). Clone parent directories from srcpath to dstpath as
        needed. If srcpath is a regular file, copy the content. Copy
        flags, permissions, ownership and mtime.

    --clone-from srcpath dstpath [files ...]
        Clone files from srcpath to dstpath.

    --clone-recurse srcpath dstpath [--quick]
        Clone srcpath to dstpath. If srcpath is a directory,
        --clone-recurse it's contents. If --quick is given, assume
        directory contents are unchanged if their size and modification
        times match.

    --dev
        Create a minimal /dev for jails at {jaildev}.

    --, --execute [name=value ...] program [args ...]
        Execute program inside the jail, replacing the jail script. The
        environment will be cleared except for JAILBASE, PWD, USER,
        HOME, PATH and LANG, and anything provided as name=value before
        program. Everything after --execute is taken as arguments to
        program. --execute implies --passwd and --mount. See also
        --chuid, --umask, --chdir.

    --ln-s target linkname
        Create the symlink linkname referring to target. If linkname
        exists it must be a symlink referring to target.

    --mkdir dstpath [mode [user[:group]]]
        Create the directory dstpath with mode permissions and
        optionally set the owning user and group. mode defaults to 0750.

    --mknod dstpath devtype major [minor]
        Create the special device file dstpath of type devtype. devtype
        must be c or b. If dstpath exists, ensure it has the same type
        and device numbers. If minor is omitted, major is taken to be a
        combined device number.

    --mount
        Mount {jailhome} at {jailmount}, then mount all --bind
        directories. Creates mount point directories in {jailhome} as
        needed.

    --print [fmtstring]
        Print the text fmtstring using python's str.format() method. If
        fmtstring is omitted, prints a list of the available properties.

    --remove
        Remove {jailhome} and {jailpriv}. Implies --umount.

    --rm dstpath
        Remove the file dstpath.

    --rmdir dstpath
        Remove the empty directory dstpath.

    --tmp
        Create a /tmp for jails at {jailtmp}.

    --touch dstpath [mtime]
        Set the modification time of dstpath. dstpath must exist. mtime
        defaults to the current time. Use the time format %Y%m%d%H%M.%S.

    --try
        The next command will ignore failure.

    --umount
        Unmount all mounted directories at or below {jailmount}.
  ```
