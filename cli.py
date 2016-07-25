#!/usr/bin/python
"""Supplies a command line interface for an object using
decorators and code introspection.
"""

__copyright__ = "Copyright \302\251 2012 Johan Lindh"
__license__ = "MIT"
__author__ = "Johan Lindh <johan@linkdata.se>"

import sys, os, types
import inspect, re

QUEUED, DIRECT, MAPPER, RESOLVER, FINAL = 0x01, 0x02, 0x04, 0x08, 0x10

class size_t(long):
    """A long integer that converts into a compact human readable string.

    Stores a long integer value containing a byte count, such as
    a file size, memory buffer size or data transfer progression.
    When converted to a string, outputs a compact string, possibly
    with a one-character magnitude suffix (one of 'KMGTPEZY').
    Uses 1024 as an order of magnitude.
    """

    _suffixes = 'KMGTPEZY'
    _format_defaults = dict(fill=' ', align='<', sign='-',
        minimumwidth='3', precision='-1')
    _parse_format_specifier_regex = re.compile(r"""\A
(?:
   (?P<fill>.)?
   (?P<align>[<>=^])
)?
(?P<sign>[-+ ])?
(?P<zeropad>0)?
(?P<minimumwidth>(?!0)\d+)?
(?:\.(?P<precision>[-+]?\d+))?
(?P<magnitude>[KMGTPEZY])?
\Z
""", re.VERBOSE)

    def _parse_format_specifier(self, format_spec):
        m = self._parse_format_specifier_regex.match(format_spec)
        if m is None:
            raise ValueError("Invalid format specifier: " + format_spec)
        format_dict = m.groupdict()
        for key, value in format_dict.iteritems():
            if value is None and key in self._format_defaults:
                format_dict[key] = self._format_defaults[key]
        if format_dict.pop('zeropad') is not None:
            format_dict['fill'] = ' '
            format_dict['align'] = '<'
        format_dict['minimumwidth'] = int(format_dict['minimumwidth'])
        format_dict['precision'] = int(format_dict['precision'])
        return format_dict

    def _format_align(self, body, spec_dict):
        if len(body) > 0 and body[0] in '-+':
            sign = body[0]
            body = body[1:]
        else:
            sign = ''
        if sign != '-':
            if spec_dict['sign'] in ' +':
                sign = spec_dict['sign']
            else:
                sign = ''
        minimumwidth = spec_dict['minimumwidth']
        fill = spec_dict['fill']
        padding = fill*(max(minimumwidth - (len(sign+body)), 0))
        align = spec_dict['align']
        if align == '<':
            result = padding + sign + body
        elif align == '>':
            result = sign + body + padding
        elif align == '=':
            result = sign + padding + body
        else: #align == '^'
            half = len(padding)//2
            result = padding[:half] + sign + body + padding[half:]
        return result

    def __str__(self):
        return self.__format__()

    def __format__(self, fmt=''):
        """Format the value into a compact human readable string.
        The format string syntax:
            [[fill]align][sign][0][minimumwidth][.precision][magnitude]

        The width is inclusive leading sign (if the value is negative)
        and magnitude suffix (if applicable). The string will be padded
        with fill to be at least this long. It may be longer.
        A positive value for precision forces a return string with
        a magnitude suffix to have at least that many decimals.
        A negative precision sets the maximum number of allowed
        digits to return from the fractional part, and insignificant
        fractional digits will be discarded.
        The magnitude, if given, must be one of 'KMGTPEZY' and
        forces the value to reported using that magnitude.
        The width defaults to 5, and is always at least 3.
        The precision defaults to -1.
        """
        spec_dict = self._parse_format_specifier(fmt)
        fmtmag = spec_dict['magnitude']
        width = max(3, spec_dict['minimumwidth'] - (2 if self < 0 else 1))
        minprec = max(0, spec_dict['precision'])
        maxprec = abs(spec_dict['precision'])

        val = abs(self) * pow(10L, maxprec)
        breakval = pow(10L, width + maxprec)
        if fmtmag or val > breakval:
            for suffix in size_t._suffixes:
                val >>= 10
                if (suffix == fmtmag) if fmtmag else (val < breakval):
                    break
        else:
            suffix = ''
            minprec = 0

        val = str((-val) if self < 0 else val).zfill(maxprec + 1)
        if maxprec:
            frac = val[-maxprec:]
            val = val[:-maxprec]
            prec = max(minprec, min(maxprec, width - 1 - len(val)))
            if prec:
                frac = frac[:minprec] + frac[minprec:prec].rstrip('0')
                if frac:
                    val += '.' + frac
        return self._format_align(val + suffix, spec_dict)

class CommandLineError(Exception):
    """Base class for cli exceptions.
    """
    def __init__(self, text=None):
        Exception.__init__(self)
        self.strerror = text or ''
    def __str__(self):
        return self.strerror
    def __repr__(self):
        return '<' + self.__class__.__name__ + ' ' + str(self) + '>'

class ArgumentUnexpectedError(CommandLineError):
    """Raised when a command line argument did not have a
    suitable Handler."""
    pass

class ArgumentMissingError(CommandLineError):
    """Raised if a Command is called with missing parameters.
    """
    pass

class Usage(object):
    """Generate usage text.
    """
    def __init__( self, obj ):
        self.obj = obj
        self.handlers = search(obj)
        self.options = sorted(h for h in self.handlers
            if (h.flags & DIRECT) and h.hasstr)
        self.arguments = sorted(h for h in self.handlers
            if h.hasint)
        self.commands = sorted(h for h in self.handlers
            if (h.flags & QUEUED) and h.hasstr)

    def __format__(self, format_spec=''):
        match = re.match(r'(\d+)?(\.\d+)?([nox])?$', format_spec)
        if match is None:
            raise ValueError('invalid format ' + repr(format_spec))
        tabsize = max(int(match.group(1) or 4), 1)
        maxcol = max(int(match.group(2) or 72), tabsize*3)
        if not match.group(3):
            if os.getenv('TERM', '').startswith('xterm'):
                if sys.stdout.isatty():
                    mode = 'x'
                else:
                    mode = 'o'
            else:
                mode = 'n'
        else:
            mode = 'nox'.find(match.group(3))

        if mode == 'x':
            bold = lambda s: '\033[1m' + s + '\033[0m'
            uline = lambda s: '\033[4m' + s + '\033[0m'
            wordlen = lambda w: len(w) - w.count('\033[') * 4
        elif mode == 'o':
            bold = lambda s: ''.join(c + '\b' + c for c in s)
            uline = lambda s: ''.join('_\b' + c for c in s)
            wordlen = lambda w: len(w) - w.count('\b') * 2
        elif mode == 'n':
            bold = lambda s: s
            uline = lambda s: s
            wordlen = len

        output = []
        out_map = {'*': bold, '_': uline}
        out_rx = re.compile(r'([{0}])(.*?)\1'.format(
            re.escape(''.join(out_map))))
        out_fmt = lambda f, s: out_map[f](s) if s else f
        out_repl = lambda match: out_fmt(*match.groups())

        def out(margin, text):
            accum = []
            indent = ' ' * (margin * tabsize)
            def acc_flush():
                if accum:
                    output.append(indent + ' '.join(accum))
                    del accum[:]
                return len(indent)
            col = len(indent)
            text = out_rx.sub(out_repl, text)
            for word in text.split():
                wlen = wordlen(word)
                if col + wlen > maxcol and accum:
                    col = acc_flush()
                accum.append(word)
                col += wlen + 1
            acc_flush()
            return

        def line(margin, *args):
            out(margin, ' '.join(''.join(flatten(args)).split()))
            return

        def para(margin, *args):
            j = None
            args = list(flatten(args))
            for i, arg in enumerate(args):
                if not arg:
                    line(margin, args[j:i])
                    if j:
                        output.append('')
                    j = i + 1
            line(margin, args[j:])
            return

        def blank():
            if output and output[len(output)-1].startswith(' '):
                output.append('')
            return

        def section(name):
            blank()
            line(0, '*', name, '*')
            return

        scriptname = os.path.basename(sys.argv[0])
        scriptdocs = _cli_docs(self.obj.__class__)

        if scriptdocs:
            section('NAME')
            line(1, scriptname, ' - ', scriptdocs[:1])

        section('SYNOPSIS')
        line(1, '*', scriptname, '*',
            ' [_options_]' if self.options else '',
            ' '.join(h.arglist() for h in self.arguments),
            ' [_commands_]' if self.commands else ''
            )

        if scriptdocs or self.arguments:
            section('DESCRIPTION')
            para(1, scriptdocs[1:])
            for handler in self.arguments:
                blank()
                line(1, handler.arglist())
                para(2, _cli_docs(handler.obj))

        if self.options:
            section('OPTIONS')
            for handler in self.options:
                opts = sorted(
                    (k for k in handler.keys if isinstance(k,str)),
                    key=len, reverse=True )
                blank()
                line(1, ', '.join('*' + o + '*' for o in opts),
                    handler.arglist())
                para(2, _cli_docs(handler.obj))

        if self.commands:
            section('COMMANDS')
            for handler in self.commands:
                blank()
                line(1, ', '.join('*' + k + '*' for k in handler.keys),
                    handler.arglist())
                para(2, _cli_docs(handler.obj))

        return '\n'.join(output)

    def __str__( self ):
        return self.__format__()

def decorate(set_flags, set_keys, set_docs, obj=None):
    """Decorate 'obj' as a CLI handler for the CLI keys 'set_keys'
    with the CLI flags 'set_flags'. If 'set_keys' is a string, it
    will be split. A CLI key is either a string preceeding the first
    command line argument to be used as the handlers parameters,
    or a positive integer identifying which positional command line
    argument is the first handler parameter, starting at 1.
    CLI flags are QUEUED, DIRECT, RESOLVER, MAPPER and FINAL.
    """
    assert set_flags is None or isinstance(set_flags, int)
    assert set_docs is None or isinstance(set_docs, dict)
    if set_keys is not None:
        if isinstance(set_keys, str):
            set_keys = set_keys.split()
        if not hasattr(set_keys, '__iter__' ):
            set_keys = (set_keys,)
    def decorator(obj):
        flags, keys, docs = _cli_get_data(obj) or (0, set(), dict())
        if set_keys:
            keys.update(set_keys)
        if set_docs:
            docs.update(set_docs)
        return _cli_set_data(obj, (flags|set_flags, keys, docs))
    return decorator if obj is None else decorator(obj)

def final(obj=None):
    """Decorator marking a CLI handler as final. Everything that
    follows after it is taken as arguments to the handler.
    """
    return decorate(FINAL, None, None, obj)

def queued(keys, obj=None):
    """Decorator marking an object as a queued CLI handler.
    See 'decorate()' for details.
    """
    return decorate(QUEUED, keys, None, obj)

def direct(keys, obj=None):
    """Decorator marking an object as a direct CLI handler.
    See 'decorate()' for details.
    """
    return decorate(DIRECT, keys, None, obj)

def argtext(arg, text, obj=None):
    """Set the _text_ to use when generating usage help for
    _arg_. If _text_ is None or empty, the argument will
    not be documented in the usage help.
    """
    return decorate(0, None, {arg: text}, obj)

def argument(keys = 1, obj=None):
    """Same as cli.queued(keys)."""
    return queued(keys, obj)

def option(keys, obj=None):
    """Same as cli.direct(keys)."""
    return direct(keys, obj)

def mapper(obj=None):
    """Mark a callable object as a CLI input mapper. Mappers must take a single
    parameter, an iterable yielding strings, and return an iterable
    yielding strings. All mappers are called in the order found.
    """
    assert obj is None or callable(obj)
    return decorate(MAPPER, None, None, obj)

def resolver(obj=None):
    """Mark a callable as a CLI error resolver. The function must
    take a single parameter which will be a Command instance that
    is either missing arguments or is unhandled. Return None to
    raise an error or anything else to prepend to the queue.
    """
    assert obj is None or callable(obj)
    return decorate(RESOLVER, None, None, obj)

def parse(obj, argv, verbose=0):
    """Process argv using Handlers from obj and return a list of
    queued Commands.
    """
    if verbose > 0:
        print '{0}: parse({1},{2},{3})'.format(__name__, obj, argv, verbose)
    if hasattr(argv, '__iter__') and not isinstance(argv, basestring):
        if hasattr(argv, 'pop'):
            indata = argv
        else:
            indata = list(argv)
    else:
        indata = [argv]
    argindex = 0
    output = list()
    mappers = list()
    resolvers = list()
    handlers = dict()
    for handler in search( obj ):
        for k in handler.keys:
            if k in handlers:
                raise KeyError(
                    '{0}: {1!r} already handled by {2}'.format(
                        handler, k, handlers[k]))
            if (handler.flags & (QUEUED|DIRECT)) == 0:
                raise KeyError(
                    '{0}: {1!r} neither QUEUED nor DIRECT'.format(
                        handler, k))
            if (handler.flags & (QUEUED|DIRECT)) == (QUEUED|DIRECT):
                raise KeyError(
                    '{0}: {1!r} both QUEUED and DIRECT'.format(
                        handler, k))
            handlers[k] = handler
        if handler.flags & MAPPER:
            mappers.append(handler)
        if handler.flags & RESOLVER:
            resolvers.append(handler)
        if verbose > 0:
            print '{0}: {1!r}'.format(__name__, handler)

    def command(indata, arg=None):
        if arg is None:
            if hasattr(indata, 'pop'):
                arg = indata.pop(0)
            else:
                arg = indata
                indata = []
        handler = handlers.get(arg)
        return handler.command(indata, arg,
            None if handler.flags & FINAL else handlers) if handler else None

    while indata:
        if verbose > 1:
            print '{0}: indata {1}'.format(__name__, indata)

        arg = indata.pop(0)
        if arg is None:
            continue

        if mappers and isinstance(arg, str):
            map_from = (arg,)
            map_to = map_from
            for handler in mappers:
                cmd = handler.command([map_from])
                map_to = cmd()
                if verbose > 0 and tuple(map_to) != tuple(map_from):
                    print '{0}: {1!r} => {2}'.format(__name__, cmd, map_to)
                map_from = map_to
            if map_to != (arg,):
                if not map_to:
                    continue
                indata[0:0] = map_to[1:]
                arg = map_to[0]

        if isinstance(arg, Command):
            if not arg:
                for handler in resolvers:
                    cmd = handler.command([arg])
                    fix = cmd()
                    if not fix:
                        continue
                    if verbose > 0:
                        print '{0}: {1!r} => {2!r}'.format(__name__, cmd, fix)
                    fix = command(fix)
                    if verbose > 0:
                        print '{0}:  => {1!r}'.format(__name__, fix)
                    if fix:
                        arg = fix
                        break
            if not arg:
                raise ArgumentUnexpectedError(arg.error())
            elif arg.flags & DIRECT:
                if verbose > 0:
                    print __name__ + ': ' + repr(arg)
                inject = arg()
                if inject is not None:
                    if verbose > 0:
                        print __name__ + ':  =>',
                        try:
                            print 'len({0}) {1}'.format(
                                len(inject), type(inject).__name__)
                        except TypeError:
                            print repr(inject)
                    indata[0:0] = (inject, None)
            elif arg.flags & QUEUED:
                if verbose > 0:
                    print __name__ + ': ' + repr(arg)
                output.append(arg)
            else:
                assert False
            continue

        if not isinstance(arg, (str, int)):
            if not hasattr(arg, '__iter__'):
                raise TypeError(
                    '{0!r}: type {1!r} unhandled by {2}.parse()'.format(
                        arg, type(arg).__name__, __name__))
            indata[0:0] = arg
            continue

        cmd = command(indata, arg)
        if cmd is None:
            argindex += 1
            if argindex in handlers:
                indata.insert(0, arg)
                arg = argindex
                cmd = command(indata, argindex)
            else:
                cmd = Command(0, argindex, arg)
        indata.insert(0, cmd)
    # end while indata

    return output

class Command(object):
    """Represents a command line option or argument found by parse().
    """
    def __init__(
            self, flags, key, text,
            func=None, arg_data=None,
            arg_list=None, arg_var=None, arg_kw=None, arg_defs=None,
            name=None
            ):
        self.flags = flags
        self.key = key
        self.text = text
        self.func = func
        self.arg_data = arg_data or list()
        self.arg_list = arg_list or tuple()
        self.arg_var = arg_var
        self.arg_kw = arg_kw
        self.arg_defs = arg_defs or tuple()
        self.arg_need = len(self.arg_list) - len(self.arg_defs)
        self.name = name
        return

    def missing(self):
        return self.arg_list[len(self.arg_data) : self.arg_need]

    def error(self):
        text = repr(self.text) if self.text else self.name
        if not self.name:
            return '{0}: unexpected argument'.format(text)
        if len(self.arg_data) < len(self.arg_list) - len(self.arg_defs):
            missing = ', '.join(repr(n) for n in self.missing())
            return '{0}: missing {1}'.format(text, missing)
        return None

    def __nonzero__(self):
        needed = len(self.arg_list) - len(self.arg_defs)
        return bool(self.name and len(self.arg_data) >= needed)

    def __str__(self):
        return str(self.text)

    def __repr__(self):
        return '<{0}.Command({1}, {2!r}): {3}>'.format(
            __name__, _cli_flagtext(self.flags),
            self.key, self.error() or self.name)

    def __call__(self, *args, **kwargs):
        posargs = tuple(self.arg_data) + tuple(args)
        need_ends = len(self.arg_list) - len(self.arg_defs)
        needed = self.arg_list[len(posargs):need_ends]
        if needed:
            missing_args = '{0!r}: missing {1}'.format(
                self.text or self.name,
                ', '.join(repr(n) for n in needed))
            raise TypeError(missing_args)
        try:
            return self.func(*posargs, **kwargs)
        except CommandLineError, err:
            err.strerror = self.text + ': ' + err.strerror
            raise
        return

class Handler(object):
    """Produces Command instances.
    """
    def __init__(self, obj, data, parent, attr, text):
        self.obj = obj
        self.flags, self.keys, self.docs = data
        self.parent = parent
        self.attr = attr
        self.name = text or repr(obj)
        self.hasint = False
        self.hasstr = False
        self.sortkey = ''
        for k in self.keys:
            assert isinstance(k, (str, int))
            if isinstance(k, str):
                self.hasstr = True
            elif isinstance(k, int):
                self.hasint = True
                k = str(k)
            if len(k) > len(self.sortkey):
                self.sortkey = k
        return

    def argtext(self, arg):
        return (self.docs.get(arg, '_' + arg + '_') or '') if arg else ''

    def arglist(self):
        cmd = self.command()
        arg_list = cmd.arg_list[len(cmd.arg_data):]
        need = len(arg_list) - len(cmd.arg_defs)
        arg_need = [' ' + txt for txt in \
            (self.argtext(arg) for arg in arg_list[:need]) if txt]
        arg_opts = [' [' + txt for txt in \
            (self.argtext(arg) for arg in arg_list[need:]) if txt]
        if cmd.arg_var in self.docs:
            arg_var = ' ' + self.argtext(cmd.arg_var)
        elif cmd.arg_var:
            arg_var = ' [' + cmd.arg_var + ' ...]'
        else:
            arg_var = ''
        return ''.join(arg_need) + \
            ''.join(arg_opts) + \
            (']' * len(arg_opts)) + arg_var

    def __str__( self ):
        return self.name

    def __repr__(self):
        return '<{0}.Handler({1}, {2}): {3}>'.format(
            __name__,
            _cli_flagtext(self.flags),
            list(self.keys) or None,
            self.name)

    def __cmp__(self, other):
        if self.sortkey < other.sortkey:
            return -1
        if self.sortkey > other.sortkey:
            return 1
        return 0

    def command(self, indata=None, key=None, stops=None):
        """Construct a Command object for this Handler using
        arguments from indata and return it.
        """

        func = _cli_func(self.obj)
        if func is None:
            raise TypeError('{0!r}: {1!r} is not callable'.format(
                self.name, self.obj))

        arg_list, arg_var, arg_kw, arg_defs = inspect.getargspec(func)
        arg_defs = arg_defs or tuple()
        arg_data = []
        arg_self = self.parent
        try:
            if func.__self__ is not None:
                del arg_list[0]
                arg_self = None
        except AttributeError:
            pass

        if arg_self is not None:
            arg_data.append(arg_self)
        arg_first = len(arg_data)

        #if not indata or indata[0] is None or indata[0] in stops:
        #    break

        while indata and indata[0] and \
            (arg_var or len(arg_data) < len(arg_list)) and \
            (not stops or indata[0] not in stops):
            arg_data.append(indata.pop(0))

        text_args = tuple((
            repr(s) if ' ' in s else s
            for s in (str(a) for a in arg_data[arg_first:])
            ))
        if isinstance(key, str):
            text = ' '.join((key,) + text_args)
        else:
            text = ','.join(text_args)

        name_args = ','.join((repr(a) for a in arg_data[arg_first:]))
        if callable(self.obj):
            cmd_name = self.name + '(' + name_args + ')'
        else:
            cmd_name = self.name + '=' + (name_args or 'None')

        return Command(
            self.flags, key, text,
            func, arg_data,
            arg_list, arg_var, arg_kw, arg_defs,
            cmd_name
            )

    def __call__( self, *args, **kwargs ):
        return self.command(args)(**kwargs)

def _cli_get_data(obj):
    try:
        return getattr(obj, '_cli_data')
    except AttributeError:
        try:
            return getattr(obj.fget, '_cli_data')
        except AttributeError:
            pass
    return None

def _cli_set_data(obj, data):
    assert data and \
        isinstance(data[0], int) and \
        isinstance(data[1], set) and \
        isinstance(data[2], dict)
    try:
        obj._cli_data = data
    except AttributeError:
        try:
            obj.fget._cli_data = data
        except AttributeError:
            obj = Wrapper(obj, data)
    return obj

def _cli_flagtext(flags):
    return ','.join(s for s in ( \
        ('QUEUED' if flags & QUEUED else None), \
        ('DIRECT' if flags & DIRECT else None), \
        ('MAPPER' if flags & MAPPER else None), \
        ('RESOLVER' if flags & RESOLVER else None)) if s)

def _cli_docs(obj):
    try:
        docs = obj.fset.__doc__
    except AttributeError:
        docs = None
    try:
        docs = docs or obj.fget.__doc__
    except AttributeError:
        pass
    try:
        docs = docs or obj.__doc__
    except AttributeError:
        pass
    return docs.splitlines() if docs else None

def _cli_func(obj):
    if isinstance(obj, (types.FunctionType, types.MethodType)):
        return obj
    try:
        return obj.__call__
    except AttributeError:
        try:
            return obj.fset
        except AttributeError:
            try:
                return obj.fget
            except AttributeError:
                pass
    return None

def flatten(iterable):
    for element in iterable:
        if isinstance(element, basestring):
            yield element
        else:
            try:
                subiterable = iter(element)
            except TypeError:
                yield element
            else:
                for subelement in flatten(subiterable):
                    yield subelement
    return

def search(obj, parent=None, attr=None, text=None, \
    _checked=set(), _result=list()):
    """Return a list of Handler instances for CLI objects in obj.
    """
    _checked.add( id(obj) )
    if text is None:
        try:
            text = obj.__name__
        except AttributeError:
            text = type(obj).__name__+'()'
    else:
        text += '.' + attr

    data = _cli_get_data(obj)
    if data:
        _result.append(Handler(obj, data, parent, attr, text))

    for child in (obj,) + type(obj).__mro__:
        try:
            iterator = child.__dict__.iteritems()
        except AttributeError:
            continue
        for key, value in iterator:
            if not (key.startswith('__') or id(value) in _checked):
                search( value, obj, key, text, _checked, _result )
    return _result

class Wrapper(object):
    """Wraps objects that don't have a dictionaty and aren't properties.
    """
    __slots__ = ('_cli_data', '_obj', '_doc', 'fset')
    def __init__( self, obj, data ):
        self._cli_data = data
        self._obj = obj
        self._doc = None
        if obj is False:
            self.fset = self.enable
        elif obj is True:
            self.fset = self.disable
        else:
            self.fset = self.setvalue
    @property
    def __doc__(self):
        return self._doc
    def __get__(self, obj, objtype):
        return self._obj
    def __set__(self, obj, val):
        self._obj = val
    def __str__(self):
        return str( self._obj )
    def __repr__(self):
        return '<%s.Wrapper %s: %r>' % (
            __name__,
            type(self._obj).__name__,
            self._obj )
    def doc(self, text):
        self._doc = text
        return self
    def fget(self):
        return self._obj
    def enable(self):
        self._obj = True
    def disable(self):
        self._obj = False
    def setvalue(self, value):
        if not isinstance(value, type(self._obj)):
            try:
                value = self._obj.__class__(value)
            except (TypeError, ValueError):
                conversion_failed = 'failed converting {0} to {1}'.format(
                    repr(value), type(self._obj).__name__)
                raise CommandLineError(conversion_failed)
        self._obj = value
