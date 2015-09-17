#!/usr/bin/env python2

# Copyright (c) 2012-2015, The Linux Foundation. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and
# only version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# this script requires python2. However, we'd like to be able to print
# an informative message to a user who might be unknowingly running
# python3 so we can't allow any python2 print statements to sneak in
# since they result in syntax errors in python3. By importing
# print_function we are requiring ourselves to use the python3 syntax.
from __future__ import print_function

import sys
import os
import re
import time
from optparse import OptionParser

import parser_util
from ramdump import RamDump
from print_out import print_out_str, set_outfile, print_out_section, print_out_exception, flush_outfile

# Please update version when something is changed!'
VERSION = '2.0'

# quick check of system requirements:
major, minor = sys.version_info[:2]
if major != 2:
    print("This script requires python2 to run!\n")
    print("You seem to be running: " + sys.version)
    print()
    sys.exit(1)
if minor != 7 and '--force-26' not in sys.argv:
    from textwrap import dedent
    print(dedent("""
    WARNING! This script is developed and tested with Python 2.7.
    You might be able to get things working on 2.6 by installing
    a few dependencies (most notably, OrderedDict [1])
    and then passing --force-26 to bypass this version check, but
    the recommended and supported approach is to install python2.7.

    If you already have python2.7 installed but it's not the default
    python2 interpreter on your system (e.g. if python2 points to
    python2.6) then you'll need to invoke the scripts with python2.7
    explicitly, for example:

        $ python2.7 $(which ramparse.py) ...

    instead of:

        $ ramparse.py ...

    [1] https://pypi.python.org/pypi/ordereddict"""))
    sys.exit(1)
if '--force-26' in sys.argv:
    sys.argv.remove('--force-26')


def parse_ram_file(option, opt_str, value, parser):
    a = getattr(parser.values, option.dest)
    if a is None:
        a = []
    temp = []
    for arg in parser.rargs:
        if arg[:2] == '--':
            break
        if arg[:1] == '-' and len(arg) > 1:
            break
        temp.append(arg)

    if len(temp) is not 3:
        raise OptionValueError(
            "Ram files must be specified in 'name, start, end' format")

    a.append((temp[0], int(temp[1], 16), int(temp[2], 16)))
    setattr(parser.values, option.dest, a)

if __name__ == '__main__':
    usage = 'usage: %prog [options to print]. Run with --help for more details'
    parser = OptionParser(usage)
    parser.add_option('', '--print-watchdog-time', action='store_true',
                      dest='watchdog_time', help='Print watchdog timing information', default=False)
    parser.add_option('-e', '--ram-file', dest='ram_addr',
                      help='List of ram files (name, start, end)', action='callback', callback=parse_ram_file)
    parser.add_option('-v', '--vmlinux', dest='vmlinux', help='vmlinux path')
    parser.add_option('-n', '--nm-path', dest='nm', help='nm path')
    parser.add_option('-g', '--gdb-path', dest='gdb', help='gdb path')
    parser.add_option('-j', '--objdump-path', dest='objdump', help='objdump path')
    parser.add_option('-a', '--auto-dump', dest='autodump',
                      help='Auto find ram dumps from the path')
    parser.add_option('-o', '--outdir', dest='outdir', help='Output directory')
    parser.add_option('-s', '--t32launcher', action='store_true',
                      dest='t32launcher', help='Create T32 simulator launcher', default=False)
    parser.add_option('', '--t32-host-system', dest='t32_host_system',
                      metavar='HOST', choices=('Linux', 'Windows'),
                      help='T32 host system (for launcher script generation). Supported choices: "Linux", "Windows". Defaults to the system ramparse.py is running on.')
    parser.add_option('-x', '--everything', action='store_true',
                      dest='everything', help='Output everything (may be slow')
    parser.add_option('-f', '--output-file', dest='outfile',
                      help='Name of file to save output')
    parser.add_option('', '--stdout', action='store_true',
                      dest='stdout', help='Dump to stdout instead of the file')
    parser.add_option('', '--phys-offset', type='int',
                      dest='phys_offset', help='use custom phys offset')
    parser.add_option('', '--page-offset', type='int',
                      dest='page_offset', help='use custom page offset')
    parser.add_option('', '--force-hardware', type='int',
                      dest='force_hardware', help='Force the hardware detection')
    parser.add_option(
        '', '--force-version', type='int', dest='force_hardware_version',
        help='Force the hardware detection to a specific hardware version')
    parser.add_option('', '--parse-qdss', action='store_true',
                      dest='qdss', help='Parse QDSS (deprecated)')
    parser.add_option('', '--64-bit', action='store_true', dest='arm64',
                      help='Parse dumps as 64-bit dumps (default)')
    parser.add_option('', '--32-bit', action='store_true', dest='arm32',
                      help='Parse dumps as 32-bit dumps')
    parser.add_option('', '--shell', action='store_true',
                      help='Run an interactive python interpreter with the ramdump loaded')
    parser.add_option('', '--classic-shell', action='store_true',
                      help='Like --shell, but forces the use of the classic python shell, even if ipython is installed')
    parser.add_option('', '--qtf', action='store_true', dest='qtf',
                      help='Use QTF tool to parse and save QDSS trace data')
    parser.add_option('', '--qtf-path', dest='qtf_path',
                      help='QTF tool executable')
    parser.add_option('', '--ipc-help', dest='ipc_help',
                      help='Help for IPC Logging', action='store_true',
                      default=False)
    parser.add_option('', '--ipc-test', dest='ipc_test',
                      help='List of test files for the IPC Logging test command (name1, name2, ..., nameN, <version>)',
                      action='append', default=[])
    parser.add_option('', '--ipc-skip', dest='ipc_skip', action='store_true',
                      help='Skip IPC Logging when parsing everything',
					  default=False)
    parser.add_option('', '--ipc-debug', dest='ipc_debug', action='store_true',
                      help='Debug Mode for IPC Logging', default=False)
    parser.add_option('', '--eval',
                      help='Evaluate some python code directly, or from stdin if "-" is passed. The "dump" variable will be available, as it is with the --shell option.')  # noqa

    for p in parser_util.get_parsers():
        parser.add_option(p.shortopt or '',
                          p.longopt,
                          dest=p.cls.__name__,
                          help=p.desc,
                          action='store_true')

    (options, args) = parser.parse_args()

    if options.outdir:
        if not os.path.exists(options.outdir):
            print ('!!! Out directory does not exist. Creating...')
            try:
                os.makedirs(options.outdir)
            except:
                print ("Failed to create %s. You probably don't have permissions there. Bailing." % options.outdir)
                sys.exit(1)
    else:
        options.outdir = '.'

    if options.outfile is None:
        # dmesg_TZ is a very non-descriptive name and should be changed
        # sometime in the future
        options.outfile = 'dmesg_TZ.txt'

    if not options.stdout:
        set_outfile(options.outdir + '/' + options.outfile)

    print_out_str('Linux Ram Dump Parser Version %s' % VERSION)

    args = ''
    for arg in sys.argv:
        args = args + arg + ' '

    print_out_str('Arguments: {0}'.format(args))

    system_type = parser_util.get_system_type()

    if options.autodump is not None:
        if os.path.exists(options.autodump):
            print_out_str(
                'Looking for Ram dumps in {0}'.format(options.autodump))
        else:
            print_out_str(
                'Path {0} does not exist for Ram dumps. Exiting...'.format(options.autodump))
            sys.exit(1)

    if options.vmlinux is None:
        if options.autodump is None:
            print_out_str("No vmlinux or autodump dir given. I can't proceed!")
            parser.print_usage()
            sys.exit(1)
        autovm = os.path.join(options.autodump, 'vmlinux')
        if os.path.isfile(autovm):
            options.vmlinux = autovm
        else:
            print_out_str("No vmlinux given or found in autodump dir. I can't proceed!")
            parser.print_usage()
            sys.exit(1)

    if not os.path.exists(options.vmlinux):
        print_out_str(
            '{0} does not exist. Cannot proceed without vmlinux. Exiting...'.format(options.vmlinux))
        sys.exit(1)
    elif not os.path.isfile(options.vmlinux):
        print_out_str(
            '{0} is not a file. Did you pass the ram file directory instead of the vmlinux?'.format(options.vmlinux))
        sys.exit(1)

    print_out_str('using vmlinux file {0}'.format(options.vmlinux))

    if options.ram_addr is None and options.autodump is None:
        print_out_str('Need one of --auto-dump or at least one --ram-file')
        sys.exit(1)

    if options.ram_addr is not None:
        for a in options.ram_addr:
            if os.path.exists(a[0]):
                print_out_str(
                    'Loading Ram file {0} from {1:x}--{2:x}'.format(a[0], a[1], a[2]))
            else:
                print_out_str(
                    'Ram file {0} does not exist. Exiting...'.format(a[0]))
                sys.exit(1)

    gdb_path = options.gdb
    nm_path = options.nm
    objdump_path = options.objdump

    if options.arm64:
        print_out_str('--64-bit is deprecated. Dumps are assumed to be 64-bit by default.')
        print_out_str('For 32-bit dumps, use --32-bit.')
    else:
        options.arm64 = not options.arm32

    try:
        import local_settings
        try:
            if options.arm64:
                gdb_path = gdb_path or local_settings.gdb64_path
                nm_path = nm_path or local_settings.nm64_path
                objdump_path = objdump_path or local_settings.objdump64_path
            else:
                gdb_path = gdb_path or local_settings.gdb_path
                nm_path = nm_path or local_settings.nm_path
                objdump_path = objdump_path or local_settings.objdump_path
        except AttributeError as e:
            print_out_str("local_settings.py looks bogus. Please see README.txt")
            missing_attr = re.sub(".*has no attribute '(.*)'", '\\1', e.message)
            print_out_str("Specifically, looks like you're missing `%s'\n" % missing_attr)
            print_out_str("Full message: %s" % e.message)
            sys.exit(1)
    except ImportError:
        cross_compile = os.environ.get('CROSS_COMPILE')
        if cross_compile is not None:
            gdb_path = gdb_path or cross_compile+"gdb"
            nm_path = nm_path or cross_compile+"nm"

    if gdb_path is None or nm_path is None:
        print_out_str("!!! Incorrect path for toolchain specified.")
        print_out_str("!!! Please see the README for instructions on setting up local_settings.py or CROSS_COMPILE")
        sys.exit(1)

    print_out_str("Using gdb path {0}".format(gdb_path))
    print_out_str("Using nm path {0}".format(nm_path))

    if not os.path.exists(gdb_path):
        print_out_str("!!! gdb_path {0} does not exist! Check your settings!".format(gdb_path))
        sys.exit(1)

    if not os.access(gdb_path, os.X_OK):
        print_out_str("!!! No execute permissions on gdb path {0}".format(gdb_path))
        print_out_str("!!! Please check the path settings")
        print_out_str("!!! If this tool is being run from a shared location, contact the maintainer")
        sys.exit(1)

    if not os.path.exists(nm_path):
        print_out_str("!!! nm_path {0} does not exist! Check your settings!".format(nm_path))
        sys.exit(1)

    if not os.access(nm_path, os.X_OK):
        print_out_str("!!! No execute permissions on nm path {0}".format(nm_path))
        print_out_str("!!! Please check the path settings")
        print_out_str("!!! If this tool is being run from a shared location, contact the maintainer")
        sys.exit(1)

    if options.everything:
        options.qtf = True

    dump = RamDump(options, nm_path, gdb_path, objdump_path)

    if options.eval:
        if options.eval == '-':
            code = sys.stdin.read()
        else:
            code = options.eval
        exec(code)
        sys.exit(0)

    if options.shell or options.classic_shell:
        print("Entering interactive shell mode.")
        print("The RamDump instance is available in the `dump' variable\n")
        do_fallback = options.classic_shell
        if not do_fallback:
            try:
                from IPython import embed
                embed()
            except ImportError:
                do_fallback = True

        if do_fallback:
            import code
            import readline
            import rlcompleter
            vars = globals()
            vars.update(locals())
            readline.set_completer(rlcompleter.Completer(vars).complete)
            readline.parse_and_bind("tab: complete")
            shell = code.InteractiveConsole(vars)
            shell.interact()
        sys.exit(0)

    if not dump.print_command_line():
        print_out_str('!!! Error printing saved command line.')
        print_out_str('!!! The vmlinux is probably wrong for the ramdumps')
        print_out_str('!!! Exiting now...')
        sys.exit(1)

    if options.qdss:
        print_out_str('!!! --parse-qdss is now deprecated')
        print_out_str(
            '!!! Please just use --parse-debug-image to get QDSS information')

    if options.watchdog_time:
        print_out_str('\n--------- watchdog time -------')
        get_wdog_timing(dump)
        print_out_str('---------- end watchdog time-----')

    # we called parser.add_option with dest=p.cls.__name__ above,
    # so if the user passed that option then `options' will have a
    # p.cls.__name__ attribute.
    parsers_to_run = [p for p in parser_util.get_parsers()
                      if getattr(options, p.cls.__name__)
                      or (options.everything and not p.optional)]
    for i,p in enumerate(parsers_to_run):
        if i == 0:
            sys.stderr.write("\n")
        sys.stderr.write("    [%d/%d] %s ... " %
                         (i + 1, len(parsers_to_run), p.longopt))
        before = time.time()
        with print_out_section(p.cls.__name__):
            try:
                p.cls(dump).parse()
            except:
                print_out_str('!!! Exception while running {0}'.format(p.cls.__name__))
                print_out_exception()
                sys.stderr.write("FAILED! ")
        sys.stderr.write("%fs\n" % (time.time() - before))
        sys.stderr.flush()
        flush_outfile()

    sys.stderr.write("\n")

    if options.t32launcher or options.everything:
        dump.create_t32_launcher()
