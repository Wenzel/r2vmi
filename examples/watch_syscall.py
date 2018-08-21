#!/usr/bin/env python3

"""
watch_syscall.

Usage:
    watch_syscall.py [options] <vm_name> <target> <syscall>

Options:
    -d --debug                              Enable logging debug level
    -h --help                               Show this screen.
    --version                               Show version.
"""

# stdlib
import re
import os
import sys
import logging
import json
import struct
from io import StringIO
from pprint import pprint
from pathlib import Path

# 3rd
import r2pipe
from docopt import docopt
from IPython import embed
from rekall import plugins, session

def get_types(session):
    object_name = session.profile.get_obj_offset('_OBJECT_ATTRIBUTES', 'ObjectName')
    buffer = session.profile.get_obj_offset('_UNICODE_STRING', 'Buffer')
    return {
        'object_name': {
                'offset': object_name,
                'size': 'P'
            },
        'buffer': {
                'offset': buffer,
                'size': 'P'
            }
    }

def find_syscall(session, syscall_name):
    strio = StringIO()
    session.RunPlugin("ssdt", output=strio)
    ssdt = json.loads(strio.getvalue())
    for e in ssdt:
        if isinstance(e, list) and e[0] == 'r':
            if e[1]["divider"] is None:
                address = e[1]["symbol"]["address"]
                full_name = e[1]["symbol"]["symbol"]
                m = re.match(r'^(?P<table>.+)!(?P<name>.+)$', full_name)
                if m:
                    name = m.group('name')
                    if name == syscall_name:
                        return address
    raise RuntimeError('Cannot find {} in ssdt'.format(syscall_name))


def read_address(r2, win_field, from_addr):
    format = win_field['size']
    offset = win_field['offset']
    size = struct.calcsize(format)
    output = r2.cmdj('pxj {} @{}+{}'.format(size, from_addr, offset))
    addr, *rest = struct.unpack(format, bytes(output))
    return addr


def main(args):
    debug = args['--debug']
    level = logging.INFO
    if debug:
        level = logging.DEBUG
    logging.basicConfig(level=level)

    vm_name = args['<vm_name>']
    target = args['<target>']
    syscall_name = args['<syscall>']

    rekall_url = 'vmi://xen/{}'.format(vm_name)
    s = session.Session(
            filename=rekall_url,
            autodetect=["rsds"],
            autodetect_build_local='none',
            format='data',
            profile_path=[
                "http://profiles.rekall-forensic.com"
            ])
    syscall_addr = find_syscall(s, syscall_name)
    win_types = get_types(s)
    r2_url = "vmi://{}:{}".format(vm_name,target)
    r2 = r2pipe.open(r2_url, ["-d"])

    logging.info('Loading symbols')
    logging.info('Adding breakpoint on %s', syscall_name)
    r2.cmd('db {}'.format(hex(syscall_addr)))
    r2.cmd('dc')
    while True:
        # clean output
        r2.cmd('dr')
        registers = r2.cmdj('drj')
        object_attributes_addr = registers['r8']
        object_name_addr = read_address(r2, win_types['object_name'], object_attributes_addr)
        buffer_addr = read_address(r2, win_types['buffer'], object_name_addr)
        # read buffer
        output = r2.cmd('psw @{}'.format(hex(buffer_addr)))
        logging.info('%s - @%s: %s', target, syscall_name, output)
        # single step
        r2.cmd('ds')
        # continue
        r2.cmd('dc')


if __name__ == '__main__':
   args = docopt(__doc__, version='0.1')
   ret = main(args)
   sys.exit(ret)
