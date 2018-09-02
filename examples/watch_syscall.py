#!/usr/bin/env python3

# Watch Windows syscalls and print their ObjectName parameter

"""
watch_syscall.

Usage:
    watch_syscall.py [options] <vm_name> <target> <syscall>

Options:
    -h --help                               Show this screen.
    --version                               Show version.
"""


# stdlib
import os
import sys
import logging
import struct
import signal
from pprint import pprint
from pathlib import Path

# local
from utils import RekallVMI

# 3rd
import r2pipe
from docopt import docopt
from IPython import embed

interrupted = False

def sigint_handler(sig, frame):
    print('Ctrl+C received, will quit at next breakpoint hit..')
    global interrupted
    interrupted = True


def read_field(r2, win_field, from_addr):
    format = win_field['size']
    offset = win_field['offset']
    size = struct.calcsize(format)
    output = r2.cmdj('pxj {} @{}+{}'.format(size, from_addr, offset))
    addr, *rest = struct.unpack(format, bytes(output))
    return addr


def main(args):
    level = logging.INFO
    logging.basicConfig(stream=sys.stdout, level=level)
    # catch SIGINT
    signal.signal(signal.SIGINT, sigint_handler)

    vm_name = args['<vm_name>']
    target = args['<target>']
    syscall_name = args['<syscall>']

    # build rekall VMI session
    rekall = RekallVMI(vm_name, 'xen')
    # get syscall
    *rest, syscall_addr = rekall.find_syscall(syscall_name)
    # get some _OBJECT_ATTRIBUTES fields/subfields offsets & size
    win_types = rekall.get_winobj_fields()

    # init r2vmi
    r2_url = "vmi://{}:{}".format(vm_name,target)
    r2 = r2pipe.open(r2_url, ["-d", "-2"])

    logging.info('Setting breakpoint on %s @%s', syscall_name, hex(syscall_addr))
    r2.cmd('db {}'.format(hex(syscall_addr)))
    logging.info('Waiting for breakpoint...')

    global interrupted
    while not interrupted:
        # continue
        r2.cmd('dc')
        registers = r2.cmdj('drj')
        # bp hit !
        object_attributes_addr = registers['r8']
        object_name_addr = read_field(r2, win_types['object_name'], object_attributes_addr)
        buffer_addr = read_field(r2, win_types['buffer'], object_name_addr)
        # read UNICODE_STRING buffer
        output = r2.cmd('psw @{}'.format(hex(buffer_addr)))
        logging.info('%s - @%s: %s', target, syscall_name, output)
        # single step to avoid hitting same breakpoint
        r2.cmd('ds')


if __name__ == '__main__':
   args = docopt(__doc__, version='0.1')
   ret = main(args)
   sys.exit(ret)
