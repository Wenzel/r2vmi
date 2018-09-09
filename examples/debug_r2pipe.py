#!/usr/bin/env python3

# Watch Windows syscalls and print their ObjectName parameter

"""
watch_syscall.

Usage:
    watch_syscall.py [options] <vm_name> <target>

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

# 3rd
import r2pipe
from docopt import docopt

def main(args):
    level = logging.INFO
    logging.basicConfig(level=level)

    vm_name = args['<vm_name>']
    target = args['<target>']

    # init r2vmi
    r2_url = "vmi://{}:{}".format(vm_name,target)
    r2 = r2pipe.open(r2_url, ["-d"])
    output = r2.cmd('pd 10')
    logging.info(output)
    logging.info("size of output: %s", len(output))



if __name__ == '__main__':
   args = docopt(__doc__, version='0.1')
   ret = main(args)
   sys.exit(ret)
