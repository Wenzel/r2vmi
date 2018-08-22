# stdlib
import logging
import re
import json
from io import StringIO

# 3rd
from rekall import plugins, session

class RekallVMI:

    def __init__(self, vm_name, hypervisor=""):
        self.vm_name = vm_name
        self.hypervisor = hypervisor

        rekall_url = 'vmi://{}/{}'.format(self.hypervisor, self.vm_name)
        logging.info('Initializing Rekall VMI address space')
        self.session = session.Session(
                filename=rekall_url,
                autodetect=["rsds"],
                autodetect_build_local='none',
                format='data',
                profile_path=[
                    "http://profiles.rekall-forensic.com"
                ])

    def find_syscall(self, syscall_name):
        strio = StringIO()
        logging.info('Running ssdt plugin')
        self.session.RunPlugin("ssdt", output=strio)
        ssdt = json.loads(strio.getvalue())
        for e in ssdt:
            if isinstance(e, list) and e[0] == 'r':
                if e[1]["divider"] is None:
                    full_name = e[1]["symbol"]["symbol"]
                    m = re.match(r'^(?P<table>.+)!(?P<name>.+)$', full_name)
                    if m:
                        name = m.group('name')
                        if name == syscall_name:
                            address = e[1]["symbol"]["address"]
                            return (full_name, address)
        raise RuntimeError('Cannot find {} in ssdt'.format(syscall_name))

    def get_winobj_fields(self):
        object_name_off = self.session.profile.get_obj_offset('_OBJECT_ATTRIBUTES', 'ObjectName')
        buffer_off = self.session.profile.get_obj_offset('_UNICODE_STRING', 'Buffer')
        return {
            'object_name': {
                    'offset': object_name_off,
                    'size': 'P'
                },
            'buffer': {
                    'offset': buffer_off,
                    'size': 'P'
                }
        }
