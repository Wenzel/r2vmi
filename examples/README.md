# r2vmi python examples

This directory contains examples of use cases for `r2vmi`, on top of `r2pipe` Python bindings.

# Setup

    $ virtualenv -p python3 venv
    $ source venv/bin/activate
    (venv) $ pip install -r requirements.txt

# Rekall

The examples are using the Rekall's `VMIAddressSpace` which is not available on the latest relase.

You will have to install `Rekall` from master:


    (venv) pip install --upgrade setuptools pip wheel
    (venv) git clone https://github.com/google/rekall.git
    (venv) pip install --editable rekall/rekall-lib
    (venv) pip install --editable rekall/rekall-core
    (venv) pip install --editable rekall/rekall-agent
    (venv) pip install --editable rekall

# Examples

## watch_syscall.py

    sudo ./venv/bin/python watch_syscall.py xenwin7 explorer NtOpenKey 2>/dev/null

Output:

    INFO:rekall.1:Autodetected physical address space VMIAddressSpace
    INFO:rekall.1:Cache directory is not specified or invalid. Switching to memory cache.
    INFO:rekall.1:Loaded profile pe from Local Cache - (in 0.24178719520568848 sec)
    INFO:rekall.1:Loaded profile nt/undocumented from Local Cache - (in 0.2355349063873291 sec)
    INFO:rekall.1:Loaded profile nt/GUID/F8E2A8B5C9B74BF4A6E4A48F180099942 from Local Cache - (in 0.6623311042785645 sec)
    INFO:rekall.1:Loaded profile nt/eprocess_index from Local Cache - (in 0.27491211891174316 sec)
    INFO:rekall.1:Detected ntkrnlmp.pdb with GUID F8E2A8B5C9B74BF4A6E4A48F180099942
    INFO:rekall.1:Detected kernel base at 0xF80002617000
    INFO:rekall.1:Loaded profile win32k/index from Local Cache - (in 0.2426774501800537 sec)
    INFO:rekall.1:Loaded profile win32k/GUID/A9F6403F14074E9D8A07D0AA6F0C1CFF2 from Local Cache - (in 0.3131988048553467 sec)
    INFO:root:Loading symbols
    INFO:root:Adding breakpoint on NtOpenKey
    INFO:root:explorer - @NtOpenKey: \Registry\Machine\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers
    INFO:root:explorer - @NtOpenKey: AppCompatFlags\Layers
    INFO:root:explorer - @NtOpenKey: Custom\explorer.exe
    INFO:root:explorer - @NtOpenKey: \Registry\MACHINE\Software\Microsoft\Windows\CurrentVersion\SideBySide
    INFO:root:explorer - @NtOpenKey: \Registry\User\S-1-5-21-1625813105-2267665344-3627068389-1000_Classes


Note: redirect stderr to `/dev/null` otherwise you will be flooded with `r2vmi` debug messages.
