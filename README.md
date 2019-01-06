# r2vmi

[![Join the chat at https://gitter.im/r2vmi/Lobby](https://badges.gitter.im/r2vmi/Lobby.svg)](https://gitter.im/r2vmi/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

Radare2 VMI IO and debugger plugins.

These plugins allow you to debug remote process running in a VM, from the hypervisor-level,
leveraging _Virtual Machine Introspection_.

Based on `Libvmi` to access the VM memory and listen on hardware events.

_Note: since hack.lu 2018, I shifted my work towards an **improved** version of this
project which is more **flexible** and open to any reverse-engineering framework that can act as a **GDB frontend**:_

https://github.com/Wenzel/pyvmidbg

What works:
- Intercept a process by name/PID (_at `CR3` load_)
- Read the registers
- Single-step the process execution
- Set breakpoints
    - software
    - hardware (_based on memory access permissions, page must be mapped_)
- Load Kernel symbols

# Demo

[High quality link](https://drive.google.com/file/d/1R63TdJiP3TjN4t-4FFiPjSFajqfXgZ0C/view?usp=sharing)

The following demonstrate how `r2vmi`:
- intercepts `explorer.exe` process
- sets a `software` breakpoint on `NtOpenKey`
- how the breakpoint is hit (_ignoring hits by not targeted processes_)
- using `radare2` to disassemble `NtOpenFile`'s function
- singlestep the execution
- opening a `Rekall` shell usin the [`VMIAddressSpace`](https://github.com/google/rekall/blob/master/rekall-core/rekall/plugins/addrspaces/vmi.py) to work on the VM's physical memory
- running `pslist` plugin
- running `dlllist` plugin and selecting a random `DLL`'s base address
- seeking there in `radare2` and displaying the `MZ` header

![R2VMI_DEMO](https://github.com/Wenzel/wenzel.github.io/raw/master/public/images/r2vmi_demo.gif)

# Requirements

- `Xen 4.6`
- `pkg-config`
- [`libvmi`](http://libvmi.com/)
- [`radare2`](https://github.com/radare/radare2)

# Setup

An complete installation guide is available on the [Wiki](https://github.com/Wenzel/r2vmi/wiki/Project-Setup)

# Usage

You need a virtual machine configured on top of `Xen`, and a process name/pid to intercept

    $ r2 -d vmi://<vm_name>:<name/pid>

Example:

    $ r2 -d vmi://win7:firefox

