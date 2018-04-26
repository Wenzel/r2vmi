# Radare 2 IO VMI plugin

[![Join the chat at https://gitter.im/r2vmi/Lobby](https://badges.gitter.im/r2vmi/Lobby.svg)](https://gitter.im/r2vmi/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

This plugins allow you to debug remote process running in a VM.

It uses `Libvmi` to read and write the process virtual address space and listen on hardware events like
the `CR3` register being written (switching process), or `int3` interrupt being catched.

What works:
- Intercept a process by PID
- Read the registers
- Single-step the process execution

Demo: https://asciinema.org/a/Vm2eXMSOS8faegNQGlH4C9J0u

# Requirements

- `Xen 4.6`
- [`libvmi`](http://libvmi.com/)
- `radare2`
- `pkg-config`

# Setup

    $ make
    $ make install

Note: if `pkgconfig` fails, you need to:

    export PKG_CONFIG_PATH=/usr/lib/pkgconfig

# Usage

You need a virtual machine configured on top of `Xen`, and a process to intercept using its `PID`.

    $ r2 vmi://<vm_name>:<pid>

Example:

    $ r2 vmi://win7:5344

