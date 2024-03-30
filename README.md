# libxom

libxom is a library for managing execute-only memory (XoM) on x86_64 Linux.
It can create XoM mappings using Protection Keys or Extended Page Tables,
depending on which is supported by hardware.
See `demo.c` for an example. libxom comes with the `xom` command line tool,
which can launch any dynamically linked ELF-program with its code in XoM.

### Execute-only Memory with Protection Keys

Memory Protection Keys (MPK) are a hardware feature which enables intra-process
memory segmentation. In contrast to the conventional paging mechanisms on x86_64, it has the capability to
enforce execute-only permissions. However, note that Protection Keys can easily be subverted by an unprivileged attacker,
so you should not rely on them for security unless you know exactly what you are doing. To see whether your CPU
supports MPK, run `lscpu | grep pku`. If the output is empty, your CPU lacks support.

### Execute-only Memory with Extended Page Tables

Extended Page Tables (EPT) are a mechanism for [Second Level Address Translation (SLAT)](https://en.wikipedia.org/wiki/Second_Level_Address_Translation)
on Intel platforms. They, too, can enforce execute-only permissions, but only on Intel CPUs and only in
hardware-assisted virtual machines. However, they do not suffer from the same security weaknesses as MPK,
and are thus a more secure option. To use libxom with EPT, you will need a [modified version of the Xen hypervisor](https://github.com/tristan-hornetz/xen.git),
and the modxom kernel module. If configured correctly, this hypervisor also supports a feature called
_Register Clearing_, which overwrites the registers during interrupt handling.
This prevents the system from accessing secrets stored in XoM by inspecting the register state after an interrupt.
You can use the `expect_full_register_clear` macro to gracefully recover from these events.


## Setup

You can build and install libxom with CMake. There are no specific build dependencies, except for a working C compiler
and a build management tool such as GNU Make or Ninja.
If you also want to build modxom, you must run CMake with
```shell
cmake -DEPT=ON ..
```
This will require kernel headers, which you can install with
```shell
apt install linux-headers-$(uname -r)
```
on Debian-based distributions.
Additionally, EPT-enforced XOM depends on a 
modified version of the Xen hypervisor, which you can find [here](https://github.com/tristan-hornetz/xen.git).
Note that you will have to install this hypervisor from source.

## Documentation

You can use [Doxygen](https://www.doxygen.nl/) to generate the documentation from code. 
Additionally, see the comments in `xom.h` and the example code in `demo.c`.

## Warning

libxom is meant as a research tool, and not as a dependable security mechanism. modxom in particular
may cause unexpected crashes, and should not be used on production systems. Use this software at your own risk.
