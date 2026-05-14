Modify with sudo `#include "queue.h"` to `#include "sys/queue.h"` in `/opt/elfmaster/include/libelfmaster.h`

Modify shiva_dwarf.c line to: `int ret = dwarf_init_b(fd, 0, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &err);`

Install `libelf-dev`

Change all instances of `musl-gcc` to `gcc` in shiva repo

Clone libdwarf from `v2.3.1` and build with cmake

Change makefile `DWARFLIB=` to hard code to your new libdwarf build
Change makefile to include new dwarf header like so:
```makefile
GCC_OPTS= -DDEBUG -fPIC -ggdb \
  -I/home/rzmuda/repos/gh-resolve/test/shiva/libdwarf-code/src/lib/libdwarf \
  -I./ -c
```