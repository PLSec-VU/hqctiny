#!/bin/sh
# Runs a command under Valgrind Memcheck with the ctgrind settings, from VG_ROOT (Valgrind and a matching C library
# unpacked there) when it exists, else from the installed valgrind package.
VG_ROOT=${VG_ROOT:-/mnt/neon}
if [ ! -x "$VG_ROOT/vg/usr/bin/valgrind" ]; then
  exec valgrind --error-exitcode=9 --track-origins=yes "$@"
fi
L=$VG_ROOT/libc4/usr/lib/aarch64-linux-gnu
export VALGRIND_LIB=$VG_ROOT/vg/usr/libexec/valgrind
exec $VG_ROOT/vg/usr/bin/valgrind --error-exitcode=9 --track-origins=yes $L/ld-linux-aarch64.so.1 --library-path $L "$@"
