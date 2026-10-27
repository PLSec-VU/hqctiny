#!/bin/sh
KIT=${VALGRIND_KIT:-/mnt/neon}
L=$KIT/libc4/usr/lib/aarch64-linux-gnu
export VALGRIND_LIB=$KIT/vg/usr/libexec/valgrind
exec $KIT/vg/usr/bin/valgrind --error-exitcode=9 --track-origins=yes $L/ld-linux-aarch64.so.1 --library-path $L "$@"
