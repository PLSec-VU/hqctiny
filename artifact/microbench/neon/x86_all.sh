#!/bin/sh
# usage: x86_all.sh   (on the build host, after build_all.sh)
export STUDY=neon BUILD_ROOT=${BUILD_ROOT:-neon-build} NOLOCK=1
cd "$BUILD_ROOT"
for job in "ffull test-avx2" "ffull test-portable" "ffull bench-requests" "base bench-requests" "ffull bench-mul" "ffull ct"; do
  sh x86_run.sh $job
done
