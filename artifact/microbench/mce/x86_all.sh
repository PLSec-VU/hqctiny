#!/bin/sh
# usage: x86_all.sh   (on the build host, after build_all.sh)
export STUDY=mce BUILD_ROOT=${BUILD_ROOT:-mce-build} NOLOCK=1
cd "$BUILD_ROOT"
for job in "head test-avx2" "head test-portable" "head bench-requests" "head ct"; do
  sh x86_run.sh $job
done
