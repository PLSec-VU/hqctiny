: "${BUILD_HOST:?set BUILD_HOST to the ssh name of the x86 build host}"
BUILD_ROOT=${BUILD_ROOT:-${STUDY:?}-build}
BUILD_CPUS=${BUILD_CPUS:-12-15}
MEASURE_LOCK=${MEASURE_LOCK:-'$HOME/measure.lock'}
BUILDER_IMAGE=${BUILDER_IMAGE:-arm-builder:2}
PI_ROOT=${PI_ROOT:-/mnt/$STUDY}
PI_LOCK=${PI_LOCK:-/mnt/pi.lock}
VALGRIND_KIT=${VALGRIND_KIT:-/mnt/neon}
