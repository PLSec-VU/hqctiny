#!/bin/sh -e
cd "$HOME/${BUILD_DIR:?}"
sh build/remote_build.sh
sh build/remote_extra.sh
