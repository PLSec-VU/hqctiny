#!/bin/sh -e
# usage: sync_src.sh COMMIT   Copies a clean checkout of COMMIT (with submodules) to ~/$BUILD_DIR/src on playground.
. "$(dirname "$0")/config.sh"
COMMIT=$(git -C "$REPO" rev-parse "$1")
WT=$(mktemp -d)
git -C "$REPO" worktree add --detach "$WT" "$COMMIT" >/dev/null
git -C "$WT" submodule update --init >/dev/null 2>&1
ssh $PLAY "mkdir -p ~/$BUILD_DIR/src"
rsync -a --delete --exclude target --exclude .git --exclude eval/results --exclude ssprove "$WT"/ $PLAY:$BUILD_DIR/src/
echo $COMMIT | ssh $PLAY "cat > ~/$BUILD_DIR/out-commit.txt"
git -C "$REPO" worktree remove --force "$WT"
echo "synced $COMMIT"
