#!/bin/sh

set -e

if [ ! -f "./env.sh" ]; then
    echo "$0 must be run from the root of the repository."
    exit 2
fi

# Create fake Go workspace if it doesn't exist yet.
workspace="$PWD/build/_workspace"
root="$PWD"
doradir="$workspace/src/github.com/dora"
if [ ! -L "$doradir/ultron" ]; then
    mkdir -p "$doradir"
    cd "$doradir"
    ln -s $root/src ultron
    #cp -rf $root/src ultron
    cd "$root"
fi

# Set up the environment to use the workspace.
GOPATH="$workspace"
export GOPATH
echo $GOPATH

# Run the command inside the workspace.
cd "$doradir/ultron"
PWD="$doradir/ultron"

# Launch the arguments with the configured environment.
exec "$@"
