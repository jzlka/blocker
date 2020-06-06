#!/bin/sh
#   @file       test.sh
#   @brief      Brief description
#   @author     Jozef Zuzelka <jozef.zuzelka@gmail.com>
#   @date
#    - Created: 06.06.2020 16:16
#    - Edited:  06.06.2020 17:22
#   @version    1.0.0
#   @par        SHELL: zsh 5.7.1 (x86_64-apple-darwin19.0)
#   @bug
#   @todo


BINARY=./blockerd/blockerd
TEST_CNT=100
FILE_SIZE=1KB

function genFiles {
    echo "Generating $1(+) files in $2"
    for (( i=0; i<$1; i++ )); do
        dd if=/dev/random of=$i bs=$FILE_SIZE count=1
    done
}

echo "Testing operations outside Dropbox folder"
srcdir=$(mktemp -d /tmp/blocker.XXXXX)
dstdir=$(mktemp -d /tmp/blocker.XXXXX)

echo "Testing without blocker running"
time find $srcdir -print0 | xargs -0 -I % echo 'test -r "%" && echo "Allowed" || echo "Blocked"' | bash

echo "Generating $TEST_CNT(+) events to be allowed"
genFiles $TEST_CNT $srcdir
sudo $BINARY -v 2 -d ronly 2>&1 &
PID=$!

# Not safe but working
# https://stackoverflow.com/questions/6958689/running-multiple-commands-with-xargs
time find $srcdir -print0 | xargs -0 -I % echo 'test -r "%" && echo "Allowed" || echo "Blocked"' | bash

kill -2 $PID
wait $PID
read -e -p "Check stats. Ready to continue? "

echo "Generating 200(+) events to be blocked"
echo "Generating 200(+) events to be blocked and 200(+) events to be allowed"

echo "Testing operations inside Dropbox folder"
