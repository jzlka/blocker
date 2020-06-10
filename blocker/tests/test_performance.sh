#!/bin/zsh
#   @file       test_performance.sh
#   @brief      Brief description
#   @author     Jozef Zuzelka <jozef.zuzelka@gmail.com>
#   @date
#    - Created: 06.06.2020 16:16
#    - Edited:  07.06.2020 20:26
#   @version    1.0.0
#   @par        SHELL: zsh 5.7.1 (x86_64-apple-darwin19.0)
#   @bug
#   @todo


BINARY=./blockerd/blockerd
LOG_FILE=./performance.csv
TESTS=5

function genFiles {
    echo "Generating $1 $2 files in $3"
    for (( i=0; i<$1; i++ )); do
        dd if=/dev/random of="$3/$i" bs=$2 count=1 >/dev/null 2>&1
    done
}

# Ask for sudo password upfront
sudo -v

function runTest {
	local test_files=$3
	local file_size=$4
	local tests_cnt=$5
	srcdir=$(mktemp -d "${1}/blockerd.XXXXX")
	genFiles $test_files $file_size $srcdir
	echo "Test_files $test_files, file_size $file_size, tests_cnt $tests_cnt, src $1, dst $2"

    	for (( j=0; j<$tests_cnt; j++ )); do
		dstdir=$(mktemp -d "${2}/blockerd.XXXXX")
		echo "**** Test $j/$tests_cnt from $srcdir to $dstdir"

		echo "*** Testing without blocker running"
		# Not safe but working
		# https://stackoverflow.com/questions/6958689/running-multiple-commands-with-xargs
		#time find $srcdir -print0 | xargs -0 -I % echo 'test -r "%" && echo "Allowed" || echo "Blocked"' | bash
		time_no_block=$( { time cp -R $srcdir/ $dstdir/ 2>/dev/null } 2>&1 )

		# Reinit destination folder
		rm -r $dstdir
		dstdir=$(mktemp -d "${2}/blockerd.XXXXX")

		echo "*** Testing with blocker running"
		sudo $BINARY -v 2 -d ronly 2>&1 | grep -e Summary -A 6 &
		PID=$!

		# Let it initialize
		sleep 1

		time_block=$( { time cp -R $srcdir/ $dstdir/ 2>/dev/null } 2>&1 )

		# Cleanup
		sudo pkill -15 blockerd
		wait $PID
		echo "Files in $srcdir: $(ls -l $srcdir 2>/dev/null | grep -v total | wc -l)"
		echo "Files in $dstdir: $(ls -l $dstdir 2>/dev/null | grep -v total | wc -l)"
		rm -r $dstdir
		printf "$j $file_size $test_files 0 $time_no_block\n" | tee -a $LOG_FILE
		printf "$j $file_size $test_files 1 $time_block\n" | tee -a $LOG_FILE
		echo
	done
	rm -r $srcdir
}

for files in 50 100 200 400 600 800 1000; do
	for folder in /tmp ~/tmp/Dropbox; do
		for size in 1k 1m; do
			runTest /tmp $folder $files $size $TESTS
			echo "-------------------------------------------------------------------"
		done
	done
done
#read -e "?Check stats. Ready to continue? "

#MAX_PARALLEL=4
#nroffiles=$(ls "$SOURCEDIR" | wc -w)
#setsize=$(( nroffiles/MAX_PARALLEL + 1 ))
#ls -1 "$SOURCEDIR"/* | xargs -n "$setsize" | while read workset; do
#  cp -p "$workset" "$TARGETDIR" &
#done
#wait
