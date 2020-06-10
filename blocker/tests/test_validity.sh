#!/bin/zsh
#   @file       test_validity.sh
#   @brief      Brief description
#   @author     Jozef Zuzelka <jozef.zuzelka@gmail.com>
#   @date
#    - Created: 07.06.2020 11:39
#    - Edited:  07.06.2020 20:26
#   @version    1.0.0
#   @par        SHELL: zsh 5.7.1 (x86_64-apple-darwin19.0)
#   @bug
#   @todo


function checkResult {
    [[ $? -eq 0 ]] && echo "ALLOWED" || echo "DENIED"
}

function doTest {
	local TESTING_PATH="$1"
	local MODE="$2"
	local tfile=$(mktemp "$TESTING_PATH/blockerd.XXXXX")
	local tfile_remove=$(mktemp "$TESTING_PATH/blockerd.remove.XXXXX")
	local tfile_rename=$(mktemp "$TESTING_PATH/blockerd.rename.XXXXX")
	local log_file=$(mktemp "./blockerd.out.$(echo "$TESTING_PATH" | tr -d '/').$MODE.XXXXX")
	echo TESTING > "$tfile"

	echo "Testing $TESTING_PATH ($MODE)"
	echo "Log file: $log_file"
	sudo $BINARY -v 3 -i $MODE -d $MODE > "$log_file" 2>&1 | grep -e Summary -A 6 &
	[[ $? -ne 0 ]] && echo "Could not run blockerd" && exit
	PID=$!

	# Let it initialize
	sleep 1

	# OPEN
	printf "Testing OPEN (read) <$tfile>: "
	cat "$tfile" >/dev/null 2>&1
	checkResult

	printf "Testing OPEN (write) <$tfile>: "
	{ echo TESTING2 > "$tfile" 2>/dev/null } >/dev/null 2>&1
	checkResult

	# CREATE
	local tfile_create="$TESTING_PATH/blockerd.create.$(cat /dev/urandom | env LC_CTYPE=C tr -cd 'a-f0-9' | head -c 5)"
	printf "Testing CREATE <$tfile_create>: "
	{ touch "$tfile_create" } >/dev/null 2>&1
	checkResult

	# COPY
	local tfile_copy="/tmp/blockerd.copy.$(cat /dev/urandom | env LC_CTYPE=C tr -cd 'a-f0-9' | head -c 5)"
	printf "Testing COPY <$tfile><$tfile_copy>: "
	cp "$tfile" "$tfile_copy" >/dev/null 2>&1
	checkResult

	# MOVE
	local tfile_move="/tmp/blockerd.move.$(cat /dev/urandom | env LC_CTYPE=C tr -cd 'a-f0-9' | head -c 5)"
	printf "Testing MOVE <$tfile><$tfile_move>: "
	mv "$tfile" "$tfile_move" >/dev/null 2>&1
	checkResult

	# REMOVE
	printf "Testing REMOVE <$tfile_remove>: "
	rm $tfile_remove >/dev/null 2>&1
	checkResult

	# RENAME
	local tfile_rename_dst="$TESTING_PATH/blockerd.rename_dst.$(cat /dev/urandom | env LC_CTYPE=C tr -cd 'a-f0-9' | head -c 5)"
	printf "Testing RENAME <$tfile_rename><$tfile_rename_dst>: "
	mv "$tfile_rename" "$tfile_rename_dst" >/dev/null 2>&1
	checkResult

	# DUPLICATE
	local tfile_duplicate="$TESTING_PATH/blockerd.duplicate.$(cat /dev/urandom | env LC_CTYPE=C tr -cd 'a-f0-9' | head -c 5)"
	printf "Testing DUPLICATE <$tfile><$tfile_duplicate>: "
	cp "$tfile" "$tfile_duplicate" >/dev/null 2>&1
	checkResult

	# HARD LINK
	local tfile_hardlink="/tmp/blockerd.hardlink.$(cat /dev/urandom | env LC_CTYPE=C tr -cd 'a-f0-9' | head -c 5)"
	printf "Testing HARD LINK <$tfile><$tfile_hardlink>: "
	ln "$tfile" "$tfile_hardlink" >/dev/null 2>&1
	checkResult

	# SYMBOLIC LINK
	local tfile_symlink="/tmp/blockerd.symlink.$(cat /dev/urandom | env LC_CTYPE=C tr -cd 'a-f0-9' | head -c 5)"
	printf "Testing SYMBOLIC LINK <$tfile><$tfile_symlink>: "
	ln -s "$tfile" "$tfile_symlink" >/dev/null 2>&1
	checkResult

	printf "Testing SYMLINK (read) <$tfile>: "
	cat "$tfile_symlink" >/dev/null 2>&1
	checkResult

	printf "Testing SYMLINK (write) <$tfile>: "
	{ echo TESTING2 > "$tfile_symlink" 2>/dev/null } >/dev/null 2>&1
	checkResult

	# EXCHANGE DATA
	#printf "Testing EXCHANGE DATA: "
	#checkResult


	sudo pkill -15 blockerd
	wait $PID

	read -e "?Delete files?"
	rm "$tfile"
	rm -f "$tfile_create"
	rm -f "$tfile_copy"
	rm -f "$tfile_move"
	rm -f "$tfile_remove"
	rm -f "$tfile_rename"
	rm -f "$tfile_rename_dst"
	rm -f "$tfile_duplicate"
	rm -f "$tfile_harlink"
	rm -f "$tfile_symlink"
}


# Ask for sudo password upfront
sudo -v

DROPBOX_PATH="$HOME/tmp/Dropbox"
ICLOUD_PATH=~"/Library/Mobile Documents/com~apple~CloudDocs"
BINARY=./blockerd

doTest "$DROPBOX_PATH" "ronly"
read -e "?Press any key to continue on next test..."
doTest "$DROPBOX_PATH" "full"
read -e "?Press any key to continue on next test..."
doTest "$ICLOUD_PATH" "ronly"
read -e "?Press any key to continue on next test..."
doTest "$ICLOUD_PATH" "full"
