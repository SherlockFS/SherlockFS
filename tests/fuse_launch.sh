#!/bin/bash

blue() {
    echo -e "\e[34m$1\e[0m"
}

green() {
    echo -e "\e[32m$1\e[0m"
}

yellow() {
    echo -e "\e[33m$1\e[0m"
}

red() {
    echo -e "\e[31m$1\e[0m"
}



DEVICE=${1}
MOUNT=${2}
test_failed=0
test_success=0

test() {
    if [ $1 -eq $2 ]; then
    green "[SUCESS] $3"
    ((test_success++))
else
    red "[ERROR] $3"
    ((test_failed++))
fi
}

blue "Starting fuse test"
blue "Create SherlockFS file"
touch $DEVICE
mkdir -p $MOUNT

dd if=/dev/zero of=$DEVICE bs=4096 count=100

green "Device set successfully"

blue "Trying to format to SherlockFS device..."
y |../build/shlkfs.mkfs $DEVICE

if [ $? -eq 0 ]; then
    green "Format successfull"
else
    red "Format failed"
    exit 1
fi

blue "\nLauch FUSE"
../build/shlkfs.mount -v $DEVICE -f $MOUNT > "/dev/null" 2>&1 &


if [ $? -eq 0 ]; then
    green "Fuse launch with success\n"
else
    red "Fuse launch failed\n"
    exit 1
fi

#fuse_test.sh $DEVICE $MOUNT


#umount $MOUNT
