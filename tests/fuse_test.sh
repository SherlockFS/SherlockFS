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
    green "[SUCCESS] $3"
    ((test_success++))
else
    red "[ERROR] $3"
    ((test_failed++))
fi
}

testString() {
if [[ "$1" = "$2" ]]; then
    green "[SUCCESS] $3"
    ((test_success++))
else
    red "[ERROR] $3"
    ((test_failed++))
fi
}

blue "\nStarting test ...\n"

cd $MOUNT

# Test create file
touch file
test $? 0 "Creation of a file"

output=$(ls)
testString $output "file" "Listing file"

rm file
test $? 0 "Deleting file"

mkdir dir
test $? 0 "Creation of a directory"

output=$(ls)
testString $output "dir" "Listing one directory"

rm -rf dir
test $? 0 "Deletion of a directory"

echo "This is a test" > file
test $? 0 "Creation and writing to a file"

rm file

green "\nNumber of test successful : $test_success"
red "Number of test failed : $test_failed"

cd ..

# rm $DEVICE
# rm -rf $MOUNT
