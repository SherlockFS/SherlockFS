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

testEmpty() {
if [[ -z $1 ]]; then
    green "[SUCCESS] $2"
    ((test_success++))
else
    red "[ERROR] $2"
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

output=$(ls)
testEmpty "$output" "Empty file system"

mkdir dir
test $? 0 "Creation of a directory"

output=$(ls)
testString $output "dir" "Listing one directory"

rm -rf dir
test $? 0 "Deletion of a directory"

echo -n "This is a test" > file
test $? 0 "Creation and writing to a file"

output=$(cat file)
test $? 0 "Reading file"
testString "$output" "This is a test" "Verify content of a file"

echo -n "Append to file" >> file
test $? 0 "Append to file"

output=$(cat file)
testString "$output" "This is a testAppend to file" "Verify append the content of a file"

touch
test $? 1 "Touch without argument"

mkdir symbolic_folder
cp file symbolic_folder/.
test $? 0 "Copy file to folder"

output=$(ls symbolic_folder)
testString "$output" "file" "Listing from directory"

ln -s symbolic_folder/file sym
test $? 0 "Create symbolic link"

output=$(cat sym)
test $? 0 "Reading sym link"
testString "$output" "This is a testAppend to file" "Reading content of sym link"

rm sym
test $? 0 "Deletion of sym link"
rm file

output=$(ls)
testString "$output" "symbolic_folder" "Deletion of sym link and remaining folder"

rm -rf symbolic_folder


blue "\nNumber of test successful : $test_success"
blue "Number of test failed : $test_failed"

cd ..

# rm $DEVICE
# rm -rf $MOUNT
