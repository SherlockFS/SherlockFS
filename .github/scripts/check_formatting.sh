function green() {
    echo -e "\033[32m$1\033[0m"
}

function red() {
    echo -e "\033[31m$1\033[0m"
}

function yellow() {
    echo -e "\033[33m$1\033[0m"
}

IS_ALL_CORRECT=1
for file in $(find . -name "*.h" -o -name "*.c" -type f); do
    clang-format -style=file -output-replacements-xml $file | grep "<replacement " >/dev/null
    if [ $? -eq 0 ]; then
        yellow "The file $file is not formatted correctly, please run 'clang-format -i $file'" >&2
        IS_ALL_CORRECT=0
    fi
done
if [ "$IS_ALL_CORRECT" = "0" ]; then
    red "Some files are not formatted correctly. 😢"
    echo 'To fix everything, run `clang-format -i $(find . -name '*.h' -o -name '*.c')`'
    exit 1
else
    green "All files are formatted correctly. 🎉"
    exit 0
fi
