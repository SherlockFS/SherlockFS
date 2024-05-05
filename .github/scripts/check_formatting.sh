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
        yellow "Le fichier $file n'est pas formaté correctement, veuillez exécuter 'clang-format -i $file'" >&2
        IS_ALL_CORRECT=0
    fi
done
if [ "$IS_ALL_CORRECT" = "0" ]; then
    red "Certains fichiers ne sont pas formatés correctement. 😢"
    echo 'Pour tout corriger, exécutez `clang-format -i $(find . -name '*.h' -o -name '*.c')`'
    exit 1
else
    green "Tous les fichiers sont formatés correctement. 🎉"
    exit 0
fi
