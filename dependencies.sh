#!/bin/bash
if [ -x "$(command -v apt)" ]; then
    sudo apt update
    sudo apt install -y \
        build-essential make libssl-dev libfuse-dev
elif [ -x "$(command -v yum)" ]; then
    sudo pacman -Syu
    sudo pacman -S --noconfirm \
        base-devel make libssl-dev libfuse-dev
else
    echo "Unsupported OS"
    exit 1
fi
