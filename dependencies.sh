#!/bin/bash

# Make sure the script is being executed with superuser privileges.
if [[ "${UID}" -ne 0 ]]; then
    echo "Please run this script with superuser privileges."
    exit 1
fi

# Exit on error
set -e

green() {
    echo -e "\e[32m$1\e[0m"
}

yellow() {
    echo -e "\e[33m$1\e[0m"
}

if [ -x "$(command -v apt)" ]; then
    apt update
    apt install -y \
        build-essential make libssl-dev libfuse-dev
elif [ -x "$(command -v pacman)" ]; then
    pacman -Syu
    pacman -S --noconfirm \
        base-devel make libssl-dev libfuse-dev
else
    red "Unsupported OS: Your system must use 'apt' or 'pacman' packages managers"
    exit 1
fi

# Check that openssl version is 3.0.0 or higher
echo "Checking OpenSSL version..."
if [ -x "$(command -v openssl)" ]; then
    openssl_version=$(openssl version | awk '{print $2}')
    if [ "$(printf '%s\n' "3.0.0" "$openssl_version" | sort -V | head -n1)" = "3.0.0" ]; then
        green "OpenSSL version is '$openssl_version', OK for SherlockFS"
    else
        yellow "OpenSSL version is '$openssl_version', KO for SherlockFS: must be 3.0.0 or higher"
        yellow "You must install OpenSSL 3.0.0 or higher by yourself"
        exit 1
    fi
else
    red "OpenSSL not installed"
    exit 1
fi

green "Dependencies installed successfully!"
exit 0
