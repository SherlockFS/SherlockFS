#!/bin/bash

# Exit on error
set -e

green() {
    echo -e "\e[32m$1\e[0m"
}

yellow() {
    echo -e "\e[33m$1\e[0m"
}

if [ -x "$(command -v apt)" ]; then
    sudo apt update
    sudo apt install -y \
        build-essential make libssl-dev libfuse-dev

    green "Dependencies installed successfully"
elif [ -x "$(command -v yum)" ]; then
    sudo pacman -Syu
    sudo pacman -S --noconfirm \
        base-devel make libssl-dev libfuse-dev

    green "Dependencies installed successfully"
else
    red "Unsupported OS"
    exit 1
fi

manual_openssl_install() {
    ossl_version="3.2.0"
    # Ask user if he wants to install OpenSSL $ossl_version
    read -p "Do you want to install OpenSSL '$ossl_version' (using manual wget, tar and make)? [y/n] " -n 1 -r REPLY

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "\nExiting..."
        exit 1
    fi

    echo "Downloading and installing OpenSSL '$ossl_version'"
    # Creating temporary directory
    tmp_dir=$(mktemp -d)

    wget https://www.openssl.org/source/openssl-$ossl_version.tar.gz -P $tmp_dir
    cd $tmp_dir
    tar -xzf openssl-$ossl_version.tar.gz
    cd openssl-$ossl_version
    sudo ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib
    sudo make -j && sudo make -j install

    # Cleaning temporary directory
    rm -rf $tmp_dir

    green "OpenSSL '$ossl_version' installed successfully"
}

# Check that openssl version is 3.0.0 or higher
echo "Checking OpenSSL version..."
if [ -x "$(command -v openssl)" ]; then
    openssl_version=$(openssl version | awk '{print $2}')
    if [ "$(printf '%s\n' "3.0.0" "$openssl_version" | sort -V | head -n1)" = "3.0.0" ]; then
        green "OpenSSL version is '$openssl_version', OK for SherlockFS"
    else
        yellow "OpenSSL version is '$openssl_version', KO for SherlockFS: must be 3.0.0 or higher"
        manual_openssl_install
    fi
else
    red "OpenSSL not installed"
    manual_openssl_install
fi

exit 0
