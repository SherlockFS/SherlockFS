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
elif [ -x "$(command -v yum)" ]; then
    pacman -Syu
    pacman -S --noconfirm \
        base-devel make libssl-dev libfuse-dev
else
    red "Unsupported OS: Your system must use 'apt' or 'pacman' packages managers"
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

    if [ -x "$(command -v apt)" ]; then
        apt remove -y openssl libssl-dev
    elif [ -x "$(command -v yum)" ]; then
        pacman -R openssl libssl-dev
    fi

    echo "Downloading, configuring, compiling and installing OpenSSL '$ossl_version'"
    # Creating temporary directory
    tmp_dir=$(mktemp -d)

    wget https://www.openssl.org/source/openssl-$ossl_version.tar.gz -P $tmp_dir
    cd $tmp_dir
    tar -xzf openssl-$ossl_version.tar.gz
    cd openssl-$ossl_version
    ./config
    make -j
    make -j install

    ldconfig
    ln -s /usr/local/bin/openssl /usr/bin/

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

green "Dependencies installed successfully!"

exit 0
