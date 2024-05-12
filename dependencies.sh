#!/bin/bash

# Check if "-h" or "--help" is passed as an argument
if [[ "${1}" == "-h" || "${1}" == "--help" ]]; then
    echo "This script installs the dependencies required to build SherlockFS."
    echo "If you want to install the dependencies required to run the tests, use the '--with-tests' option."
    echo
    echo "Usage: sudo $0 [-h | --help | --with-tests]"
    exit 0
fi

# Make sure the script is being executed with superuser privileges.
if [[ "${UID}" -ne 0 ]]; then
    echo "Please run this script with superuser privileges."
    exit 1
fi

# Check if "--with-tests" is passed as an argument
if [[ "${1}" == "--with-tests" ]]; then
    WITH_TESTS="true"
else
    WITH_TESTS="false"
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
    PACKAGES="build-essential make libssl-dev libfuse-dev openssl"
    if [ "$WITH_TESTS" = "true" ]; then
        PACKAGES="$PACKAGES libcriterion-dev"
    fi

    apt update
    apt install -y $PACKAGES

elif [ -x "$(command -v pacman)" ]; then
    PACKAGES="base-devel make libssl-dev libfuse-dev openssl"
    if [ "$WITH_TESTS" = "true" ]; then
        PACKAGES="$PACKAGES criterion"
    fi

    pacman -Syu
    pacman -S --noconfirm $PACKAGES
else
    red "Unsupported OS: Your system must use 'apt' or 'pacman' packages managers"
    exit 1
fi

# Check that openssl version is 3.0.0 or higher
echo "Checking OpenSSL version..."
REQUIRED_OPENSSL_VERSION="3.0.10"
if [ -x "$(command -v openssl)" ]; then
    openssl_version=$(openssl version | awk '{print $2}')
    if [ "$(printf '%s\n' "$REQUIRED_OPENSSL_VERSION" "$openssl_version" | sort -V | head -n1)" = "$REQUIRED_OPENSSL_VERSION" ]; then
        green "OpenSSL version is '$openssl_version', OK for SherlockFS"
    else
        yellow "OpenSSL version is '$openssl_version', KO for SherlockFS: must be $REQUIRED_OPENSSL_VERSION or higher"
        yellow "You must install OpenSSL $REQUIRED_OPENSSL_VERSION or higher by yourself"
        exit 1
    fi
else
    red "OpenSSL not installed"
    exit 1
fi

green "Dependencies installed successfully!"
exit 0
