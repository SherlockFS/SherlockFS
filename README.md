# SherlockFS v1 - Encrypted File System

![SherlockFS logo](images/SherlockFS_logo.png)

**Development Branch**

[![dev branch tests](https://github.com/SherlockFS/SherlockFS/actions/workflows/test_suite.yml/badge.svg?branch=dev)](https://github.com/SherlockFS/SherlockFS/actions/workflows/test_suite.yml)

**Production Branch**

[![main branch tests](https://github.com/SherlockFS/SherlockFS/actions/workflows/test_suite.yml/badge.svg?branch=main)](https://github.com/SherlockFS/SherlockFS/actions/workflows/test_suite.yml)

## Introduction

SherlockFS is an encrypted file system inspired by the principles of FAT and LUKS. Designed for multiple users, it offers a secure solution for file storage on a device. The current version (v1) of SherlockFS is a software implementation based on FUSE.

## Features

Currently, SherlockFS offers four main tools:

1. `shlkfs.mkfs`: Used to initialize a device with the SherlockFS file system.
2. `shlkfs.mount`: Allows mounting a file system formatted with SherlockFS.
3. `shlkfs.useradd`: Allows adding a new user (via their public key) using an existing user's access (their private key).
4. `shlkfs.userdel`: Allows removing a user from the file system.

## Prerequisites

Before starting, you need to install the dependencies. Run `bash dependencies.sh`. This script is only compatible with the `apt` or `pacman` package managers.

> Since this script installs packages on the system, it must be run with super-user privileges (`root`).

## Compilation

To compile the programs:

- `make`: Compiles all programs.
- `make shlkfs.mkfs`: Compiles only the `shlkfs.mkfs` program.
- `make shlkfs.mount`: Compiles only the `shlkfs.mount` program.
- `make shlkfs.useradd`: Compiles only the `shlkfs.useradd` program.
- `make shlkfs.userdel`: Compiles only the `shlkfs.userdel` program.
- `make check`: Compiles all programs and runs the unit tests.
- `make clean`: Removes files generated by the compilation.
- `make clean.all`: Removes the `build/` folder.

The compiled executables will be found in the `build/` folder.

> If you want to compile the programs with debugging options, you must first set the environment variable `SHLKFS_DEBUG=1`.

## Using the Utilities

### `shlkfs.mkfs`

```shell
# ./build/shlkfs.mkfs

SherlockFS v1 - Format a device
        Usage: ./build/shlkfs.mkfs <device> [label]
```

`shlkfs.mkfs` allows initializing a device with the SherlockFS file system. It takes as parameters the path to the device to be formatted and optionally a label (name of the file system). If the device is already formatted with SherlockFS, you will be asked if you want to reformat it.

Once the formatting is done, the public and private keys used during formatting will be saved in the `~/.shlkfs` folder (`public.pem` and `private.pem`). These keys are necessary to mount the device and add new users to the file system. **It is therefore important to keep them in a safe place and not lose them.**

### `shlkfs.mount`

```shell
# ./build/shlkfs.mount

SherlockFS v1 - Mounting a SherlockFS file system
        Usage: ./build/shlkfs.mount [-k|--key <PRIVATE KEY PATH>] [-v|--verbose] <DEVICE> [FUSE OPTIONS] <MOUNTPOINT>
```

`shlkfs.mount` allows mounting a file system formatted with SherlockFS using FUSE. It takes several parameters:

- `-k` or `--key`: The path to the private key to be used for mounting. This key must correspond to a key registered on the device. If this option is not specified, `shlkfs.mount` will try to use the private key `~/.shlkfs/private.pem`.
- `-v` or `--verbose`: Enables verbose mode, which displays additional information throughout the life of the mounted file system.
- `<DEVICE>`: The path to the device to be mounted. This device must be formatted with SherlockFS.
- `[FUSE OPTIONS]`: Additional options for FUSE, if necessary.
- `<MOUNTPOINT>`: The mount point where the file system should be mounted.

Once the file system is mounted, you can interact with it like any other file system on your machine. Make sure you have the corresponding private key before attempting to mount the file system. If you lose this key, you will not be able to access the data on the SherlockFS file system.

### `shlkfs.useradd`

```shell
# ./build/shlkfs.useradd

SherlockFS v1 - Adding user to device keys storage
        Usage: ./build/shlkfs.useradd <device> <other user public key path> [registered user private key path]
```

`shlkfs.useradd` allows adding a new user to the file system. It takes as parameters the path to the device formatted with SherlockFS, the path to the public key of the user to be added, and optionally the path to the private key of a user already registered on the device. If the private key is not specified, `shlkfs.useradd` will try to use the private key of the current user (the one running the program): `~/.shlkfs/private.pem`.

### `shlkfs.userdel`

```shell
SherlockFS v1 - Deleting user from device keys storage
        Usage: ./build/shlkfs.userdel <device> <deleting user public key path> [registered user private key path]
```

`shlkfs.userdel` allows removing a user from the file system. It takes as parameters the path to the device formatted with SherlockFS, the path to the public key of the user to be removed, and optionally the path to the private key of a user already registered on the device. If the private key is not specified, `shlkfs.userdel` will try to use the private key of the current user (the one running the program): `~/.shlkfs/private.pem`.

## Using Docker

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/SherlockFS/SherlockFS/tree/dev?quickstart=1)

### Creating the Docker Image

To create the Docker image of SherlockFS, you can run the following command from the root of the project repository:

```shell
docker build -t shlkfs .
```

> This image contains all the dependencies needed to compile and run SherlockFS.

### Starting the Development Container

To start a Docker container with the SherlockFS image, you can run the following command from the root of the project repository:

```shell
docker run --privileged -it -v $(pwd):/workspace/SherlockFS shlkfs
```

> This command mounts the project repository located in the current directory into the Docker container, in the `/workspace/SherlockFS` directory.

## Want to Contribute?

We'd love your help! Check out our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines and tips on how to get started.
