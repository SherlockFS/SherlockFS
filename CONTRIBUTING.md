# Contributing to SherlockFS

First off, thanks for taking the time to contribute! ❤️

All types of contributions are encouraged and valued. See the [Table of Contents](#table-of-contents) for different ways to help and details about how this project handles them. Please make sure to read the relevant section before making your contribution. It will make it a lot easier for us maintainers and smooth out the experience for all involved. The open-source community looks forward to your contributions. 🎉

> And if you like the project, but just don't have time to contribute, that's fine! There are other easy ways to support the project and show your appreciation, which we would also be very happy about:
> - Star the project
> - Talk about it/share it on social media
> - Refer this project in your project's readme
> - Mention the project at local meetups and tell your friends/colleagues
> - (_Write an article in your personal blog to praise this wonderful project 🙂_)

## Table of Contents

- [I Have a Question](#i-have-a-question)
- [I Want To Contribute](#i-want-to-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Your First Code Contribution](#your-first-code-contribution)
  - [Improving The Documentation](#improving-the-documentation)
- [On Your Favorite IDE](#on-your-favorite-ide)
  - [Code Organization](#code-organization)
  - [Coding Style](#coding-style)
  - [Code Testing](#code-testing)
  - [Commit Your Changes](#commit-your-changes)

## I Have a Question

Before you ask a question, it is best to search for existing [Issues](https://github.com/SherlockFS/SherlockFS/issues) that might help you. In case you have found a suitable issue and still need clarification, you can write your question in this issue. It is also advisable to search the internet for answers first.

If there is no issue related to your question:

- Open an [Issue](https://github.com/SherlockFS/SherlockFS/issues/new).
- Provide as much context as possible, including screenshots, links, and details about your system setup.

You can also contact any project maintainer via email or social media (if you can find them 🙂).

## I Want To Contribute

### Reporting Bugs

If you find a bug in the project, please report it by opening an issue on [GitHub](https://github.com/SherlockFS/SherlockFS/issues). Please include:

- A clear and descriptive title.
- A detailed description of the steps to reproduce the issue.
- Any relevant error messages or screenshots.
- Information about your environment (e.g., operating system, software versions).

> To help you write a good bug report, a template is provided when you click the [New issue](https://github.com/SherlockFS/SherlockFS/issues/new/choose) button.

### Suggesting Enhancements

Enhancement suggestions are tracked as [GitHub issues](https://github.com/SherlockFS/SherlockFS/issues).

- Use a **clear and descriptive title** for the issue to identify the suggestion.
- Provide a **step-by-step description of the suggested enhancement** in as many details as possible.
- **Describe the current behavior** and **explain which behavior you expected to see instead** and why. At this point, you can also tell which alternatives do not work for you.
- You may want to **include screenshots and animated GIFs** which help you demonstrate the steps or point out the part which the suggestion is related to.
- **Explain why this enhancement would be useful** to most SherlockFS users. You may also want to point out the other projects that solved it better and which could serve as inspiration.

> To help you write a good enhancement request, a template is provided when you click the [New issue](https://github.com/SherlockFS/SherlockFS/issues/new/choose) button.

### Your First Code Contribution

We use the [_Gitflow_](https://www.atlassian.com/git/tutorials/comparing-workflows/gitflow-workflow) Git workflow. Each released version (or tag) is on the `main` branch, and the development branch is `dev`.

Pushes to `main` and `dev` are prohibited (and blocked), but you can create feature branches and create a Pull Request on the `dev` branch.
The project owner decides when it is the right time to create a PR from the `dev` branch to the `main` branch in order to create a new release (internal contributors are not allowed to do so).

For external contributors, you can [FORK](https://github.com/SherlockFS/SherlockFS/fork) the project following these guidelines and create a PR on the official repository.

Also, to better understand how to work with the SherlockFS environment, refer to [README.md](https://github.com/SherlockFS/SherlockFS/blob/main/README.md).

### Improving The Documentation

For certain obscur reasons, writing documentation is not currently allowed. This possibility will be available soon.

## On Your Favorite IDE

### Code Organization

The project is structured to maintain a clear and logical organization of the source code:

- **src/**: Contains the program sources.
  - The root of this folder contains the "main()" sources of each program (e.g., `shlkfs.mkfs`, `shlkfs.mount`, ...).
- **src/fs/**: Contains sources related purely to the file system.
- **src/fuse/**: Contains sources related to the FUSE implementation.
- **include/**: Contains the program headers.
- **build/**: Contains compiled executables.
- **tests/**: Contains unit tests.
  - **tests/criterion/**: Contains sources for the Criterion unit testing library.
  - **tests/shlkfs.tests.main.c**: Test file for various functionalities. Usable with `make shlkfs.tests.main` and then `./build/shlkfs.tests.main`. Please clean this file if the content is only necessary for you.

> If you wish to make significant changes to the project's architecture, please thoroughly document your motivations. This will help other contributors understand your changes and maintain the project's coherence.

### Coding Style

Here are the practices we use in SherlockFS to write readable code.

- **Variable/Function Names**: Use consistent and meaningful names for variables and functions.
- **Composite Names**: Separate composite names with underscores (e.g., `max_value`).
- **English Names**: All names should be in English and correctly spelled.
- **Function Size**: Functions should be short and perform a single task. If a function becomes too long, consider splitting it into smaller functions.
- **Function Prototyping**: All exported functions must have prototypes in header files.
- **Function Documentation**:
  - All functions must have documentation in [Doxygen](https://wikipedia.org/wiki/Doxygen) style.
  - This documentation must be in header files for exported functions and in source files for non-exported functions.
  - This documentation should at least contain:
    - `@brief` (a general description of the function).
    - `@param` (a description of a parameter). Should be written for every parameter.
    - `@return` (a description of the returned value, if any). Should start with the returned type (e.g., `@return size_t ...`)
- **Source Comments**: If some parts of your code are not as straightforward as they should be, consider writing comments in them.
- **Capitalization**:
  - Variable names, function names, and file names: lower case letters, digits, and underscores.
  - Macro names and constants: entirely capitalized with underscores.
- **Include Guards**:
  - You must include an include guard in all header files.
  - You should use the standard include guard (no `#pragma once`):
    ```c
    #ifndef FILE_NAME_H
    #define FILE_NAME_H
    ...
    #endif /* FILE_NAME_H */
    ```
  - The include guard name must match the file name. For example, if the file is named `example_feature.h`, you should have:
    ```c
    #ifndef EXAMPLE_FEATURE_H
    #define EXAMPLE_FEATURE_H
    ...
    #endif /* EXAMPLE_FEATURE_H */
    ```

### Code Testing

All code must be unit tested using the [Criterion](https://github.com/Snaipe/Criterion) library.

An untested code will not be accepted to the `dev` branch (and even less to `main`).

> To install the testing environment, you can run the `dependencies.sh` script (at the root of the project) with the `--with-tests` option.

### Commit Your Changes

Here are some guidelines on how to create good commits.

- **By Feature**: Commits should, as much as possible, be done by feature. Avoid large commits with many changes.
- **Descriptive Messages**: Commit messages should be clear and descriptive, explaining precisely what was done.
