# C Bindings for [`keynesis`] library

We are using makefile to build and generate the necessary libraries.

## Setup

* install rustup
* `make init`: will install the necessary targets
* `make help`: will provide some more details about the available builds

## Local library build

* `make system`: will build the library for the local system;
* `make bindings`: will generate the **C** header file;

Everything will be released and build under the `target` directory.

# Supported platforms

## Apple's platforms:

| Platform | Support | Comments |
|:---------|:-------:|:---------|
| `aarch64-apple-ios` | ✅ | to deploy on iOS |
| `x86_64-apple-ios` | ✅ | to use in the iOS simulator |
| `aarch64-apple-darwin` | ✅ | on Apple M1 devices |
| `x86_64-apple-darwin` | ✅ | on MacOS x86_64 devices |

## Android's platforms:

| Platform | Support | Comments |
|:---------|:-------:|:---------|
| `aarch64-linux-android` | ✅ | to deploy on aarch64 android devices |
| `armv7-linux-androideabi` | ✅ | to deploy on armv7 android devices |
| `x86_64-linux-android` | ✅ | to use in the Android's simulator |

## Microsoft Windows

| Platform | Support | Comments |
|:---------|:-------:|:---------|
| `x86_64-pc-windows-gnu` | ✅ | to use in the Windows 64 bits devices |
| `x86_64-pc-windows-msvc` | ✅ | to use in the Windows 64 bits devices |

## Linux and BSD

| Platform | Support | Comments |
|:---------|:-------:|:---------|
| `aarch64-unknown-linux-gnu` | ✅ | will use the system's libc |
| `aarch64-unknown-linux-musl` | ✅ | will be statically linked to the libc |
| `x86_64-unknown-linux-gnu` | ✅ | will use the system's libc |
| `x86_64-unknown-linux-musl` | ✅ | will be statically linked to the libc |
| `x86_64-unknown-netbsd` | ✅ | |
| `x86_64-unknown-freebsd` | ✅ | |
| `x86_64-unknown-redox` | ✅ | |

[`keynesis`]: https://github.com/primetype/keynesis