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

## Microsoft Windows:

| Platform | Support | Comments |
|:---------|:-------:|:---------|
| `x86_64-pc-windows-gnu` | ✅ | to use in the Windows 64 bits devices |
| `x86_64-pc-windows-msvc` | ✅ | to use in the Windows 64 bits devices |

## Linux's:

| Platform | Support |
|:---------|:-------:|
| `aarch64-unknown-linux-gnu` | ✅ |
| `arm7-unknown-linux-gnueabihf` | ✅ |
| `x86_64-unknown-linux-gnu` | ✅ |
| `x86_64-unknown-linux-musl` | ✅ |
| `mips64el-unknown-linux-gnuabi64` | ✅ |
| `powerpc64le-unknown-linux-gnu` | ✅ |

[`keynesis`]: https://github.com/primetype/keynesis

## License

This project is licensed under the [MIT] **OR** [Apache-2.0] dual license.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in `keynesis-c` by you, shall be licensed as `MIT OR Apache-2.0` dual
license, without any additional terms or conditions.
 