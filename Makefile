.DEFAULT_GOAL := help
PROJECTNAME=$(shell basename "$(PWD)")
OS_NAME=$(shell uname | tr '[:upper:]' '[:lower:]')

SOURCES=$(sort $(wildcard ./src/*.rs ./src/**/*.rs))
TARGET=$(shell cargo metadata --format-version=1 | jq .target_directory)

PATH := $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(OS_NAME)-x86_64/bin:$(PATH)
SHELL := /bin/bash

ANDROID_AARCH64_LINKER=$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(OS_NAME)-x86_64/bin/aarch64-linux-android30-clang
ANDROID_ARMV7_LINKER=$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(OS_NAME)-x86_64/bin/armv7a-linux-androideabi30-clang
ANDROID_X86_64_LINKER=$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(OS_NAME)-x86_64/bin/x86_64-linux-android30-clang

ifeq ($(OS),Windows_NT)
    SYSTEM_LIB := libkeynesis.dll
else
    SYSTEM_LIB := libkeynesis.a
endif


.PHONY: help
help: Makefile
	@echo
	@echo " Available actions in "$(PROJECTNAME)":"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo

## init: Install missing dependencies.
.PHONY: init
init:
	@if [ $$(uname) == "Darwin" ] ; then rustup target add aarch64-apple-ios x86_64-apple-ios; fi
	@if [ $$(uname) == "Darwin" ] ; then cargo install cargo-lipo ; fi
	rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
	cargo install cbindgen

## all: Compile iOS, Android and bindings targets
all: system ios android bindings

## ios: Compile the iOS universal library
ios: ${TARGET}/universal/release/libkeynesis.a

## compile the local system release
system: ${TARGET}/release/${SYSTEM_LIB}

${TARGET}/release/${SYSTEM_LIB}: $(SOURCES)
	cargo rustc --release -- -C lto

${TARGET}/universal/release/libkeynesis.a: $(SOURCES)
	@if [ $$(uname) == "Darwin" ] ; then \
		if [ "$(release)" == "" ] ; then cargo lipo --release ; \
		else cargo lipo --release --targets aarch64-apple-ios ; \
		fi \
	else echo "Skipping iOS compilation on $$(uname)" ; \
	fi

## android: Compile the android targets (arm64, armv7 and i686)
android: ${TARGET}/aarch64-linux-android/release/libkeynesis.so ${TARGET}/armv7-linux-androideabi/release/libkeynesis.so ${TARGET}/x86_64-linux-android/release/libkeynesis.so ndk-home

${TARGET}/aarch64-linux-android/release/libkeynesis.so: $(SOURCES) ndk-home
	CC_aarch64_linux_android=$(ANDROID_AARCH64_LINKER) \
	CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$(ANDROID_AARCH64_LINKER) \
		cargo build --target aarch64-linux-android --release

${TARGET}/armv7-linux-androideabi/release/libkeynesis.so: $(SOURCES) ndk-home
	CC_armv7_linux_androideabi=$(ANDROID_ARMV7_LINKER) \
	CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER=$(ANDROID_ARMV7_LINKER) \
		cargo build --target armv7-linux-androideabi --release

${TARGET}/x86_64-linux-android/release/libkeynesis.so: $(SOURCES) ndk-home
	CC_x86_64_linux_android=$(ANDROID_X86_64_LINKER) \
	CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER=$(ANDROID_X86_64_LINKER) \
		cargo build --target x86_64-linux-android --release
		
.PHONY: ndk-home
ndk-home:
	@if [ ! -d "${ANDROID_NDK_HOME}" ] ; then \
		echo "Error: Please, set the ANDROID_NDK_HOME env variable to point to your NDK folder" ; \
		exit 1 ; \
	fi

## bindings: Generate the .h file for iOS in the workspace's target
bindings: ${TARGET}/bindings.h

${TARGET}/bindings.h: $(SOURCES)
	cbindgen src/lib.rs -c cbindgen.toml | uniq > $@

## clean:
.PHONY: clean
clean:
	cargo clean
	rm -f ${TARGET}/keynesis.h ${TARGET}/keynesis.src.h
