# Dylib Injector

A work in progress dylib injector for MacOS built in C++.

A graphical version of this program with a UI is coming soon!


## Building

Building is as simple as running:
```
g++ -o dylibInjector inject.cpp
```
This will generate a program `dylibInjector`.

## Usage

In the directory of the `dylibInjector` program, run:
```
sudo ./dylibInjector
```
Note that you will need to have admin permissions on your Mac.

## Common Questions

### How do I disable SIP (System Integrity Protection)?

The below guide should help you:
https://developer.apple.com/documentation/security/disabling_and_enabling_system_integrity_protection

### Will this work on an Apple silicon Mac?

No, currently this program has no support for any Mac with an Apple silicon chip and only supports Macs with Intel chips.