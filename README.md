# PwnIt

This repository started as a fork of [spwn](https://github.com/MarcoMeinardi/spwn). It was a good tools for initialize a PWN challenge, but I wanted more customization, and since it had not been maintained for a couple of years, I started to look into the code to give more freedom to the user. In the end, I ended up completely refactoring the code and adding some useful features.

## Features
- Auto detect files from cwd (executable and all the libs)
- Analyze executable:
  - `checksec`
  - interesting functions
  - seccomp rules
  - cryptographic constants
- Patch executable:
  - Download and unstrip all the libraries related to the detected libc (loader included)
  - Set runpath and interpreter of the executable with the libraries from the cwd or from the downloaded ones
- Set binary and loader to be executable
- Interactively generate functions to navigate a menu in the binary
- Generate the solve script from your template
- Download the libc source code

## Usage
```
usage: pwnit [-h] [-r REMOTE] [-i] [-t TEMPLATE] [-o] [--libc-source] [--patch] [--seccomp] [--yara]

pwnit is a tool to quickly start a pwn challenge

options:
  -h, --help            show this help message and exit
  -r REMOTE, --remote REMOTE
                        Specify <host>:<port>
  -i, --interactions    Create the interactions
  -t TEMPLATE, --template TEMPLATE
                        Create the script from the template
  -o, --only            Do only the actions specified in args
  --libc-source         Donwload the libc source
  --patch               Patch the executable with the specified path
  --seccomp             Check seccomp
  --yara                Check for given Yara rules
```

If the files have weird names (such as the libc name not starting with `libc`), the autodetection will fail; the best fix for this is to rename the files.

To understand how the interactions creation works, I suggest to just try it out. It should be pretty straight forward, but if you want to pwn as fast as possible, you cannot waste any time :)

## Installation
This tool requires this packages:
```bash
sudo apt update
sudo apt install patchelf elfutils ruby-rubygems
# Or the equivalent for you package manager

sudo gem install seccomp-tools
```
