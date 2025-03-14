# Spwn

This repository started as a fork of [the original spwn](https://github.com/MarcoMeinardi/spwn). It was a good tools for initialize a PWN challenge, but I wanted more customization, and since it had not been maintained for a couple of years, I started to look into the code to give more freedom to the user. In the end, I ended up completely refactoring the code and adding some useful features.

## Features
- Auto detect files from cwd (executable and all the libs)
- Analyze executable:
  - `checksec`
  - interesting functions
  - seccomp rules
  - cryptographic constants
  - CWEs
- Patch executable:
  - Download and unstrip the libs (loader included) related to the detected libc
  - Set runpath and interpreter of the executable with the libs from the cwd or from the downloaded libs
- Set binary and loader executable
- Interactively generate functions to interact with the binary with a menu
- Generate the solve script from your template
- Download the libc source code

## Usage
```
usage: spwn [-h] [-r REMOTE] [-i] [-t TEMPLATE] [-o] [--source] [--patch PATCH] [--seccomp] [--yara YARA] [--cwe]

spwn is a tool to quickly start a pwn challenge

options:
  -h, --help            show this help message and exit
  -r REMOTE, --remote REMOTE
                        Specify the host:port
  -i, --interactions    Create the interactions
  -t TEMPLATE, --template TEMPLATE
                        Create the script from the template
  -o, --only            Do only the actions specified in args
  --source              Donwload the libc source
  --patch PATCH         Patch the executable with the specified path
  --seccomp             Check seccomp
  --yara YARA           Check for given Yara rules
  --cwe                 Check for CWEs
```

If the files have weird names (such as the libc name not starting with "libc"), the autodetection will fail, the best fix for this is to rename the files.

To understand how the interactions creation works, I suggest to just try it out. It should be pretty straight forward, but if you want to pwn as fast as possible, you cannot waste any time :)

## Installation
Non python tools:
```bash
sudo apt update
sudo apt install patchelf elfutils ruby-rubygems
# Or the equivalent for you package manager
sudo gem install seccomp-tools  # Might not need `sudo`
```
To install [cwe_checker](https://github.com/fkie-cad/cwe_checker)
follow the instructions in their repository.
