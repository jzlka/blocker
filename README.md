Control of External Devices on macOS to Prevent Data Leaks
===
[![Build Status](https://travis-ci.com/TheKuko/blocker.svg?branch=master)](https://travis-ci.com/TheKuko/blocker)
[//]: # ( [![Build status](https://ci.appveyor.com/api/projects/status/gow7petki0obew78?svg=true)](https://ci.appveyor.com/project/TheKuko/namon))


PoC of restricting an access to cloud drives. Uses Endpoint Security framework and currently supports iCloud and (partially) Dropbox
Its functionality is described in *[thesis.pdf](https://thekuko.github.io/blocker/docs/thesis.pdf)* (Chapter 8).

### Features ###
- Shows way of restricting work with **iCloud**
- Shows way of restricting work with **Dropbox**
- In combination with blocking all USB storage drives

### Dependencies ###
- SIP disabled

The application was tested on the following platforms:
- macOS:
    - 10.15.4 Catalina

## Build
```bash
git clone https://github.com/TheKuko/blocker.git
cd blocker/blocker/blockerd
make && cd ../ && ./sign.sh && cd blockerd
```
or
```bash
git clone https://github.com/TheKuko/blocker.git
cd blocker/blocker/
//xcbuild TODO
```
Final binary (_blockerd_) is located in the current folder.

### Makefile parameters

    * make              - build the tool
    * make test         - run basic tests (**TODO**)
    * make clean        - clean compiled binary, object files and \*.dSYM files

[//]: # (    * make clean-all    - clean, clean-tests, clean-doc)
[//]: # (    * make libs         - run helper script to download & install PF_RING/netmap/PFQ [interactive])
[//]: # (    * make pf_ring      - build against PF_RING downloaded in libs/ folder)
[//]: # (    * make netmap       - build against netmap downloaded in libs/ folder)
[//]: # (    * make pfq          - build against PFQ downloaded in libs/ folder)

## Program arguments
```bash
blockerd [-v[<level>]] [<cloud_provider> <block_level>] [-h]
```

|Argument                                |Description                                                                                                                              |
|----------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
|`-h`, `--help`                          |Show help message and exit.                                                                                                              |
|`-v`, `--verbosity`                     |Select verbosity level 0(_disabled_), 1(_error_), 2(_warning_), 3(_info_), 4(_verbose_). If no value is specified `3` is used by default.|
| Supported cloud providers:                                                                                                                                                       |
|`-d`, `--dropbox`                       |Control of Dropbox's shared folders.                                                                                                     |
|`-i`, `--icloud`                        |Control of iCloud's shared folders.                                                                                                      |
| Block levels:                                                                                                                                                                    |
|`none`                                  |Nothing is blocked.                                                                                                                      |
|`ronly`                                 |Only content non-modifying operations are allowed, and background processes needed for cloud synchronization.                            |
|`full`                                  |All file operations are blocked except background processes needed for cloud synchronization.                                            |

## Author
Jozef Zuzelka <jozef.zuzelka@gmail.com>

## More information
* ZUZELKA, Jozef. Control of External Devices on macOS to Prevent Data Leaks. Brno, 2020. Master’s thesis. Brno University of Technology, Faculty of Information Technology. Supervisor Ing. Jan Pluskal ([thesis.pdf](https://thekuko.github.io/blocker/docs/thesis.pdf))
