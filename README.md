# Tattlenet
A utility to detect open Telnet ports and audit their password security. Use responsibly please.

![Logo](logo.svg)

## Overview
This utility can be used to do a couple of things:

* You can scan IP address ranges for open Telnet ports. These ranges are expressed in a flexible syntax.
* You can audit the password security of those Telnet-enabled devices by running password guessing attacks against them.

It's designed to be as simple as possible to use without shooting yourself (or your network) in the foot. This utility was originally written to audit networked devices for vulnerability to the password guessing attack over Telnet used by the Mirai botnet worm to propagate.

## Building
It's a Python script, so nothing special is needed. Just one of these:

```bash
python3 tattlenet.py
```

## Usage
Briefly, use the program like this to scan yourself for an open Telnet connection:

```
python3 tattlenet.py -ip 127.0.0.1
```

There really aren't that many options to get to grips with.

| Option      | Required? | Description                                                                                 |
|-------------|-----------|---------------------------------------------------------------------------------------------|
| `-ip`       | Yes*      | The IP address range to scan.                                                               |
| `-f`        | Yes*      | The file containing the IP address ranges to scan.                                          |
| `-p`        | No        | Specifies that password guessing attacks **should** be run. Use with care!                  |
| `-b`        | No        | Forces exhaustive password guessing attacks, rather than stopping on successful login.      |
| `-s`        | No        | Silences the banner.                                                                        |
| `-c <file>` | No        | Specifies the file containing credentials to guess. Only relevant in combination with `-p`. |

_\*One or the other of these is required_
