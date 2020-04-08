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

Here's a quick animation showing how to use Tattlenet to scan IP addresses 192.168.66.100-130 for open Telnet ports and audit their password security using the attack dictionary from the original strain of the [Mirai botnet worm](https://github.com/jgamblin/Mirai-Source-Code):

![Demo](demo.svg)

There really aren't that many options to get to grips with.

| Option      | Required? | Description                                                                                 |
|-------------|-----------|---------------------------------------------------------------------------------------------|
| `-ip`       | Yes*      | The IP address range to scan.                                                               |
| `-f`        | Yes*      | The file containing the IP address ranges to scan.                                          |
| `-p`        | No        | Specifies that password guessing attacks **should** be run. Use with care!                  |
| `-b`        | No        | Forces exhaustive password guessing attacks, rather than stopping on successful login.      |
| `-s`        | No        | Silences the banner.                                                                        |
| `-c <file>` | No        | Specifies the file containing credentials to guess. Only relevant in combination with `-p`. |
| `-n <num>`  | No        | Specifies the port number to connect to. Defaults to standard port 23 for Telnet.           |

_\*One or the other of these is required_

## Disclaimer
The standard disclaimer in the MIT license, under which this project is licensed, applies. Also, please use this utility
for its intended purpose: *auditing networks for insecure devices*. Ensure you have permission, in writing, to run this
tool on any network you do not personally own and adhere to applicable laws in your jurisdiction.

## Acknowlegements
* The Mirai attack dictionary bundled with this work was extracted from the [Mirai source code repository](https://github.com/jgamblin/Mirai-Source-Code).
* The font used in the logo is [LCD Solid](https://www.fontspace.com/lcd-solid-font-f11346).
