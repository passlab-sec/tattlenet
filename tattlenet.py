#!/usr/bin/python3

import os
import sys
import re
from enum import Enum
from functools import reduce, partial
from telnetlib import Telnet
from termcolor import colored


# The utility version, displayed in the banner.
VERSION = 'v0.9.0.0'


def print_banner ():
    """ Prints the banner for the application.
    """
    print('#                                                              \n' +
          ' #   #####   ##   ##### ##### #      ###### #    # ###### #####\n' +
          '  #    #    #  #    #     #   #      #      ##   # #        #  \n' +
          '   #   #   #    #   #     #   #      #####  # #  # #####    #  \n' +
          '  #    #   ######   #     #   #      #      #  # # #        #  \n' +
          ' #     #   #    #   #     #   #      #      #   ## #        #  \n' +
          '#      #   #    #   #     #   ###### ###### #    # ######   #  \n' +
          '                                                       ' + VERSION + '\n'
          'A utility to detect open Telnet ports and audit their password \n' +
          'security. MIT Licensed. Use responsibly.                       \n')


def is_arg_passed (name):
    """ Returns true if an argument was passed, or false otherwise.
    Args:
        name (str): The name of the argument.
    Returns:
        str: True if a the argument was passed, or false otherwise.
    """
    arg = '-' + name
    return arg in sys.argv


def get_valued_arg (name):
    """ Returns the value of a valued argument, or none if that argument was not passed.
    Args:
        name (str): The name of the argument.
    Returns:
        str: The value of the argument, or none if it was not passed.
    """
    arg = '-' + name
    out = None
    if is_arg_passed(name):
        i = sys.argv.index(arg)
        if len(sys.argv) > i:
            out = sys.argv[i + 1]
    return out


def get_int_valued_arg (name):
    """ Returns the value of a valued argument as an integer, or none if that argument was not passed.
    Args:
        name (str): The name of the argument.
    Returns:
        str: The value of the argument as an integer, or none if it was not passed.
    """
    value = get_valued_arg(name)
    if not value is None:
        value = int(value)
    return value


def split_multi_arg (arg, delim=';'):
    """ Splits a multi-arg string along its delimiter (';' by default).
    Args:
        arg (str): The argument.
        delim (char): The delimited (';' by default).
    Returns:
        list of str: The split argument.
    """
    return arg.split(delim)


def is_telnet_open (host, port=23, timeout=2):
    """ Determines whether Telnet is open on the specified remote host.
    Args:
        host (str): The address of the remote host
        port (int): The port to scan
        timeout (float): The number of seconds to wait before timeout
    Returns:
        True if Telnet is open and listening on the remote host, otherwise false
    """
    result = False
    try:
        with Telnet(host, port, timeout=timeout) as tn:
            tn.read_some() # Read a little bit from the socket.
            result = True
    except:
        result = False
    return result


class TelnetStatus(Enum):
    """ An enumeration of ready states that a Telnet connection can hold.
    """
    LOGIN_INCORRECT = 0
    SHELL_PROMPT = 1
    LOGIN_PROMPT = 2
    PASSWORD_PROMPT = 3
    MAXED_RETRIES = 4


def get_status (tn):
    """ Gets the status of a Telnet connection.
    Args:
        tn (Telnet): The Telnet connection
    Returns:
        TelnetStatus: The status of the connection
    """
    result = tn.expect([
        b'incorrect',
        b'Last login:',
        b'login:',
        b'Password:',
        b'exceeded'])
    return TelnetStatus(result[0])


class LoginAttemptStatus(Enum):
    """ An enumeration of states that can emerge from attempting a Telnet login.
    """
    FAIL_AND_RETRY = 0
    FAIL_AND_CLOSE = 1
    FAIL_UNKNOWN = 2
    SUCCESS_SHELL = 3


def guess (tn, login, password):
    """ Guesses a login and password on a Telnet connection.
    Args:
        tn (Telnet): The Telnet connection
        login (str): The login to guess
        password (str): The password to guess
    Returns:
    """
    status = get_status(tn) # Update status.
    if status == TelnetStatus.LOGIN_PROMPT:
        tn.write(login.encode('ascii') + b'\n') # Enter login.
    elif status == TelnetStatus.MAXED_RETRIES:
        return LoginAttemptStatus.FAIL_AND_CLOSE # Maxed out our retries.
    status = get_status(tn) # Update status.
    if status == TelnetStatus.PASSWORD_PROMPT:
        tn.write(password.encode('ascii') + b'\n') # Enter password.
    elif status == TelnetStatus.LOGIN_INCORRECT:
        return LoginAttemptStatus.FAIL_AND_RETRY # Failed out of the login prompt and back to the login prompt. Retry.
    status = get_status(tn) # Update status.
    if status == TelnetStatus.SHELL_PROMPT:
        return LoginAttemptStatus.SUCCESS_SHELL # We got a shell!
    elif status == TelnetStatus.LOGIN_INCORRECT:
        return LoginAttemptStatus.FAIL_AND_RETRY # Login incorrect.
    return LoginAttemptStatus.FAIL_UNKNOWN # Fatal unknown error.


def printc (color, *args, sep=' ', **kwargs):
    """ A print function that supports console colours.
    Args:
        color (str): The colour to print the message
        sep (str): The separator to insert between values (identical to the `sep` paramater to `print`)
        args (list of str): Arguments to pass to the underlying `print` call
        kwards (dict of str): Additional keywords to pass to the underlying `print` call
    """
    print(colored(sep.join(map(str, args)), color), **kwargs)


# Partially apply `printc` for logging colours.
info = partial(printc, 'cyan')
fail = partial(printc, 'magenta')
warn = partial(printc, 'yellow')
success = partial(printc, 'green')
error = partial(printc, 'red')
fatal = partial(error, 'Fatal:')


def valid_octet (oct):
    """ Validates a single IP address octet.
    Args:
        oct (int): The octet to validate
    Returns:
        bool: True if the octet is valid, otherwise false
    """
    return oct >= 0 and oct <= 255


def valid_octets (*octs):
    """ Validates multiple IP address octets.
    Args:
        octs (list of int): The octets to validate
    Returns:
        bool: True if all octets are valid, otherwise false
    """
    return reduce(lambda x, y: x and valid_octet(y), octs, True)


def expand_ip (ip):
    """ Expands an IP address range expression into an enumerable list structure.
    Args:
        ip (str): The IP address range expression
    Returns:
        list of list of str: The resulting enumerable list structure
    """
    octets = ip.split('.') # Split IP into octets.
    out = [[] for _ in range(0, len(octets))] # Create a list for each octet.
    # Process each octet.
    for i in range(0, len(out)):
        octet = octets[i]
        if octet == '*': # A wildcard covers values 0-255.
            out[i] = list(range(0, 256))
        elif re.match('^[0-9]{1,3}\\-[0-9]{1,3}$', octet): # A range expression covers values low-high (inclusive).
            low, high = map(int, octet.split('-'))
            if valid_octets(low, high): # Validate octets.
                out[i] = list(range(low, high + 1))
            else:
                # Bad range.
                raise ValueError('Range of ' + str(low) + '-' + str(high) + ' is invalid for an octet.')
        elif re.match('^[0-9]+$', octet): # Just a number.
            num = int(octet)
            if valid_octet(num): # Validate octet.
                out[i] = [num]
            else:
                # Valid number, bad octet.
                raise ValueError('Value of ' + str(num) + ' is invalid for an octet.')
        else:
            # Bad octet.
            raise ValueError('Value of ' + octet + ' is invalid for an octet.')
    return out


def brute (creds, host, port=23, break_on_success=True, timeout=None):
    """ Bruteforces a Telnet connection on a remote host using a list of credential pairs.
    Args:
        creds (list of list of str): A list of pairs containing logins (first item) and passwords (second item)
        host (str): The address of the remote host
        port (int): The port of the remote Telnet service
        break_on_success (bool): If true, breaks on a successful login, if false continues
        timeout (float): Time to wait on a Telnet connection before timing out in seconds
    Return:
        bool: True if successful, otherwise false
    """
    result = False # Assume failure.

    # Initiate connection, create function to refresh it.
    tn = None
    def refresh_tn ():
        nonlocal tn # Import from outer scope.
        if tn != None: # Close if needed.
            tn.close()
        tn = Telnet(host, port, timeout=timeout) # Construct connection.
    refresh_tn()

    # Loop over dictionary of guesses.
    i = 0
    while i < len(creds):
        login, password = creds[i] # Destructure login/password tuple.
        info('\u2191 Guess going up:', login + ':' + password)
        result = guess(tn, login, password) # Get result from Telnet connection.
        if result == LoginAttemptStatus.SUCCESS_SHELL: # We got a shell, nice!
            success('\u2193 Successfully logged in with: ' + login + ':' + password)
            result = True
            if break_on_success: # Do we abort because we succeeded?
                break
            refresh_tn() # Refresh connection.
        elif result == LoginAttemptStatus.FAIL_AND_CLOSE: # Our connection was closed.
            warn('\u2b8f We got bounced because we maxed out our retries. Reconnecting...')
            refresh_tn() # Refresh connection.
            continue # Don't move on to next password.
        fail('\u2193 Login failed with:', login + ':' + password)
        i += 1 # Next!
    return result


def enumerate_ip_range (lst, pref=''):
    separator = '' if pref == '' else '.' # Determine necessary separator.
    out = []
    if len(lst) == 1:
        return [pref + separator + str(i) for i in lst[0]]
    else:
        acc = []
        for p in lst[0]:
            acc.extend(enumerate_ip_range(lst[1:], pref + separator + str(p)))
        return acc

def count_candidates (lst):
    lens = [len(l) for l in lst]
    return reduce(lambda x, y: x * y, lens, 1)

def load_creds (file):
    pairs = []
    with open(file, 'r') as f:
        for line in f:
            pairs.append(line.strip().replace('(none)', '').split(':'))
    return pairs

def load_target_list (file):
    lines = []
    with open(file, 'r') as f:
        for line in f:
            lines.append(line)
    return lines


# Persist with guesses even if we successfully guess password?
break_on_success = not is_arg_passed('p')

# Print banner unless we're suppressing it.
if not is_arg_passed('b'):
    print_banner()

# Get targets passed.
ips = get_valued_arg('ip')
if ips == None:
    ip_file = get_valued_arg('f') # Assume file instead.
    if ip_file != None:
        if not os.path.isfile(ip_file):
            error('Could not read target file.')
        ips = load_target_list(ip_file) # Read targets from file.
else:
    ips = [ips] # Make this a list too.

# No IP address passed.
if ips == None:
    fatal('No targets specified. Use -ip or -f.')

# Load credentials file.
creds = None
creds_file = get_valued_arg('c')
if creds_file != None:
    if not os.path.isfile(creds_file):
        fatal('Could not read credentials file.')
    creds = load_creds(creds_file)

# No IP address passed.
if creds == None:
    fatal('No credentials specified. Use -c.')

# For every IP (or range expression).
for ip in ips:
    expanded_ip = expand_ip(ip) # Expand embedded ranges.
    target_count = count_candidates(expanded_ip) # How many candidates?
    info('Now auditing range', ip, 'containing', target_count, 'addresses for open ports...')
    enumerated_ips = enumerate_ip_range(expanded_ip)
    listening_targets = []
    for enumerated_ip in enumerated_ips:
        if is_telnet_open(enumerated_ip, timeout=0.1):
            success('Telnet is open on host:', enumerated_ip)
            listening_targets.append(enumerated_ip)
        else:
            fail('Telnet is closed on host:', enumerated_ip)
    info('Found', len(listening_targets), 'listening targets. Now auditing password security...')
    for listening_target in listening_targets:
        info('Now bruting', listening_target, 'with', len(creds), 'login/password pairs')
        brute(creds, listening_target, break_on_success=break_on_success)
