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


def get_float_valued_arg (name):
    """ Returns the value of a valued argument as an float, or none if that argument was not passed.
    Args:
        name (str): The name of the argument.
    Returns:
        str: The value of the argument as an float, or none if it was not passed.
    """
    value = get_valued_arg(name)
    if not value is None:
        value = float(value)
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


class TelnetStatus(Enum):
    UNKNOWN = 0
    HOST_UNREACHABLE = 1
    CONN_REFUSED = 2
    TELNET_OPEN = 3


def get_telnet_status (host, port=23, timeout=2):
    """ Determines whether Telnet is open on the specified remote host.
    Args:
        host (str): The address of the remote host
        port (int): The port to scan
        timeout (float): The number of seconds to wait before timeout
    Returns:
        True if Telnet is open and listening on the remote host, otherwise false
    """
    result = TelnetStatus.UNKNOWN
    try:
        with Telnet(host, port, timeout=timeout) as tn:
            tn.read_some() # Read a little bit from the socket.
            result = TelnetStatus.TELNET_OPEN
    except ConnectionRefusedError:
        result = TelnetStatus.CONN_REFUSED
    except OSError:
        result = TelnetStatus.HOST_UNREACHABLE
    return result


class TelnetLoginStatus(Enum):
    """ An enumeration of ready states that a Telnet connection can hold.
    """
    DROPPED_CONN = -1
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
        TelnetLoginStatus: The status of the connection
    """
    result = tn.expect([
        b'incorrect',
        b'Last login:|#',
        b'login:',
        b'Password:',
        b'exceeded'])
    return TelnetLoginStatus(result[0])


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
    if status == TelnetLoginStatus.LOGIN_PROMPT:
        tn.write(login.encode('ascii') + b'\n') # Enter login.
    elif status == TelnetLoginStatus.MAXED_RETRIES or status == TelnetLoginStatus.DROPPED_CONN:
        return LoginAttemptStatus.FAIL_AND_CLOSE # Maxed out our retries.
    status = get_status(tn) # Update status.
    if status == TelnetLoginStatus.PASSWORD_PROMPT:
        tn.write(password.encode('ascii') + b'\n') # Enter password.
    elif status == TelnetLoginStatus.LOGIN_INCORRECT:
        return LoginAttemptStatus.FAIL_AND_RETRY # Failed out of the login prompt and back to the login prompt. Retry.
    status = get_status(tn) # Update status.
    if status == TelnetLoginStatus.SHELL_PROMPT:
        return LoginAttemptStatus.SUCCESS_SHELL # We got a shell!
    elif status == TelnetLoginStatus.LOGIN_INCORRECT:
        return LoginAttemptStatus.FAIL_AND_RETRY # Login incorrect.
    return LoginAttemptStatus.FAIL_UNKNOWN # Fatal unknown error.


def printc (color, *args, sep=' ', **kwargs):
    """ A print function that supports console colours.
    Args:
        color (str): The colour to print the message
        sep (str): The separator to insert between values (identical to the `sep` paramater to `print`)
        args (list of str): Arguments to pass to the underlying `print` call
        kwards (dict): Additional keywords to pass to the underlying `print` call
    """
    print(colored(sep.join(map(str, args)), color), **kwargs)


# Partially apply `printc` for logging colours.
info = partial(printc, 'cyan')
fail = partial(printc, 'blue')
warn = partial(printc, 'yellow')
success = partial(printc, 'green')
error = partial(printc, 'red')
fatal = partial(error, 'Fatal:')
irrelevant = partial(printc, 'magenta')


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


def count_candidates (range):
    """ Counts the number of IP addresses that would result from enumeration of a list struture produced by `expand_ip`.
    Args:
        range (list of list of int): The enumerable list structure
    Return:
        int: The number of distinct IP addresses
    """
    # Multiply together list lengths.
    return reduce(lambda x, y: x * y, [len(r) for r in range], 1)


def enumerate_ip_range (range, pref=''):
    """ Enumerates a list struture produced by `expand_ip`.
    Args:
        range (list of list of int): The enumerable list structure
        pref (str): The current prefix (used for recursion)
    Return:
        list of str: The enumerated list of IP addresses
    """
    separator = '' if pref == '' else '.' # Determine necessary separator.
    if len(range) == 0:
        return [pref] # Base case, just return prefix.
    ips = []
    for octet in range[0]:
        # Make recursive call.
        ips.extend(enumerate_ip_range(range[1:], pref + separator + str(octet)))
    return ips


def brute (creds, host, port=23, break_on_success=True, timeout=None):
    """ Bruteforces a Telnet connection on a remote host using a list of credential pairs.
    Args:
        creds (list of list of str): A list of pairs containing logins (first item) and passwords (second item)
        host (str): The address of the remote host
        port (int): The port of the remote Telnet service
        break_on_success (bool): If true, breaks on a successful login, if false continues
        timeout (float): Time to wait on a Telnet connection before timing out in seconds
    Return:
        list of dict: Credentials tried successfully on the machine
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
        login, password = creds[i]['login'], creds[i]['password'] # Destructure login/password tuple.
        info('\u2191 Guess going up:', login + ':' + password)
        result = guess(tn, login, password) # Get result from Telnet connection.
        if result == LoginAttemptStatus.SUCCESS_SHELL: # We got a shell, nice!
            success('\u2193 Successfully logged in with: ' + login + ':' + password)
            result = True
            if break_on_success: # Do we abort because we succeeded?
                break
            refresh_tn() # Refresh connection.
        elif result == LoginAttemptStatus.FAIL_AND_CLOSE: # Our connection was closed.
            warn('\u2b8f We got bounced, maybe because we maxed out our retries. Reconnecting...')
            refresh_tn() # Refresh connection.
            continue # Don't move on to next password.
        fail('\u2193 Login failed with:', login + ':' + password)
        i += 1 # Next!
    return result


def load_creds (path):
    """ Loads a credentials file.
    Args:
        path (str): The path of the file to load
    Returns:
        list of dict: The credentials from the file as dictionaries containing 'login' and 'password' keys
    """
    creds = []
    with open(path, 'r') as file:
        for line in file:
            login, password = line.strip().replace('(none)', '').split(':')
            creds.append({'login': login, 'password': password})
    return creds


def load_target_list (file):
    """ Loads a targets file.
    Args:
        path (str): The path of the file to load
    Returns:
        list of str: The targets from the file
    """
    targets = []
    with open(file, 'r') as f:
        for line in f:
            targets.append(line.strip())
    return targets


# Print banner unless we're suppressing it.
if not is_arg_passed('s'):
    print_banner()

# Get port number.
port_num = get_int_valued_arg('n')
if port_num == None:
    port_num = 23

# Get timeout.
timeout = get_float_valued_arg('t')
if timeout == None:
    timeout = 1

# Capture command-line flags.
break_on_success = not is_arg_passed('b') # Persist with guesses even if we successfully guess password?
pwd_audit = is_arg_passed('p') # Run password security audit?

# Get targets passed.
ips = get_valued_arg('ip')
if ips == None:
    ip_file = get_valued_arg('f') # Assume file instead.
    if ip_file != None:
        if not os.path.isfile(ip_file):
            fatal('Could not read target file.')
            exit(1)
        ips = load_target_list(ip_file) # Read targets from file.
else:
    ips = [ips] # Make this a list too.

# No IP address passed.
if ips == None:
    fatal('No targets specified. Use -ip or -f.')

# We only need credentials if we're doing a password audit.
creds = None
if pwd_audit:
    # Let user know password security audit is enabled.
    info('Password security *WILL* be audited because -p flag passed.')

    # Load credentials file.
    creds_file = get_valued_arg('c')
    if creds_file != None:
        if not os.path.isfile(creds_file):
            fatal('Could not read credentials file.')
            exit(1)
        creds = load_creds(creds_file)

    # No IP address passed.
    if creds == None:
        fatal('No credentials specified. Use -c.')
        exit(1)
else:
    # Let user know password security audit is disabled.
    info('Password security will *NOT* be audited because -p flag not passed.')

# For every IP (or range expression).
for ip in ips:
    # This might be an IP range (e.g. 192.168.0-10.*)
    expanded_ip = expand_ip(ip) # Expand embedded ranges.
    target_count = count_candidates(expanded_ip) # How many candidates?
    info('Now auditing range', ip, 'containing', target_count, 'address(es) for open ports...')

    # Enumerate range.
    enumerated_ips = enumerate_ip_range(expanded_ip)
    listening_targets = []
    for enumerated_ip in enumerated_ips:
        status = get_telnet_status(enumerated_ip, timeout=timeout)
        if status == TelnetStatus.TELNET_OPEN:
            success('Telnet is open on host:', enumerated_ip) # Telnet is open.
            listening_targets.append(enumerated_ip)
        elif status == TelnetStatus.CONN_REFUSED:
            fail('Telnet is closed on host:', enumerated_ip) # Host is online, Telnet isn't.
        elif status == TelnetStatus.HOST_UNREACHABLE:
            irrelevant('Host is inaccessible:', enumerated_ip) # Host is unreachable.
    info('Found', len(listening_targets), 'listening targets:', ', '.join(listening_targets))

    # If password security audit desired, launch guessing attack(s).
    if pwd_audit:
        info('Now auditing password security...')
        for listening_target in listening_targets:
            info('Now bruting', listening_target, 'on port', port_num, 'with', len(creds), 'login/password pairs')
            brute(creds, listening_target, port=port_num, break_on_success=break_on_success)

    # Print summary.
    info('Done!')
