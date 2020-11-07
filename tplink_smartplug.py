#!/usr/bin/env python3
#
# TP-Link Wi-Fi Smart Plug Protocol Client
# For use with TP-Link HS-100 or HS-110
#
# by Lubomir Stroetmann
# Copyright 2016 softScheck GmbH
# Extensively modified by sylvan butler - github.com/sylvandb/tplink-smartplug
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ipaddress
import json
import socket
from struct import pack, unpack
import time
try:
    from tplink_children import ChildMap
except ImportError:
    # example: {target: (real_target, child_id), ...}
    #   target is the hostname or ip address (less useful) specified
    #   real_target is the parent hostname or ip address
    #   child_id is the 'Id' value of the intended child
    # probably want to alias child hostnames to the parent IP address
    ChildMap = {
        'child1': ('parent', 'parent_deviceId00'),
        'child2': ('parent', 'parent_deviceId01'),
        'child3': ('parent', 'parent_deviceId02'),
    }
    # must have a dictionary ({} for no default map)
    ChildMap = {}

VERSION = 0.17


# Predefined Smart Plug Commands
# For a full list of commands, consult tplink-smarthome-commands.txt
COMMANDS = {
    'info'     : '{"system": {"get_sysinfo": {}}}',
    'on'       : '{"system": {"set_relay_state": {"state": 1}}}',
    'off'      : '{"system": {"set_relay_state": {"state": 0}}}',
    'ledoff'   : '{"system": {"set_led_off": {"off": 1}}}',
    'ledon'    : '{"system": {"set_led_off": {"off": 0}}}',
    'reboot'   : '{"system": {"reboot": {"delay": 1}}}',
    'reset'    : '{"system": {"reset": {"delay": 1}}}', # reset to factory defaults
    'wlanscan' : '{"netif": {"get_scaninfo": {"refresh": 0}}}',
    #'wlanssid' : '{"netif":{"set_stainfo":{"ssid":"%s","password":"%s","key_type":3}}}',
    'time'     : '{"time": {"get_time": {}}}',
    'settime'  : '{"time": {"set_timezone": '
        '{"year": %(yr)d, "month": %(mo)d, "mday": %(md)d, "hour": %(hr)d, "min": %(mi)d, "sec": %(se)d, "index": 42}}}',
    'schedule' : '{"schedule": {"get_rules": {}}}',
    'countdown': '{"count_down": {"get_rules": {}}}',
    'away'     : '{"anti_theft": {"get_rules": {}}}',
    'energy'   : '{"emeter": {"get_realtime": {}}}',
    'cloudinfo': '{"cnCloud": {"get_info": {}}}',
    'bind'     : '{"cnCloud": {"bind": {"username": "%(user)s", "password": "%(pass)s"}}}',
    'unbind'   : '{"cnCloud": {"unbind": ""}}',
# HS220
    'bright'   : '{"smartlife.iot.dimmer": {"set_brightness": {"brightness": %d}}}',
}


# Encryption and Decryption of TP-Link Smart Home Protocol
# XOR Autokey Cipher with starting key
_STARTING_KEY = 171

def encrypt(bytestring):
    key = _STARTING_KEY
    result = []
    for plain in bytestring:
        key ^= plain
        result.append(key)
    return bytes(result)

def decrypt(bytestring):
    key = _STARTING_KEY
    result = []
    for cipher in bytestring:
        result.append(key ^ cipher)
        key = cipher
    return bytes(result)



class CommFailure(Exception):
    pass

class MissingArg(Exception):
    pass


# Send command and receive reply
def communicate(cmd, *, udp=False, broadcast=False, **kwargs):
    if isinstance(cmd, str):
        cmd = encrypt(cmd.encode())
        def reverse(d):
            return decrypt(d).decode()
    else:
        cmd = encrypt(cmd)
        reverse = decrypt
    res = _communicate_udp(cmd, broadcast=broadcast, **kwargs) if udp else _communicate_tcp(cmd, **kwargs)
    return {k: reverse(v) for k, v in res.items()} if udp and broadcast else reverse(res)


def _communicate_tcp(cmd, *, ip, port=9999, timeout=None, **kwargs):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        if timeout:
            sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
        except socket.error:
            raise CommFailure("Could not connect to host %s:%d" % (ip, port))
        else:
            sock.settimeout(None)
            sock.send(pack('>I', len(cmd)) + cmd)
            data = sock.recv(4096)
            dlen = 4 + unpack('>I', data[:4])[0]
            while len(data) < dlen:
                data += sock.recv(4096)
            sock.shutdown(socket.SHUT_RDWR)
    return data[4:]


def _communicate_udp(cmd, *, ip, port=9999, timeout=None, broadcast=False, **kwargs):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        if broadcast:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # must have a timeout to avoid infinite loop/wait
        sock.settimeout(timeout or 3)
        # doesn't seem to use the length header???
        sock.sendto(cmd, (ip, port))
        res = {}
        try:
            while True:
                resp, (respip, respport) = sock.recvfrom(4096)
                if broadcast:
                    res[respip] = resp
                else:
                    res = resp
                    break
        except socket.timeout:
            if not broadcast:
                raise CommFailure("No response from %s:%d" % (ip, port))
    return res


def discover_udp(cmd, trylimit=None, callback=None, **kwargs):
    """
        Used to discover available devices on the local network
        Sends cmd to ip:port as UDP broadcast
        Repeats until no new device responds, unless trylimit or callback
        Repeats trylimit times, unless callback
        Repeats until callback returns True-ish
        Waits timeout for responses
        ip is expected to be a broadcast address or network cidr
        (an ip address or network address or 255.255.255.255)
        return: dict keyed with ipaddress(es): {ipaddress: reply, ...}
    """
    found = {}
    nfound = -1 # makes it try again if none the first try
    trynum = 0
    while True:
        found.update(communicate(cmd, udp=True, broadcast=True, **kwargs))
        trynum += 1
        if callback:
            if callback(trynum, found):
                break
        elif trylimit and trylimit <= trynum:
            break
        elif not trylimit and nfound == len(found):
            break
        nfound = len(found)
    return found


def time_dict(when=None):
    if when is None:
        when = time.localtime()
    try:
        _ = when.tm_year
    except AttributeError:
        when = time.localtime(int(when))
    return {
        'yr': when.tm_year,
        'mo': when.tm_mon,
        'md': when.tm_mday,
        'hr': when.tm_hour,
        'mi': when.tm_min,
        'se': when.tm_sec,
    }

# command to send
def cmd_lookup(*, command=None, json=None, username=None, password=None, argument=None):
    cmd = json if json else COMMANDS[command or 'info']
    if command == 'bind':
        if not username or not password:
            raise MissingArg("%s requires username and password" % (command,))
        cmd = cmd % {'user': username, 'pass': password}
    elif command == 'settime':
        cmd = cmd % time_dict(when=argument)
    if '%d' in cmd or '%s' in cmd or '%(' in cmd:
        if argument is None:
            raise MissingArg("Missing argument for '%s'" % ((json or command),))
        try:
            cmd = cmd % (argument,)
        except TypeError:
            cmd = cmd % (int(argument),)
    return cmd


def get_sysinfo(**kwargs):
    reply = communicate(cmd_lookup(command='info'), **kwargs)
    return json.loads(reply).get('system', {}).get('get_sysinfo')


def add_cmd_context(cmd, child, **kwargs):
    try:
        child = int(child)
    except ValueError:
        pass
    else:
        child = '%s%02x' % (get_sysinfo(**kwargs)['deviceId'], child)
    return '{"context": {"child_ids": ["%s"]},' % (child,) + cmd[1:]




if __name__ == '__main__':
    import argparse
    import sys


    def _cmd_lookup(args):
        return cmd_lookup(**_args_to_dict(args, 'json', 'command', 'username', 'password', 'argument'))

    def _args_to_dict(args, *which, xlate={}):
        d = {attr: getattr(args, attr) for attr in which}
        d.update({key: getattr(args, attr) for attr, key in xlate.items()})
        return d


    def do_command(args, nested=False):
        commargs = _args_to_dict(args, 'port', 'udp', xlate={'target': 'ip'})
        commargs['timeout'] = getattr(args, 'timeout', 5)
        cmd = _cmd_lookup(args)
        if args.child:
            cmd = add_cmd_context(cmd, args.child, **commargs)
        else:
            try:
                try:
                    child = ChildMap[OrigTarget]
                except KeyError:
                    child = ChildMap[args.target]
            except KeyError:
                pass
            else:
                cmd = add_cmd_context(cmd, child, **commargs)
        try:
            reply = communicate(cmd, **commargs)
        except CommFailure as e:
            print("<<%s>>" % (str(e),), file=sys.stderr)
            reply = None
            ec = 2
        else:
            ec = len(reply) <= 0
        if not ec:
            if args.naked_json:
                if nested:
                    print("{\"%s:%d\": %s}" % (args.target, args.port, reply))
                else:
                    print(reply)
            elif not args.silent:
                nested = "%s:%d - " % (args.target, args.port) if nested else ''
                print("%-16s %s%s" % ("Sent(%d):"     % (len(cmd)  ,), nested, cmd))
                print("%-16s %s%s" % ("Received(%d):" % (len(reply),), nested, reply))
        return ec


    def do_discover(args):
        nfound = prev_nfound = -1
        def discover_callback(trynum, found):
            nonlocal nfound, prev_nfound
            print("Found: %d (try %d)" % (len(found), trynum))
            prev_nfound = nfound
            nfound = len(found)
            return nfound == prev_nfound
        cb = None if (args.naked_json or args.silent) else discover_callback
        commargs = {
            'ip': args.target or '255.255.255.255',
            'port': args.port,
            'timeout': getattr(args, 'timeout', 1),
        }
        cmd = _cmd_lookup(args)
        found = discover_udp(cmd, callback=cb, **commargs)
        if args.naked_json and found:
            print("{")
            comma = False
            for ip, reply in found.items():
                print('  %s"%s": %s' % (", " if comma else '', ip, reply))
                comma = True
            print("}")
        elif not args.silent and found:
            for ip, reply in found.items():
                print('  %s:\n    fqdn: %s' % (ip, socket.getfqdn(ip)))
                try:
                    sysi = json.loads(reply).get('system', {}).get('get_sysinfo')
                    for f in ('alias', 'model', 'dev_name', 'mac'):
                        val = sysi.get(f, 'unknown')
                        print('    %s: %s' % (f, val))
                except AttributeError:
                    print('    resp:', reply)
        return not len(found)


    def do_more(multitarget, args):
        rv = 0
        comma = False
        if args.naked_json:
            print("[")
        for more in args.more:
            if multitarget:
                args.target = more
            else:
                args.command = more
            if comma and args.naked_json:
                print(", ", end='')
            rv = (do_discover(args) if args.discover else do_command(args, nested=multitarget)) or rv
            comma = True
        if args.naked_json:
            print("]")
        return rv


    # Check if hostname is a valid ip address or network address or hostname
    # remember original target
    OrigTarget = None
    def validHostname(hostname):
        global OrigTarget
        OrigTarget = hostname
        try:
            hostname = str(ipaddress.ip_network(hostname, strict=False).broadcast_address)
        except ValueError:
            try:
                hostname = socket.gethostbyname(hostname)
            except:
                raise argparse.ArgumentTypeError('Invalid hostname/address "%s"' % (hostname,))
        return hostname

    def validNum(num, minnum, maxnum, numname):
        try:
            num = int(num)
            if num < minnum or num > maxnum:
                raise ValueError
        except ValueError:
            raise argparse.ArgumentTypeError("Invalid %s number (must be %d-%d)." % (numname, minnum, maxnum))
        return num


    # Parse commandline arguments
    description="TP-Link Wi-Fi Smart Plug Client v%s" % (VERSION,)
    parser = argparse.ArgumentParser(description=description)

    group = parser.add_argument_group(title="Output format")
    group.add_argument("-n", "--naked-json", action='store_true',
        help="Output only the JSON result")
    group.add_argument("-s", "--silent", action='store_true',
        help="No output")

    group = parser.add_argument_group(title="Communication")
    group.add_argument("-u", "--udp", action='store_true',
        help="Use UDP instead of TCP")
    group.add_argument("-d", "--discover", action='store_true',
        help="Perform network discovery for device target(s)")
    group.add_argument("-t", "--target", metavar="<hostname>", type=validHostname,
        help="Target hostname or IP address (or broadcast address for discovery)")
    group.add_argument("-p", "--port", metavar="<port>", default=9999, type=lambda x: validNum(x, 1, 65535, 'port'),
        help="Target port")
    group.add_argument("-k", "--kindes", "--child", metavar="<child>", dest='child',
        help="Specify for multi-unit devices the number or ID of the child to control, defined: " +
        ", ".join(ChildMap.keys()))
    group.add_argument("--timeout", default=argparse.SUPPRESS, type=lambda x: validNum(x, 0, 65535, 'timeout'),
        help="Timeout to establish connection, 0 for infinite")

    parser.add_argument("--version", action="version", version=description)

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-c", "--command", metavar="<command>", choices=COMMANDS.keys(),
        help="Preset command to send. Choices are: "+", ".join(COMMANDS.keys()))
    group.add_argument("-j", "--json", metavar="<JSON string>",
        help="Full JSON string of command to send")

    parser.add_argument("--username",
        help="Required username for bind")
    parser.add_argument("--password",
        help="Required password for bind")
    parser.add_argument("-a", "--argument", metavar="<value>",
        help="Some commands (bright) require an argument, others (settime) accept an optional arg")
    parser.add_argument('more', nargs=argparse.REMAINDER,
        help="targets or commands - whichever is not specified by option")

    args = parser.parse_args()


    try:

        if not args.more:
            if not args.target and not args.discover:
                print("Target is required")
                sys.exit(1)

            sys.exit(do_discover(args) if args.discover else do_command(args))


        multitarget = not args.target

        if multitarget:
            if args.json:
                print("more args cannot combine with json command option")
                sys.exit(1)

        elif args.json or args.command:
            print("more args cannot combine with both target and any command option")
            sys.exit(1)

        sys.exit(do_more(multitarget, args))

    except MissingArg as e:
        print(e)
        sys.exit(1)

# vim: sts=4 sw=4 ts=4 et ai si
