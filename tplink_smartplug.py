#!/usr/bin/env python3
#
# TP-Link Wi-Fi Smart Plug Protocol Client
# For use with TP-Link HS-100 or HS-110
#
# by Lubomir Stroetmann
# Copyright 2016 softScheck GmbH
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
#

from __future__ import print_function
import ipaddress
import socket
from struct import pack, unpack

VERSION = 0.12


# Predefined Smart Plug Commands
# For a full list of commands, consult tplink_commands.txt
COMMANDS = {
    'info'     : '{"system":{"get_sysinfo":{}}}',
    'on'       : '{"system":{"set_relay_state":{"state":1}}}',
    'off'      : '{"system":{"set_relay_state":{"state":0}}}',
    'ledoff'   : '{"system":{"set_led_off":{"off":1}}}',
    'ledon'    : '{"system":{"set_led_off":{"off":0}}}',
    'cloudinfo': '{"cnCloud":{"get_info":{}}}',
    'wlanscan' : '{"netif":{"get_scaninfo":{"refresh":0}}}',
    'time'     : '{"time":{"get_time":{}}}',
    'schedule' : '{"schedule":{"get_rules":{}}}',
    'countdown': '{"count_down":{"get_rules":{}}}',
    'antitheft': '{"anti_theft":{"get_rules":{}}}',
    'reboot'   : '{"system":{"reboot":{"delay":1}}}',
    'reset'    : '{"system":{"reset":{"delay":1}}}',
    'energy'   : '{"emeter":{"get_realtime":{}}}',
# HS220
    'bright'   : '{"smartlife.iot.dimmer": {"set_brightness": {"brightness": %d}}}'
}


# Encryption and Decryption of TP-Link Smart Home Protocol
# XOR Autokey Cipher with starting key
_STARTING_KEY = 171

def encrypt(string):
    chars = isinstance(string[0], str)
    if chars:
        string = map(ord, string)
    key = _STARTING_KEY
    result = []
    for plain in string:
        key ^= plain
        result.append(key)
    return b''.join(map(chr, result)) if chars else bytes(result)

def decrypt(string):
    chars = isinstance(string[0], str)
    if chars:
        string = map(ord, string)
    key = _STARTING_KEY
    result = []
    for cipher in string:
        result.append(key ^ cipher)
        key = cipher
    return b''.join(map(chr, result)) if chars else bytes(result)



class CommFailure(Exception):
    pass


# Send command and receive reply
def communicate(cmd, udp=False, **kwargs):
    if isinstance(cmd, str):
        cmd = encrypt(cmd.encode())
        def reverse(d):
            return decrypt(d).decode()
    else:
        cmd = encrypt(cmd)
        def reverse(d):
            return decrypt(d)
    res = _communicate_udp(cmd, **kwargs) if udp else _communicate_tcp(cmd, **kwargs)
    if udp and kwargs.get('broadcast'):
        res = {k: reverse(v) for k, v in res.items()}
    else:
        res = reverse(res)
    return res


def _communicate_tcp(cmd, ip, port=9999, timeout=None):
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


def _communicate_udp(cmd, ip, port=9999, timeout=None, broadcast=False):
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


def discover_udp(cmd, tries=3, **kwargs):
    """
        Used to discover available devices on the local network
        Sends cmd to target:port as UDP
        Waits timeout for responses
        ip is expected to be a broadcast address or network cidr
        (an ip address or network address or 255.255.255.255)
        return: dict keyed with ipaddress(es): {ipaddress: reply, ...}
    """
    found = {}
    for i in range(tries):
        found.update(communicate(cmd, udp=True, broadcast=True, **kwargs))
    return found




if __name__ == '__main__':
    import argparse
    import json
    import sys


    # command to send
    def cmd_lookup(args):
        cmd = args.json if args.json else COMMANDS[args.command or 'info']
        if not args.argument is None:
            try:
                cmd = cmd % (args.argument,)
            except TypeError:
                cmd = cmd % (int(args.argument),)
        return cmd


    def do_command(args):
        cmd = cmd_lookup(args)
        try:
            reply = communicate(cmd, ip=args.target, port=args.port, timeout=args.timeout, udp=args.udp)
        except CommFailure as e:
            print("<<%s>>" % (str(e),), file=sys.stderr)
            reply = None
            ec = 2
        else:
            ec = len(reply) <= 0
        if not ec:
            if args.naked_json:
                print(reply)
            elif not args.silent:
                print("%-16s %s" % ("Sent(%d):" % (len(cmd),), cmd))
                print("%-16s %s" % ("Received(%d):" % (len(reply),), reply))
        return ec


    def do_discover(args):
        cmd = cmd_lookup(args)
        found = discover_udp(cmd, ip=args.target or '255.255.255.255', port=args.port, timeout=args.timeout)
        if args.naked_json and found:
            print("{")
            comma = False
            for ip, reply in found.items():
                print('  %s"%s": %s' % (", " if comma else '', ip, reply))
                comma = True
            print("}")
        elif not args.silent and found:
            print("Found: %d" % (len(found),))
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


    # Check if hostname is a valid ip address or network address or hostname
    def validHostname(hostname):
        try:
            hostname = str(ipaddress.ip_network(hostname, strict=False).broadcast_address)
        except ValueError:
            hostname = socket.gethostbyname(hostname)
        return hostname

    def validNum(num, minnum, maxnum, numname):
        try:
            num = int(num)
            if num < minnum or num > maxnum:
                raise ValueError
        except ValueError:
            parser.error("Invalid %s number (must be %d-%d)." % (numname, minnum, maxnum))
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
    group.add_argument("--timeout", default=10, type=lambda x: validNum(x, 0, 65535, 'timeout'),
        help="Timeout to establish connection, 0 for infinite")

    parser.add_argument("--version", action="version", version=description)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-c", "--command", metavar="<command>", choices=COMMANDS,
        help="Preset command to send. Choices are: "+", ".join(COMMANDS))
    group.add_argument("-j", "--json", metavar="<JSON string>",
        help="Full JSON string of command to send")
    parser.add_argument("-a", "--argument", metavar="<value>",
        help="Some commands (bright) require an argument")

    args = parser.parse_args()

    if not args.target and not args.discover:
        print("Target is required")
        sys.exit(1)

    sys.exit(do_discover(args) if args.discover else do_command(args))

# vim: sts=4 sw=4 ts=4 et ai si
