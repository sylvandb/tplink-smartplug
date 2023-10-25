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
    # * example: {alias: (real_target, child_id), ...}
    #   - alias is specified - first of child alias/number/id or the target
    #   - real_target is the parent device hostname or ip address
    #   - child_id is the 'Id' value of the child to inspect/control
    #     which is typically the parent deviceId with a two digit suffix
    # * if child hostnames are aliased to the parent IP address then can
    #   use the child alias as the target name (no child option needed)
    # * if real_target is specified (not None) it will override any target
    #   specified while using the child alias option
    ChildMap = {
        'childalias1': ('parent_ip', 'parent_deviceId00'),
        'childalias2': ('parent_ip', 'parent_deviceId01'),
        'childalias3': ('parent_ip', 'parent_deviceId02'),
    }
    # must have a dictionary ({} for no default map)
    ChildMap = {}

VERSION = 0.22

# supported:
#  plugs:
#    HS100 HS103 HS105 HS107 HS110(em) HS300 KP303 KP115(em) EP10 EP25(em) EP40
#  switches:
#    HS200 HS210 HS220
#  outlets:
#  bulbs:
#    LB130? KL110 KL125

_STATE = ('relay_state', 'state')

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
    'setalias' : '{"system": {"set_dev_alias": {"alias": "%s"}}}',
    'alias'    : lambda **a: get_sysinfo_field('alias', **a),
    'state'    : lambda **a: get_sysinfo_field(_STATE, **a),
    'wlanscan' : '{"netif": {"get_scaninfo": {"refresh": 0}}}',
    #'wlanssid' : '{"netif":{"set_stainfo":{"ssid":"%s","password":"%s","key_type":3}}}',
    'time'     : '{"time": {"get_time": {}}}',
    'settime'  : '{"time": {"set_timezone": '
        '{"year": %(yr)d, "month": %(mo)d, "mday": %(md)d, "hour": %(hr)d, "min": %(mi)d, "sec": %(se)d, "index": 42}}}',
    'next-action'  :
        '{"schedule": {"get_next_action": {}}}',
    'schedule' : '{"schedule": {"get_rules": {}}}',
    # add-schedule
    # edit-schedule
    # delete-schedule
    'delete-all-schedule' :
        '{"schedule": {"delete_all_rules": {}}}',
    'runtime-reset':
        '{"schedule": {"erase_runtime_stat": {}}}',
    'countdown': '{"count_down": {"get_rules": {}}}',
    # add-countdown
    # edit-countdown
    # delete-countdown
    'delete-all-countdown':
        '{"count_down": {"delete_all_rules": {}}}',
    'away'     : '{"anti_theft": {"get_rules": {}}}',
    # add-away
    # edit-away
    # delete-away
    'delete-all-away':
        '{"anti_theft": {"delete_all_rules": {}}}',
    'cloudinfo': '{"cnCloud": {"get_info": {}}}',
    'bind'     : '{"cnCloud": {"bind": {"username": "%(user)s", "password": "%(pass)s"}}}',
    'unbind'   : '{"cnCloud": {"unbind": ""}}',
# ???
    'tempinfo' : '{"emeter":{"get_tempinfo": {} }}',
# HS110, KP115, EP25, maybe KP125(Matter)
    'energy'   : '{"emeter": {"get_realtime": {}}}',
    'energy-reset':
        '{"emeter": {"erase_emeter_stat": {}}}',
# HS220
    'bright'   : '{"smartlife.iot.dimmer": {"set_brightness": {"brightness": %(brt)d}}}',
# LB130 (untested), KL110
    # Hue: 0-360 (untested)
    # Saturation: 0-100 (untested)
    # Brighness: 0-100
    # Transition: ms delay (for fading)
    'bulb-hsi' : '{"smartlife.iot.smartbulb.lightingservice": {"transition_light_state": {"on_off": %(on)d,' +
        '"hue": %(hue)d, "saturation": %(sat)d, "brightness": %(brt)d, "transition_period": %(ttime)d,' +
        '"mode": "normal", "ignore_default": 1, "color_temp": 0 }}}',
    'bulbon'   : '{"smartlife.iot.smartbulb.lightingservice": {"transition_light_state": ' +
        '{"on_off": 1, "transition_period": %(ttime)d}}}',
    'bulboff'  : '{"smartlife.iot.smartbulb.lightingservice": {"transition_light_state": ' +
        '{"on_off": 0, "transition_period": %(ttime)d}}}',
    'bulbbright': '{"smartlife.iot.smartbulb.lightingservice": {"transition_light_state": ' +
        '{"brightness": %(brt)d, "transition_period": %(ttime)d}}}',
}

CMDALIASES = {
    'dim': 'bright',
}


# Encryption and Decryption of TP-Link Kasa Smart Home Protocol
# XOR Autokey Cipher with starting key
_STARTING_KEY = 171

def encrypt(bytestring):
    key = _STARTING_KEY
    return bytes(key := key ^ plain for plain in bytestring)
    #def f(plain):
    #    nonlocal key
    #    key ^= plain
    #    return key
    #return bytes(f(plain) for plain in bytestring)

def decrypt(bytestring):
    key = _STARTING_KEY
    def f(cipher):
        nonlocal key
        plain, key = key ^ cipher, cipher
        return plain
    return bytes(f(cipher) for cipher in bytestring)



class CallableCmd(Exception):
    pass

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
def cmd_lookup(*, command=None, json=None, username=None, password=None, argument=None,
               hue=None, saturation=None, brightness=None, ttime=None):
    hsi = { 'hue': hue, 'sat': saturation, 'brt': brightness, 'ttime': ttime or 0 }
    command = command or 'info'
    try:
        cmd = json if json else COMMANDS[command]
    except KeyError:
        command = CMDALIASES[command]
        cmd = COMMANDS[command]
    if callable(cmd):
        e = CallableCmd(command)
        e.cmd = cmd
        raise e
    elif command == 'bind':
        if not username or not password:
            raise MissingArg("%s requires username and password" % (command,))
        cmd = cmd % {'user': username, 'pass': password}
    elif command == 'settime':
        cmd = cmd % time_dict(when=argument)
    elif 'bright' in command:
        if hsi['brt'] is None:
            hsi['brt'] = int(argument[0])
        cmd = cmd % hsi
    elif '-hsi' in command:
        if any(hsi[k] is None for k in ('hue', 'sat', 'brt')):
            hsi['hue'] = int(argument[0])
            hsi['sat'] = int(argument[1])
            hsi['brt'] = int(argument[2])
            if len(argument) > 3:
                hsi['ttime'] = int(argument[3])
        cmd = cmd % hsi
    if 'bulb' in command and '%' in cmd:
        cmd = cmd % hsi
    elif '%d' in cmd or '%s' in cmd or '%(' in cmd:
        if not argument:
            raise MissingArg("Missing argument for '%s'" % ((json or command),))
        try:
            cmd = cmd % (argument[0],)
        except TypeError:
            cmd = cmd % (int(argument[0]),)
    return cmd


def get_sysinfo(**commargs):
    reply = communicate(cmd_lookup(command='info'), **commargs)
    return json.loads(reply).get('system', {}).get('get_sysinfo')


def get_sysinfo_field(field, child_id=None, **commargs):
    if isinstance(field, str):
        field = (field,)
    info = get_sysinfo(**commargs)
    # index into a specified child
    if child_id:
        try:
            info = [c for c in info['children'] if c['id'] == child_id][0]
        except IndexError:
            raise IndexError("No child %r with: %r" % (child_id, field,))
    # return the specified field
    for f in field:
        try:
            return info[f]
        except KeyError:
            pass
    raise KeyError("Target has no: %r" % (field,))


def get_child_id(target, childspec=None, **commargs):
    child_id = None
    if childspec is not None:
        try: # alias
            maybe_target, child_id = ChildMap[childspec]
            if maybe_target:
                target = maybe_target
        except KeyError:
            try:
                childnum = int(childspec)
            except ValueError:
                child_id = childspec
            else:
                # child 'Id' is parent 'deviceId' + 2-digit-childnum
                child_id = '%s%02x' % (get_sysinfo_field('deviceId', **commargs), childnum)
    else:
        # check the ChildMap for the target
        try:
            try:
                # typical case - a hostname was specified
                target, child_id = ChildMap[OrigTarget]
            except KeyError:
                target, child_id = ChildMap[target]
        except KeyError:
            # no ChildMap
            pass
    return target, child_id


def add_child_context(cmd, child_id=None, **kwargs):
    return '{"context": {"child_ids": ["%s"]}, %s' % (child_id, cmd[1:]) if child_id else cmd


# UNTESTED !!!
# import and call this function directly
def set_wifi_credentials(ssid, psk, key_type='3', udp=False):
    """
    :param ssid: router ssid
    :param psk: router passkey
    :param key_type: 3 is WPA2, maybe 2 is WPA and 1 maybe WEP?  0 is open?
    :return: command response
    """
    wlanssid = '{"netif":{"set_stainfo":{"ssid":"%s","password":"%s","key_type":%d}}}' % (ssid, psk, key_type)
    return communicate(wlanssid, udp=udp)




if __name__ == '__main__':
    import argparse
    import sys


    def _cmd_lookup(args):
        return \
            cmd_lookup(**_args_to_dict(args,
                'json', 'command', 'username', 'password', 'argument', 'hue', 'saturation', 'brightness', 'ttime'))

    def _args_to_dict(args, *which, xlate={}):
        d = {attr: getattr(args, attr) for attr in which}
        d.update({key: getattr(args, attr) for attr, key in xlate.items()})
        return d

    def _commargs_from_args(args):
        commargs = _args_to_dict(args, 'port', 'udp', xlate={'target': 'ip'})
        commargs['timeout'] = getattr(args, 'timeout', 5)
        commargs['ip'], commargs['child_id'] = get_child_id(args.target, args.child, **commargs)
        return commargs


    def do_command(args, nested=False):
        commargs = _commargs_from_args(args)
        try:
            cmd = _cmd_lookup(args)
        except CallableCmd as e:
            print('%r' % (e.cmd(**commargs),))
            return 0
        cmd = add_child_context(cmd, **commargs)
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


    def isonoff(args, ison=False):
        # return success(z) if state on and ison
        # return success(z) if state off and not ison
        # return fail(nz) otherwise
        #   ison t f t f
        #     on t f f t
        #        0 0 1 1
        #print(args); print()
        #reply = get_sysinfo(**_commargs_from_args(args))
        reply = get_sysinfo_field(_STATE, **_commargs_from_args(args))
        on = bool(int(reply))
        #print(on); print(reply)
        return ison ^ on


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
            if (minnum is not None and num < minnum) or (maxnum is not None and num > maxnum):
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
        help="Specify for multi-unit devices the alias, number or ID of the child to control. Aliases: " +
        (", ".join(ChildMap.keys()) or 'NONE'))
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
    parser.add_argument("-a", "--argument", metavar="<value>", action='append',
        help="Some commands (bright) require an argument, others (settime) accept an optional arg")
    parser.add_argument("--hue", metavar="0-360", type=lambda x: validNum(x, 0, 360, "hue"))
    parser.add_argument("--saturation", metavar="0-100", type=lambda x: validNum(x, 0, 100, "saturation"))
    parser.add_argument("--brightness", "--intensity", "--dim", metavar="0-100",
                        type=lambda x: validNum(x, 0, 100, "brightness/intensity"))
    parser.add_argument("--ttime", "--transition-time", metavar="ms", type=lambda x: validNum(x, 0, None, 'transition time'),
        help="Bulb commands may support a transition time in milliseconds")

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--ison', action='store_true',
        help="Test and exit success if target is on")
    group.add_argument('--isoff', action='store_true',
        help="Test and exit success if target is off")

    parser.add_argument('more', nargs=argparse.REMAINDER,
        help="targets or commands - whichever is not specified by option")
    args = parser.parse_args()
    #print(args)


    try:

        if args.ison or args.isoff:
            if not args.target:
                print("Target is required")
                sys.exit(2)
            elif args.json or args.command:
                print("Cannot combine with any command option")
                sys.exit(3)
            sys.exit(isonoff(args, ison=args.ison))

        if not args.more:
            if not args.target and not args.discover:
                print("Target is required")
                sys.exit(2)

            sys.exit(do_discover(args) if args.discover else do_command(args))


        multitarget = not args.target

        if multitarget:
            if args.json:
                print("more args cannot combine with json command option")
                sys.exit(10)

        elif args.json or args.command:
            print("more args cannot combine with both target and any command option")
            sys.exit(11)

        sys.exit(do_more(multitarget, args))

    except MissingArg as e:
        print(e)
        sys.exit(99)

# vim: sts=4 sw=4 ts=4 et ai si
