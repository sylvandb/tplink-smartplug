#!/usr/bin/env python
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
import socket
from struct import pack, unpack

VERSION = 0.9


# Predefined Smart Plug Commands
# For a full list of commands, consult tplink_commands.txt
COMMANDS = {
	'info'	   : '{"system":{"get_sysinfo":{}}}',
	'on'	   : '{"system":{"set_relay_state":{"state":1}}}',
	'off'	   : '{"system":{"set_relay_state":{"state":0}}}',
	'ledoff'   : '{"system":{"set_led_off":{"off":1}}}',
	'ledon'    : '{"system":{"set_led_off":{"off":0}}}',
	'cloudinfo': '{"cnCloud":{"get_info":{}}}',
	'wlanscan' : '{"netif":{"get_scaninfo":{"refresh":0}}}',
	'time'	   : '{"time":{"get_time":{}}}',
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
# XOR Autokey Cipher with starting key = 171
def encrypt(string):
	key = 171
	result = []
	chars = isinstance(string[0], str)
	if chars:
		string = map(ord, string)
	for plain in string:
		key ^= plain
		result.append(key)
	return b''.join(map(chr, result)) if chars else bytes(result)

def decrypt(string):
	key = 171
	result = []
	chars = isinstance(string[0], str)
	if chars:
		string = map(ord, string)
	for cipher in string:
		result.append(key ^ cipher)
		key = cipher
	return b''.join(map(chr, result)) if chars else bytes(result)



class CommFailure(Exception):
	pass

# Send command and receive reply
def comm(ip, cmd, port=9999, to=None):
	dec = isinstance(cmd, str)
	if dec:
		cmd = cmd.encode()
	try:
		sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		if to:
			sock_tcp.settimeout(to)
		sock_tcp.connect((ip, port))
		sock_tcp.settimeout(None)
		sock_tcp.send(pack('>I', len(cmd)) + encrypt(cmd))
		data = sock_tcp.recv(2048)
		dlen = 4 + unpack('>I', data[:4])[0]
		while len(data) < dlen:
			data += sock_tcp.recv(2048)
		sock_tcp.close()
	except socket.error:
		raise CommFailure("Could not connect to host %s:%d" % (ip, port))
	finally:
		sock_tcp.close()
	res = decrypt(data[4:])
	return res.decode() if dec else res




if __name__ == '__main__':
	import argparse
	import sys

	# Check if hostname is valid
	def validHostname(hostname):
		try:
			socket.gethostbyname(hostname)
		except socket.error:
			parser.error("Invalid hostname.")
		return hostname

	def validNum(num, minnum, maxnum, numname):
		try:
			num = int(num)
			if num < minnum or num > maxnum:
				raise ValueError
		except ValueError:
			parser.error("Invalid %s number." % (numname,))
		return num


	# Parse commandline arguments
	description="TP-Link Wi-Fi Smart Plug Client v%s" % (VERSION,)
	parser = argparse.ArgumentParser(description=description)
	parser.add_argument("--version", action="version", version=description)
	parser.add_argument("-n", "--naked-json", action='store_true',
		help="Output only the JSON result")
	parser.add_argument("-s", "--silent", action='store_true',
		help="No output")

	parser.add_argument("-t", "--target", metavar="<hostname>", required=True, type=validHostname,
		help="Target hostname or IP address")
	parser.add_argument("-p", "--port", metavar="<port>", default=9999, type=lambda x: validNum(x, 1, 65535, 'port'),
		help="Target port")
	parser.add_argument("--timeout", default=10, type=lambda x: validNum(x, 0, 65535, 'timeout'),
		help="Timeout to establish connection, 0 for infinite")
	parser.add_argument("-a", "--argument", metavar="<value>",
		help="Some commands (bright) require an argument")

	group = parser.add_mutually_exclusive_group()
	group.add_argument("-c", "--command", metavar="<command>", choices=COMMANDS,
		help="Preset command to send. Choices are: "+", ".join(COMMANDS))
	group.add_argument("-j", "--json", metavar="<JSON string>",
		help="Full JSON string of command to send")

	args = parser.parse_args()


	# command to send
	cmd = args.json if args.json else COMMANDS[args.command or 'info']
	if not args.argument is None:
		try:
			cmd = cmd % (args.argument,)
		except TypeError:
			cmd = cmd % (int(args.argument),)
	reply = ''

	try:
		reply = comm(args.target, cmd, port=args.port, to=args.timeout)
		ec = len(reply) <= 0
	except CommFailure as e:
		print("<<%s>>" % (str(e),), file=stderr)
		ec = 2
	finally:
		if args.naked_json:
			print(reply)
		elif not args.silent:
			print("%-16s %s" % ("Sent(%d):" % (len(cmd),), cmd))
			print("%-16s %s" % ("Received(%d):" % (len(reply),), reply))
	sys.exit(ec)
