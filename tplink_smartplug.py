#!/usr/bin/env python2
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

VERSION = 0.8


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
	'energy'   : '{"emeter":{"get_realtime":{}}}'
}


# Encryption and Decryption of TP-Link Smart Home Protocol
# XOR Autokey Cipher with starting key = 171
def encrypt(string):
	key = 171
	result = []
	for plain in map(ord, string):
		key ^= plain
		result.append(key)
	return b''.join(map(chr, result))

def decrypt(string):
	key = 171
	result = []
	for cipher in map(ord, string):
		result.append(key ^ cipher)
		key = cipher
	return b''.join(map(chr, result))



class CommFailure(Exception):
	pass

# Send command and receive reply
def comm(ip, cmd, port=9999):
	try:
		sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock_tcp.connect((ip, port))
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
	return decrypt(data[4:])




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


	# Parse commandline arguments
	description="TP-Link Wi-Fi Smart Plug Client v%s" % (VERSION,)
	parser = argparse.ArgumentParser(description=description)
	parser.add_argument("--version", action="version", version=description)
	parser.add_argument("-n", "--naked-json", action='store_true',
		help="Output only the JSON result")

	parser.add_argument("-t", "--target", metavar="<hostname>", required=True, type=validHostname,
		help="Target hostname or IP address")

	group = parser.add_mutually_exclusive_group()
	group.add_argument("-c", "--command", metavar="<command>", choices=COMMANDS,
		help="Preset command to send. Choices are: "+", ".join(COMMANDS))
	group.add_argument("-j", "--json", metavar="<JSON string>",
		help="Full JSON string of command to send")

	args = parser.parse_args()


	# command to send
	cmd = args.json if args.json else COMMANDS[args.command or 'info']
	reply = ''

	try:
		reply = comm(args.target, cmd)
		ec = len(reply) <= 0
	except CommFailure as e:
		print("<<%s>>" % (str(e),), file=stderr)
		ec = 2
	finally:
		if args.naked_json:
			print(reply)
		else:
			print("%-16s %s" % ("Sent(%d):" % (len(cmd),), cmd))
			print("%-16s %s" % ("Received(%d):" % (len(reply),), reply))
	sys.exit(ec)