##
## This file is part of the sigrok project.
##
## Copyright (C) 2012 Uwe Hermann <uwe@hermann-uwe.de>
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
##

'''
USB (low-speed and full-speed) protocol decoder.

Electrical/signalling layer (USB spec, chapter 7):

USB signalling consists of two signal lines, both driven at 3.3V
logic levels. The signals are DP (D+) and DM (D-), and normally operate in
differential mode.

Low-speed: The state where DP=1,DM=0 is K, the state DP=0,DM=1 is J.
Full-speed: The state where DP=1,DM=0 is J, the state DP=0,DM=1 is K.

A state SE0 is defined where DP=DM=0. This common mode signal is used to
signal a reset or end of packet. A state SE1 is defined where DP=DM=1.

Data transmitted on the USB is encoded with NRZI. A transition from J to K
or vice-versa indicates a logic 0, while no transition indicates a logic 1.
If 6 ones are transmitted consecutively, a zero is inserted to force a
transition. This is known as bit stuffing.

Data is transferred at a rate of 1.5Mbit/s (low-speed) / 12Mbit/s (full-speed).

The SE0 transmitted to signal an end-of-packet is two bit intervals long
(low-speed: 1.25uS - 1.50uS, full-speed: 160ns - 175ns).

Protocol layer (USB spec, chapter 8):

Bit/byte ordering: Bits are sent onto the bus LSB-first. Multibyte fields
are transmitted in little-endian order (i.e., LSB to MSB).

SYNC field: All packets begin with a SYNC field (8 bits).

Packet field format: Packets start with an SOP (Start Of Packet) delimiter
that is part of the SYNC field, and end with an EOP (End Of Packet).

PID: A PID (packet identifier) follows the SYNC field of every packet. A PID
consists of a 4-bit packet type field, and a 4 bit check field.
The check field is the one's complement of the packet type field.

Protocol output format:
TODO

Details:
https://en.wikipedia.org/wiki/USB
http://www.usb.org/developers/docs/
'''

from .usb import *

