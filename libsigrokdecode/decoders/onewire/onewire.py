##
## This file is part of the sigrok project.
##
## Copyright (C) 2011-2012 Uwe Hermann <uwe@hermann-uwe.de>
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

# 1-Wire protocol decoder

import sigrokdecode as srd

# Annotation feed formats
ANN_ASCII = 0
ANN_DEC = 1
ANN_HEX = 2
ANN_OCT = 3
ANN_BITS = 4

class Decoder(srd.Decoder):
    api_version = 1
    id = 'onewire'
    name = '1-Wire'
    longname = ''
    desc = '1-Wire bus and MicroLan'
    license = 'gplv2+'
    inputs = ['logic']
    outputs = ['onewire']
    probes = [
        {'id': 'owr', 'name': 'OWR', 'desc': '1-Wire bus'},
    ]
    optional_probes = [
        {'id': 'pwr', 'name': 'PWR', 'desc': '1-Wire power'},
    ]
    options = {
        'overdrive': ['Overdrive', 0],
    }
    annotations = [
        ['ASCII', 'Data bytes as ASCII characters'],
        ['Decimal', 'Databytes as decimal, integer values'],
        ['Hex', 'Data bytes in hex format'],
        ['Octal', 'Data bytes as octal numbers'],
        ['Bits', 'Data bytes in bit notation (sequence of 0/1 digits)'],
    ]

    def putx(self, data):
        self.put(self.startsample, self.samplenum - 1, self.out_ann, data)

    def __init__(self, **kwargs):
        # Common variables
        self.samplenum = 0
        # Link layer variables
        self.lnk_state = 'WAIT FOR NEGEDGE'
        self.lnk_event = 'NONE'
        self.lnk_start = -1
        self.lnk_bit   = -1
        self.lnk_cnt   = 0
        self.lnk_byte  = -1
        # Network layer variables
        self.net_state = 'WAIT FOR EVENT'
        self.net_event = 'NONE'
        self.net_command = -1
        # Transport layer variables
        self.trn_state = 'WAIT FOR EVENT'
        self.trn_event = 'NONE'

        self.data_sample = -1
        self.cur_data_bit = 0
        self.databyte = 0
        self.startsample = -1

    def start(self, metadata):
        self.samplerate = metadata['samplerate']
        self.out_proto = self.add(srd.OUTPUT_PROTO, 'onewire')
        self.out_ann   = self.add(srd.OUTPUT_ANN  , 'onewire')

        # The width of the 1-Wire time base (30us) in number of samples.
        # TODO: optimize this value
        self.time_base = float(self.samplerate) / float(0.000030)

    def report(self):
        pass

    def decode(self, ss, es, data):
        for (self.samplenum, (owr, pwr)) in data:

            # Data link layer

            # Clear events.
            self.lnk_event = "RESET"
            # State machine.
            if self.lnk_state == 'WAIT FOR FALLING EDGE':
                # The start of a cycle is a falling edge.
                if (owr == 0):
                    # Save the sample number for the falling edge.
                    self.lnk_fall = self.samplenum
                    # Go to waiting for sample time
                    self.lnk_state = 'WAIT FOR DATA SAMPLE'
            elif self.lnk_state == 'WAIT FOR DATA SAMPLE':
                # Data should be sample one 'time unit' after a falling edge
                if (self.samplenum - self.lnk_fall == 1*self.time_base):
                    self.lnk_bit  = owr & 0x1
                    self.lnk_event = "DATA BIT"
                    if (self.lnk_bit) :  self.lnk_state = 'WAIT FOR FALLING EDGE'
                    else              :  self.lnk_state = 'WAIT FOR RISING EDGE'
            elif self.lnk_state == 'WAIT FOR RISING EDGE':
                # The end of a cycle is a rising edge.
                if (owr == 1):
                    # A reset cycle is longer than 8T
                    if (self.samplenum - self.lnk_fall > 8*self.time_base):
                        # Save the sample number for the falling edge.
                        self.lnk_rise = self.samplenum
                        # Send a reset event to the next protocol layer
                        self.lnk_event = "RESET"
                        self.lnk_state = "WAIT FOR PRESENCE DETECT"
            elif self.lnk_state == 'WAIT FOR PRESENCE DETECT':
                # Data should be sample one 'time unit' after a falling edge
                if (self.samplenum - self.lnk_rise == 2.5*self.time_base):
                    self.lnk_bit  = owr & 0x1
                    self.lnk_event = "PRESENCE DETECT"
                    if (self.lnk_bit) :  self.lnk_state = 'WAIT FOR FALLING EDGE'
                    else              :  self.lnk_state = 'WAIT FOR RISING EDGE'
            else:
                raise Exception('Invalid lnk_state: %s' % self.lnk_state)

            # Network layer
            
            # Clear events.
            self.net_event = "RESET"
            # State machine.
            if (self.lnk_event == "RESET"):
                self.net_state = "WAIT FOR COMMAND"
                self.net_cnt = 0
                self.net_cmd = 0
            elif (self.lnk_event == "DATA BIT"):
                if (self.net_state == "WAIT FOR COMMAND"):
                    self.net_cnt = self.net_cnt + 1
                    self.net_cmd = (self.net_cmd << 1) & self.lnk_bit
                    if (self.lnk_cnt == 8):
                        self.put(self.startsample, self.samplenum,
                                 self.out_proto, ['LNK: BYTE', self.lnk_byte])
                        self.put(self.startsample, self.samplenum, self.out_ann,
                                 [ANN_DEC, ['LNK: BYTE: ' + self.lnk_byte]])
                        if   (self.net_cmd == 0x33):
                            # READ ROM
                            break
                        elif (self.net_cmd == 0x0f):
                            # READ ROM
                            break
                        elif (self.net_cmd == 0xcc):
                            # SKIP ROM
                            break
                        elif (self.net_cmd == 0x55):
                            # MATCH ROM
                            break
                        elif (self.net_cmd == 0xf0):
                            # SEARCH ROM
                            break
                        elif (self.net_cmd == 0x3c):
                            # OVERDRIVE SKIP ROM
                            break
                        elif (self.net_cmd == 0x69):
                            # OVERDRIVE MATCH ROM
                            break
                        self.lnk_cnt = 0
                if (self.net_state == "WAIT FOR ROM"):
                    #
                    break
                else:
                    raise Exception('Invalid net_state: %s' % self.net_state)
            elif not (self.lnk_event == "NONE"):
                raise Exception('Invalid net_event: %s' % self.net_event)



#                    if (self.samplenum == self.lnk_start + 8*self.time_base):
#                        self.put(self.startsample, self.samplenum - 1, self.out_proto, ['RESET'])
