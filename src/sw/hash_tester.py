#!/usr/bin/env python
# -*- coding: utf-8 -*-
#=======================================================================
#
# hash_tester.py
# --------------
# This program sends several commands to the coretest_hashed subsystem
# in order to verify the SHA-1 and SHA-256 hash function cores.
# The program uses the built in hash implementations in Python
# to do functional comparison and validation.
#
# Note: This program requires the PySerial module.
# http://pyserial.sourceforge.net/
#
# 
# Author: Joachim Strömbergson
# Copyright (c) 2014  Secworks Sweden AB
# 
# Redistribution and use in source and binary forms, with or 
# without modification, are permitted provided that the following 
# conditions are met: 
# 
# 1. Redistributions of source code must retain the above copyright 
#    notice, this list of conditions and the following disclaimer. 
# 
# 2. Redistributions in binary form must reproduce the above copyright 
#    notice, this list of conditions and the following disclaimer in 
#    the documentation and/or other materials provided with the 
#    distribution. 
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#=======================================================================
 
#-------------------------------------------------------------------
# Python module imports.
#-------------------------------------------------------------------
import sys
import serial
import os
import time
import threading

 
#-------------------------------------------------------------------
# Defines.
#-------------------------------------------------------------------
VERBOSE = False

# Memory map.
SOC                 = '\x55'
EOC                 = '\xaa'
READ_CMD            = '\x10'
WRITE_CMD           = '\x11'

UART_ADDR_PREFIX    = '\x00'
SHA1_ADDR_PREFIX    = '\x10'
SHA256_ADDR_PREFIX  = '\x20'

NAME0_ADDR          = '\x00'
NAME1_ADDR          = '\x01'
VERSION_ADDR        = '\x02'
TEST_CORE_RW_REG    = '\x10'
TEST_CORE_DEBUG_REG = '\x20'


#-------------------------------------------------------------------
# print_response()
#
# Parses a received buffer and prints the response.
#-------------------------------------------------------------------
def print_response(buffer):
    if VERBOSE:
        print "Length of response: %d" % len(buffer)
        if buffer[0] == '\xaa':
            print "Response contains correct Start of Response (SOR)"
        if buffer[-1] == '\x55':
            print "Response contains correct End of Response (EOR)"

    response_code = ord(buffer[1])

    if response_code == 0xfe:
        print "UNKNOWN response code received."

    elif response_code == 0xfd:
        print "ERROR response code received."

    elif response_code == 0x7f:
        read_addr = ord(buffer[2]) * 256 + ord(buffer[3])
        read_data = (ord(buffer[4]) * 16777216) + (ord(buffer[5]) * 65536) +\
                    (ord(buffer[6]) * 256) + ord(buffer[7])
        print "READ_OK. address 0x%02x = 0x%04x." % (read_addr, read_data)

    elif response_code == 0x7e:
        read_addr = ord(buffer[2]) * 256 + ord(buffer[3])
        print "WRITE_OK. address 0x%02x." % (read_addr)

    elif response_code == 0x7d:
        print "RESET_OK."

    else:
        print "Response 0x%02x is unknown." % response_code
        print buffer
        

#-------------------------------------------------------------------
# read_serial_thread()
#
# Function used in a thread to read from the serial port and
# collect response from coretest.
#-------------------------------------------------------------------
def read_serial_thread(serialport):
    if VERBOSE:
        print "Serial port response thread started. Waiting for response..."
        
    buffer = []
    while True:
        response = serialport.read()
        buffer.append(response)
        if response == '\x55':
            print_response(buffer)
            buffer = []


#-------------------------------------------------------------------
# write_serial_bytes()
#
# Send the bytes in the buffer to coretest over the serial port.
#-------------------------------------------------------------------
def write_serial_bytes(tx_cmd, serialport):
    if VERBOSE:
        print "Command to be sent:", tx_cmd
    
    for tx_byte in tx_cmd:
        serialport.write(tx_byte)

    # Allow the device to complete the transaction.
    time.sleep(0.1)
    
    
#-------------------------------------------------------------------
# main()
#
# Parse any arguments and run the tests.
#-------------------------------------------------------------------
def main():
    # Open device
    ser = serial.Serial()
    ser.port='/dev/cu.usbserial-A801SA6T'
    ser.baudrate=9600
    ser.bytesize=8
    ser.parity='N'
    ser.stopbits=1
    ser.timeout=1
    ser.writeTimeout=0

    if VERBOSE:
        print "Setting up a serial port and starting a receive thread."

    try:
        ser.open()
    except:
        print "Error: Can't open serial device."
        sys.exit(1)

    try:
        my_thread = threading.Thread(target=read_serial_thread, args=(ser,))
    except:
        print "Error: Can't start thread."
        sys.exit()
        
    my_thread.daemon = True
    my_thread.start()

    # TC1: Read name and version from SHA-1 core.
    print "TC1: Reading name, type and version words from SHA-1 core."
    my_cmd = [SOC, READ_CMD, SHA1_ADDR_PREFIX, NAME0_ADDR, EOC]
    write_serial_bytes(my_cmd, ser)
    my_cmd = [SOC, READ_CMD, SHA1_ADDR_PREFIX, NAME1_ADDR, EOC]
    write_serial_bytes(my_cmd, ser)
    my_cmd = [SOC, READ_CMD, SHA1_ADDR_PREFIX, VERSION_ADDR, EOC]
    write_serial_bytes(my_cmd, ser)
    print""
    
    # TC2: Read name and version from SHA-256 core.
    print "TC1: Reading name, type and version words from SHA-256 core."
    my_cmd = [SOC, READ_CMD, SHA256_ADDR_PREFIX, NAME0_ADDR, EOC]
    write_serial_bytes(my_cmd, ser)
    my_cmd = [SOC, READ_CMD, SHA256_ADDR_PREFIX, NAME1_ADDR, EOC]
    write_serial_bytes(my_cmd, ser)
    my_cmd = [SOC, READ_CMD, SHA256_ADDR_PREFIX, VERSION_ADDR, EOC]
    write_serial_bytes(my_cmd, ser)

    
    # Exit nicely.
    if VERBOSE:
        print "Done. Closing device."
    ser.close()


#-------------------------------------------------------------------
# __name__
# Python thingy which allows the file to be run standalone as
# well as parsed from within a Python interpreter.
#-------------------------------------------------------------------
if __name__=="__main__": 
    # Run the main function.
    sys.exit(main())


#=======================================================================
# EOF hash_tester.py
#=======================================================================
