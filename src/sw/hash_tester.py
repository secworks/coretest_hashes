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
import hashlib

 
#-------------------------------------------------------------------
# Defines.
#-------------------------------------------------------------------
# Serial port defines.
# CONFIGURE YOUR DEVICE HERE!
SERIAL_DEVICE = '/dev/cu.usbserial-A801SA6T'
BAUD_RATE = 9600
DATA_BITS = 8
STOP_BITS = 1


# Verbose operation on/off
VERBOSE = False


# Memory map.
SOC                   = '\x55'
EOC                   = '\xaa'
READ_CMD              = '\x10'
WRITE_CMD             = '\x11'

UART_ADDR_PREFIX      = '\x00'

SHA1_ADDR_PREFIX      = '\x10'
SHA1_ADDR_NAME0       = '\x00'
SHA1_ADDR_NAME1       = '\x01'
SHA1_ADDR_VERSION     = '\x02'
SHA1_ADDR_CTRL        = '\x08'
SHA1_CTRL_INIT_BIT    = 0
SHA1_CTRL_NEXT_BIT    = 1
SHA1_ADDR_STATUS      = '\x09'
SHA1_STATUS_READY_BIT = 0
SHA1_STATUS_VALID_BIT = 1
SHA1_ADDR_BLOCK0      = '\x10'
SHA1_ADDR_BLOCK1      = '\x11'
SHA1_ADDR_BLOCK2      = '\x12'
SHA1_ADDR_BLOCK3      = '\x13'
SHA1_ADDR_BLOCK4      = '\x14'
SHA1_ADDR_BLOCK5      = '\x15'
SHA1_ADDR_BLOCK6      = '\x16'
SHA1_ADDR_BLOCK7      = '\x17'
SHA1_ADDR_BLOCK8      = '\x18'
SHA1_ADDR_BLOCK9      = '\x19'
SHA1_ADDR_BLOCK10     = '\x1a'
SHA1_ADDR_BLOCK11     = '\x1b'
SHA1_ADDR_BLOCK12     = '\x1c'
SHA1_ADDR_BLOCK13     = '\x1d'
SHA1_ADDR_BLOCK14     = '\x1e'
SHA1_ADDR_BLOCK15     = '\x1f'
SHA1_ADDR_DIGEST0     = '\x20'
SHA1_ADDR_DIGEST1     = '\x21'
SHA1_ADDR_DIGEST2     = '\x22'
SHA1_ADDR_DIGEST3     = '\x23'
SHA1_ADDR_DIGEST4     = '\x24'

SHA256_ADDR_PREFIX      = '\x20'
SHA256_ADDR_NAME0       = '\x00'
SHA256_ADDR_NAME1       = '\x01'
SHA256_ADDR_VERSION     = '\x02'
SHA256_ADDR_CTRL        = '\x08'
SHA256_CTRL_INIT_BIT    = 0
SHA256_CTRL_NEXT_BIT    = 1
SHA256_ADDR_STATUS      = '\x09'
SHA256_STATUS_READY_BIT = 0
SHA256_STATUS_VALID_BIT = 1
SHA256_ADDR_BLOCK0      = '\x10'
SHA256_ADDR_BLOCK1      = '\x11'
SHA256_ADDR_BLOCK2      = '\x12'
SHA256_ADDR_BLOCK3      = '\x13'
SHA256_ADDR_BLOCK4      = '\x14'
SHA256_ADDR_BLOCK5      = '\x15'
SHA256_ADDR_BLOCK6      = '\x16'
SHA256_ADDR_BLOCK7      = '\x17'
SHA256_ADDR_BLOCK8      = '\x18'
SHA256_ADDR_BLOCK9      = '\x19'
SHA256_ADDR_BLOCK10     = '\x1a'
SHA256_ADDR_BLOCK11     = '\x1b'
SHA256_ADDR_BLOCK12     = '\x1c'
SHA256_ADDR_BLOCK13     = '\x1d'
SHA256_ADDR_BLOCK14     = '\x1e'
SHA256_ADDR_BLOCK15     = '\x1f'
SHA256_ADDR_DIGEST0     = '\x20'
SHA256_ADDR_DIGEST1     = '\x21'
SHA256_ADDR_DIGEST2     = '\x22'
SHA256_ADDR_DIGEST3     = '\x23'
SHA256_ADDR_DIGEST4     = '\x24'
SHA256_ADDR_DIGEST5     = '\x25'
SHA256_ADDR_DIGEST6     = '\x26'
SHA256_ADDR_DIGEST7     = '\x27'

NAME0_ADDR            = '\x00'
NAME1_ADDR            = '\x01'
VERSION_ADDR          = '\x02'


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
        print "READ_OK. address 0x%02x = 0x%08x." % (read_addr, read_data)

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
        if serialport.isOpen():
            response = serialport.read()
            buffer.append(response)
            if response == '\x55':
                print_response(buffer)
                buffer = []
        else:
            print "No open device yet."
            time.sleep(0.1)
            

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
# single_block_test_sha256()
#
# Write a given block to SHA-256 and perform single block
# processing.
#-------------------------------------------------------------------
def single_block_test_sha256(block, ser):
    sha256_block_addr = [SHA256_ADDR_BLOCK0,  SHA256_ADDR_BLOCK1,
                         SHA256_ADDR_BLOCK2,  SHA256_ADDR_BLOCK3,
                         SHA256_ADDR_BLOCK4,  SHA256_ADDR_BLOCK5,
                         SHA256_ADDR_BLOCK6,  SHA256_ADDR_BLOCK7,
                         SHA256_ADDR_BLOCK8,  SHA256_ADDR_BLOCK9,
                         SHA256_ADDR_BLOCK10, SHA256_ADDR_BLOCK11,
                         SHA256_ADDR_BLOCK12, SHA256_ADDR_BLOCK13,
                         SHA256_ADDR_BLOCK14, SHA256_ADDR_BLOCK15]

    sha256_digest_addr = [SHA256_ADDR_DIGEST0,  SHA256_ADDR_DIGEST1,
                          SHA256_ADDR_DIGEST2,  SHA256_ADDR_DIGEST3,
                          SHA256_ADDR_DIGEST4,  SHA256_ADDR_DIGEST5,
                          SHA256_ADDR_DIGEST6,  SHA256_ADDR_DIGEST7]

    # Write block to SHA-1.
    for i in range(len(block) / 4):
        message = [SOC, WRITE_CMD, SHA1_ADDR_PREFIX,] + [sha256_block_addr[i]] +\
                  block[(i * 4) : ((i * 4 ) + 4)] + [EOC]
        write_serial_bytes(message, ser)

    # Start hashing, wait and check status.
    write_serial_bytes([SOC, WRITE_CMD, SHA1_ADDR_PREFIX, SHA1_ADDR_CTRL, '\x00', '\x00', '\x00', '\x01', EOC], ser)
    time.sleep(0.1)
    write_serial_bytes([SOC, READ_CMD, SHA256_ADDR_PREFIX, SHA256_ADDR_STATUS, EOC], ser)

    # Extract contents of the digest registers.
    for i in range(8):
        message = [SOC, READ_CMD, SHA256_ADDR_PREFIX] + [sha256_digest_addr[i]] + [EOC]
        write_serial_bytes(message, ser)
    print""


#-------------------------------------------------------------------
#-------------------------------------------------------------------
def double_block_test_sha256(block1, block2, ser):
    pass


#-------------------------------------------------------------------
# single_block_test_sha1()
#
# Write a given block to SHA-1 and perform single block
# processing.
#-------------------------------------------------------------------
def single_block_test_sha1(block, ser):
    sha1_block_addr = [SHA1_ADDR_BLOCK0,  SHA1_ADDR_BLOCK1,  SHA1_ADDR_BLOCK2,  SHA1_ADDR_BLOCK3,
                       SHA1_ADDR_BLOCK4,  SHA1_ADDR_BLOCK5,  SHA1_ADDR_BLOCK6,  SHA1_ADDR_BLOCK7,
                       SHA1_ADDR_BLOCK8,  SHA1_ADDR_BLOCK9,  SHA1_ADDR_BLOCK10, SHA1_ADDR_BLOCK11,
                       SHA1_ADDR_BLOCK12, SHA1_ADDR_BLOCK13, SHA1_ADDR_BLOCK14, SHA1_ADDR_BLOCK15]

    sha1_digest_addr = [SHA1_ADDR_DIGEST0, SHA1_ADDR_DIGEST1, SHA1_ADDR_DIGEST2,
                        SHA1_ADDR_DIGEST3, SHA1_ADDR_DIGEST4]

    # Write block to SHA-1.
    for i in range(len(block) / 4):
        message = [SOC, WRITE_CMD, SHA1_ADDR_PREFIX,] + [sha1_block_addr[i]] +\
                  block[(i * 4) : ((i * 4 ) + 4)] + [EOC]
        write_serial_bytes(message, ser)

    # Start hashing, wait and check status.
    write_serial_bytes([SOC, WRITE_CMD, SHA1_ADDR_PREFIX, SHA1_ADDR_CTRL, '\x00', '\x00', '\x00', '\x01', EOC], ser)
    time.sleep(0.1)
    write_serial_bytes([SOC, READ_CMD, SHA1_ADDR_PREFIX, SHA1_ADDR_STATUS,   EOC], ser)

    # Extract the digest.
    for i in range(5):
        message = [SOC, READ_CMD, SHA1_ADDR_PREFIX] + [sha1_digest_addr[i]] + [EOC]
        write_serial_bytes(message, ser)
    print""
    

#-------------------------------------------------------------------
#-------------------------------------------------------------------
def double_block_test_sha256(block1, block2, ser):
    pass


#-------------------------------------------------------------------
# main()
#
# Parse any arguments and run the tests.
#-------------------------------------------------------------------
def main():
    # Open device
    ser = serial.Serial()
    ser.port=SERIAL_DEVICE
    ser.baudrate=BAUD_RATE
    ser.bytesize=DATA_BITS
    ser.parity='N'
    ser.stopbits=STOP_BITS
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
    write_serial_bytes([SOC, READ_CMD, SHA1_ADDR_PREFIX, SHA1_ADDR_NAME0, EOC], ser)
    write_serial_bytes([SOC, READ_CMD, SHA1_ADDR_PREFIX, SHA1_ADDR_NAME1, EOC], ser)
    write_serial_bytes([SOC, READ_CMD, SHA1_ADDR_PREFIX, SHA1_ADDR_VERSION, EOC], ser)
    print""


    # TC2: Single block message test as specified by NIST.
    print "TC2: Single block message test for SHA-1."
    tc2_block = ['\x61', '\x62', '\x63', '\x80', '\x00', '\x00', '\x00', '\x00',
                 '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                 '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                 '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                 '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                 '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                 '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                 '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x18']

    tc2_sha1_expected = [0xa9993e36, 0x4706816a, 0xba3e2571,
                         0x7850c26c, 0x9cd0d89d]

    print "TC2: Expected digest values as specified by NIST:"
    for i in tc2_sha1_expected:
        print("0x%08x " % i)
    print("")
    single_block_test_sha1(tc2_block, ser)


    # TC3: Double block message test as specified by NIST.
    print "TC3: Double block message test for SHA-1."
    tc3_1_block = ['\x61', '\x62', '\x63', '\x64', '\x62', '\x63', '\x64', '\x65',
                   '\x63', '\x64', '\x65', '\x66', '\x64', '\x65', '\x66', '\x67',
                   '\x65', '\x66', '\x67', '\x68', '\x66', '\x67', '\x68', '\x69',
                   '\x67', '\x68', '\x69', '\x6A', '\x68', '\x69', '\x6A', '\x6B',
                   '\x69', '\x6A', '\x6B', '\x6C', '\x6A', '\x6B', '\x6C', '\x6D',
                   '\x6B', '\x6C', '\x6D', '\x6E', '\x6C', '\x6D', '\x6E', '\x6F',
                   '\x6D', '\x6E', '\x6F', '\x70', '\x6E', '\x6F', '\x70', '\x71',
                   '\x80', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00']

    tc3_1_block = ['\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                   '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                   '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                   '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                   '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                   '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                   '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                   '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x01', '\xC0'

    tc3_1_sha1_expected = [0xF4286818, 0xC37B27AE, 0x0408F581,
                           0x84677148, 0x4A566572]

    tc3_2_sha1_expected = [0x84983E44, 0x1C3BD26E, 0xBAAE4AA1,
                           0xF95129E5, 0xE54670F1]

    print "TC3: Expected digest values for first block as specified by NIST:"
    for i in tc3_1_sha1_expected:
        print("0x%08x " % i)
    print("")
    print "TC3: Expected digest values for second block as specified by NIST:"
    for i in tc3_2_sha1_expected:
        print("0x%08x " % i)
    print("")
    double_block_test_sha1(tc3_1_block, tc3_2_block, ser)


    # TC4: Read name and version from SHA-256 core.
    print "TC4: Reading name, type and version words from SHA-256 core."
    my_cmd = [SOC, READ_CMD, SHA256_ADDR_PREFIX, NAME0_ADDR, EOC]
    write_serial_bytes(my_cmd, ser)
    my_cmd = [SOC, READ_CMD, SHA256_ADDR_PREFIX, NAME1_ADDR, EOC]
    write_serial_bytes(my_cmd, ser)
    my_cmd = [SOC, READ_CMD, SHA256_ADDR_PREFIX, VERSION_ADDR, EOC]
    write_serial_bytes(my_cmd, ser)
    print""


    # TC5: Single block message test as specified by NIST.
    print "TC5: Single block message test for SHA-256."

    tc5_sha256_expected = [0xBA7816BF, 0x8F01CFEA, 0x414140DE, 0x5DAE2223,
                           0xB00361A3, 0x96177A9C, 0xB410FF61, 0xF20015AD]

    print "TC5: Expected digest values as specified by NIST:"
    for i in tc5_sha256_expected:
        print("0x%08x " % i)
    print("")
    single_block_test_sha256(tc2_block, ser)


    # TC6: Double block message test as specified by NIST.
    print "TC6: Double block message test for SHA-256."


    tc6_1_sha256_expected = [0x85E655D6, 0x417A1795, 0x3363376A, 0x624CDE5C,
                             0x76E09589, 0xCAC5F811, 0xCC4B32C1, 0xF20E533A]

    tc6_2_sha256_expected = [0x248D6A61, 0xD20638B8, 0xE5C02693, 0x0C3E6039,
                             0xA33CE459, 0x64FF2167, 0xF6ECEDD4, 0x19DB06C1]

    print "TC6: Expected digest values for first block as specified by NIST:"
    for i in tc6_1_sha256_expected:
        print("0x%08x " % i)
    print("")
    print "TC6: Expected digest values for second block as specified by NIST:"
    for i in tc6_2_sha256_expected:
        print("0x%08x " % i)
    print("")
    double_block_test_sha256(tc3_1_block, tc3_2_block, ser)

    
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
