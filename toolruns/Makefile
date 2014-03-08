#===================================================================
#
# Makefile
# --------
# Makefile for building coretest_hashes simulations.
#
#
# Author: Joachim Strombergson
# Copyright (c) 2014, Secworks Sweden AB
# All rights reserved.
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
#===================================================================

CORETEST_HASHES_SRC=../src/rtl/coretest_hashes.v

CORETEST_SRC=../../coretest/src/rtl/coretest.v

UART_SRC=../../uart/src/rtl/uart.v ../../uart/src/rtl/uart_core.v

SHA1_SRC=../../sha1/src/rtl/sha1.v ../../sha1/src/rtl/sha1_core.v  ../../sha1/src/rtl/sha1_w_mem.v

SHA256_SRC=../../sha256/src/rtl/sha256.v ../../sha256/src/rtl/sha256_core.v  ../../sha256/src/rtl/sha256_w_mem.v ../../sha256/src/rtl/sha256_k_constants.v

CC=iverilog

all: coretest_hashes


coretest_hashes: $(CORETEST_HASHES_SRC) $(CORETEST_SRC) $(UART_SRC) $(SHA1_SRC) $(SHA256_SRC)
	$(CC) -o coretest_hashes.sim  $(CORETEST_HASHES_SRC) $(CORETEST_SRC) $(UART_SRC) $(SHA1_SRC) $(SHA256_SRC)


clean:
	rm -f coretest_hashes.sim


help:
	@echo "Supported targets:"
	@echo "------------------"
	@echo "all:                 Build all targets."
	@echo "coretest_hashes:     Build the coretest hashes target."
	@echo "clean:               Delete all built files."

#===================================================================
# EOF Makefile
#===================================================================

