coretest_hashes
===============

The coretest system combined with cryptographic hash functions.

## Introduction ##
This is a HW subsystem that includes the coretest module connected to a
uart for external access and to hash function cores. This version
includes the SHA-1, SHA-256 cores as well as the SHA-512/x core.

## Status ##
***(2014-05-07)***

Added the SHA-512/x core to the design. The design now requires:
- 6082 ALMs
- 7370 regs


***(2014-03-17)***

Coretest_hashes has been successfully tested in real hardware. The
supplied program in src/sw can talk to coretest and initiate block
processing in both SHA-1 and SHA-256.


***(2014-03-07)***

Initial version. Build using Altera Quarus 13.1.

- Cyclone 5 GX device
- 2847 ALMs and
- 3665 registers
- 86 MHz





