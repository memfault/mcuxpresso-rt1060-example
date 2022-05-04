# MIMXRT1060-EVKB Memfault Network Example

Example application for MCUXpresso, based on the
`lwip_httpscli_mbedTLS_freertos` sample from the `SDK_2.10.1_MIMXRT1060-EVKB`
from NXP.

See information about the base example project in
[`doc/readme.txt`](doc/readme.txt).

This project adds the Memfault SDK as a Git submodule, and enables the Memfault
demo console commands for testing Memfault end-to-end.

## Instructions

1. clone this repo, with submodules:

   ```bash
   ❯ git clone --recurse-submodules https://github.com/memfault/mcuxpresso-rt1060-example.git
   ```

2. import the project into MCUXpresso
3. configure the Memfault project key in
   [`lwip_httpscli_mbedTLS/httpsclient.c`](lwip_httpscli_mbedTLS/httpsclient.c)
4. build + flash to the board. connect an Ethernet cable with internet acess.
5. open a serial terminal to the CMSIS-DAP port on the board:

   ```bash
   # example, using pyserial-miniterm
   ❯ pyserial-miniterm --raw /dev/ttyACM0 115200
   ```
