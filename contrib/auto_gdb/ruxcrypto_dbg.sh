#!/bin/bash
# use testnet settings,  if you need mainnet,  use ~/.ruxcryptocore/ruxcryptod.pid file instead
ruxcrypto_pid=$(<~/.ruxcryptocore/testnet3/ruxcryptod.pid)
sudo gdb -batch -ex "source debug.gdb" ruxcryptod ${ruxcrypto_pid}
