#!/bin/bash

./kill_tpm.sh
depmod -ae
modprobe tpmd_dev
tpmd clear
