#!/bin/bash

./kill_tpm.sh
depmod -ae
modprobe tpmd_dev

if [ $# -eq 0 ]
then
    tpmd clear
else
    tpmd clear -f
fi

