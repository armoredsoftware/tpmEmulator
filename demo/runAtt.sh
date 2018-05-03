#!/bin/bash

te=$DEMO_PATH
#ted=$DEPLOY_PATH
#pr=$te"/provisioning"

vmIp="192.168.65.132"
odroidIp="129.237.123.192"
#"192.168.65.1"   #:56395" #"129.237.127.238"

ipString=$odroidIp


make clean
(cd scripts ; ./restart_tpm.sh; ./build_all.sh; ./deploy_executables.sh)
make provision
cd $te"/attestation/"; ./AttMain $ipString
#make run

