#!/bin/bash

te=$DEMO_PATH
#ted=$DEPLOY_PATH
#pr=$te"/provisioning"
ipString="192.168.65.1"   #:56395" #"129.237.127.238"

make clean
(cd scripts ; ./restart_tpm.sh; ./build_att.sh; ./deploy_executables.sh)
make provision
cd $te"/attestation/"; ./AttMain $ipString
#make run

