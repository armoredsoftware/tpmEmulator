#!/bin/bash

te=$DEMO_PATH
#ted=$DEPLOY_PATH
#pr=$te"/provisioning"
ipString="129.237.127.238"

make clean
(cd scripts ; ./restart_tpm.sh; ./build_all.sh; ./deploy_executables.sh)
make provision
cd $te"/attestation/"; ./AttMain $ipString
#make run

