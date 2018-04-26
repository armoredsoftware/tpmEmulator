#!/bin/bash

te=$DEMO_PATH
#ted=$DEPLOY_PATH
#pr=$te"/provisioning"

make clean
(cd scripts ; ./restart_tpm.sh; ./build_all.sh; ./deploy_executables.sh)
make provision
cd $te"/attestation/"; ./AttMain
#make run

