#!/bin/bash

te=$DEMO_PATH
#ted=$DEPLOY_PATH
#pr=$te"/provisioning"

#make clean
#(cd scripts ; ./restart_tpm.sh; ./build_all.sh; ./deploy_executables.sh)
#make provision

for i in {1..4}
do
    cd $te"/appraisal/"; ./AppMain #make run
    sleep 10s
done

#cd $te"/apps/"; ./unhappy
#cd $te"/attestation/"; ./App1

#rm "/home/adam/tpmEmulator/appraisal/appReq.txt"
#rm "/home/adam/tpmEmulator/appraisal/attResp.txt"

