#!/bin/bash

te=$DEMO_PATH
#ted=$DEPLOY_PATH
#pr=$te"/provisioning"

#make clean
#(cd scripts ; ./restart_tpm.sh; ./build_all.sh; ./deploy_executables.sh)
#make provision
cd $te"/appraisal/"; ./AppMain #make run
#rm "/home/adam/tpmEmulator/appraisal/appReq.txt"
#rm "/home/adam/tpmEmulator/appraisal/attResp.txt"

