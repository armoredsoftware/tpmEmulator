#!/bin/bash

te=$DEMO_PATH
#ted=$DEPLOY_PATH
#teb=$te"/../"
sw=$SW_PATH #$te"/../appraisal/.stack-work/install/i386-linux/lts-6.31/7.10.3/bin"
swAtt=$SWatt_PATH 

#echo $te/appraisal/ $ted/appraisal/ | xargs -n 1 cp $sw/AppMain
echo $te"/appraisal/"  | xargs -n 1 cp $sw"/AppMain"
echo $te"/attestation/"  | xargs -n 1 cp $swAtt"/AttMain"

#echo $te/provisioning/ $ted/provisioning/ | xargs -n 1 cp $sw/ProvisioningMain
echo $te"/provisioning/"  | xargs -n 1 cp $sw"/ProvisioningMain" 

cp $te/apps/happy $te/attestation/App1
cp $te/apps/happy $te/attestation/goodApp1
#cp $sw/App2 $te/attestation/
#cp $sw/App2 $te/attestation/goodApp2

cp $te/apps/unhappy $te/attestation/badApp1
#cp $sw/BAD_App2 $te/attestation/badApp2
