#!/bin/bash

te=$DEMO_PATH
ted=$DEPLOY_PATH
teb=$te/../
sw=$teb/appraisal/.stack-work/install/x86_64-linux/lts-6.31/7.10.3/bin

#cp $sw/AppMain $te/appraisal/

#cp $sw/ProvisioningMain $te/provisioning/

echo $te/attestation $ted/attestation $te/attestation/goodApp1 $ted/attestation/goodApp1 | xargs -n 1 cp $sw/App1

echo $te/attestation/ $ted/attestation/ $te/attestation/goodApp2 $ted/attestation/goodApp2 | xargs -n 1 cp $sw/App2 

echo $te/attestation/badApp1 $ted/attestation/badApp1 | xargs -n 1 cp $sw/BAD_App1 
echo $te/attestation/badApp2 $ted/attestation/badApp2 | xargs -n 1 cp $sw/BAD_App2 
