#!/bin/bash

te=/home/user/stackTopLevel/tpmEmulator/demo
teb=/home/user/stackTopLevel/tpmEmulator/
sw=$teb/appraisal/.stack-work/install/x86_64-linux/lts-6.31/7.10.3/bin

cp $sw/AppMain $te/appraisal/

cp $sw/ProvisioningMain $te/provisioning/

cp $sw/App1 $te/attestation/
cp $sw/App1 $te/attestation/goodApp1
cp $sw/App2 $te/attestation/
cp $sw/App2 $te/attestation/goodApp2

cp $sw/BAD_App1 $te/attestation/badApp1
cp $sw/BAD_App2 $te/attestation/badApp2
