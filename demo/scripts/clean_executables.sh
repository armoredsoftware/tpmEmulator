#!/bin/bash

te=/home/user/stackTopLevel/tpmEmulator/demo
sw=$te/../appraisal/.stack-work/install/x86_64-linux/lts-6.31/7.10.3/bin

rm $te/appraisal/AppMain

rm $te/provisioning/ProvisioningMain

rm $te/attestation/App1
rm $te/attestation/goodApp1
rm $te/attestation/App2
rm $te/attestation/goodApp2

rm $te/attestation/badApp1
rm $te/attestation/badApp2
