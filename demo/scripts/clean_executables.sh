#!/bin/bash

te=$DEMO_PATH
sw=$te/../appraisal/.stack-work/install/x86_64-linux/lts-6.31/7.10.3/bin

myrm $te/appraisal/AppMain

myrm $te/provisioning/ProvisioningMain

myrm $te/attestation/App1
myrm $te/attestation/goodApp1
myrm $te/attestation/App2
myrm $te/attestation/goodApp2

myrm $te/attestation/badApp1
myrm $te/attestation/badApp2
