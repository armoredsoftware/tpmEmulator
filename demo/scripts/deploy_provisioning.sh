#!/bin/bash

te=/home/user/stackTopLevel/tpmEmulator/demo
pr=$te/provisioning

cd $pr; ./ProvisioningMain a

cp $pr/goldenPcrComposite.txt $pr/caPrivateKey.txt $pr/caPublicKey.txt $te/appraisal/

#cp $pr/ekpub.txt $te/appraisal/
