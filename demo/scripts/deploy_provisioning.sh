#!/bin/bash

te=$DEMO_PATH
pr=$te/provisioning

cd $pr; ./ProvisioningMain a

cp $pr/goldenPcrComposite.txt $te/appraisal/
#cp $pr/goldenPcrComposite.txt $pr/caPrivateKey.txt $pr/caPublicKey.txt $te/appraisal/

#cp $pr/ekpub.txt $te/appraisal/
