#!/bin/bash

te=$DEMO_PATH
#ted=$DEPLOY_PATH
pr=$te"/provisioning"

cd $pr; ./ProvisioningMain a b

echo $te"/appraisal/"  | xargs -n 1 cp $pr"/goldenPcrComposite.txt"
#cp $pr/goldenPcrComposite.txt $pr/caPrivateKey.txt $pr/caPublicKey.txt $te/appraisal/

#cp $pr/ekpub.txt $te/appraisal/
