#!/bin/bash

te=$DEMO_PATH/../

fun() {
    #printf "\nBuilding $1...\n\n"
    #rm -rf .stack-work/ ;
    stack build --allow-different-user --ghc-options "fPIC"
}

#cd  $te/util/keys; fun "keys"
#fun "tpmEmulator"
#cd util/; fun "tpm-util"
#cd util/provisioning; fun "provisioning"
#cd attestation; fun "attestation"
cd $te/appraisal; fun "appraisal"
