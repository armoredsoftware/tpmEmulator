#!/bin/bash

fun() {
    printf "\nBuilding $1...\n\n"
    rm -rf .stack-work/ ;
    stack build --allow-different-user
    cd /home/user/stackTopLevel/tpmEmulator
}

#cd util/keys; fun "keys"
#fun "tpmEmulator"
#cd util/; fun "tpm-util"
#cd util/provisioning; fun "provisioning"
#cd attestation; fun "attestation"
cd appraisal; fun "appraisal"
