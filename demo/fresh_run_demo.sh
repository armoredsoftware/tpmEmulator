#!/bin/bash

make clean
(cd scripts ; ./restart_tpm.sh; ./build_all.sh; ./deploy_executables.sh)
make provision
make run

