#!/bin/bash

make clean
(cd scripts ; ./restart_tpm.sh; ./build_all.sh; ./deploy_apps.sh)
make provision
make run

