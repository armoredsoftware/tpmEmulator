#!/bin/bash

cd scripts
./restart_tpm.sh
./make_all.sh

cd ../appraisal
./AppMain
