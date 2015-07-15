#!/bin/bash

pp=`locate bytestringJSON -n1`
cd $pp
./sandboxinit.sh
cd -

cabal sandbox delete
cabal sandbox init
cabal install $pp

cabal configure
cabal build
#cabal install
