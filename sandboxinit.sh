#!/bin/bash
pp=`locate bytestringJSON -n1`
cabal sandbox delete
cabal sandbox init
cabal install $pp

cabal configure
cabal build
cabal install
