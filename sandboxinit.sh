#!/bin/bash
pp=`locate bytestringJSON -n1`
cabal sandbox delete
cabal sandbox init
cabal install $pp
cabal install --dependencies-only
cabal configure --enable-shared
cabal install
# cabal install
