module Main where

import AppraiserUtil (appmain')

main = do
  s <- appmain'
  putStrLn s
  return ()
