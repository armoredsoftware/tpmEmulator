module Main where
import Provisioning

import Data.Char
import Codec.Crypto.RSA
import System.Random
import System.Environment (getArgs)

main :: IO ()
main = do
  putStrLn "START of provisioning main"
  args <- getArgs
  case args of
    [] -> do
      i <- getInput
      putStrLn ""
      case i of
        1 -> ekProvision
        2 -> pcrProvision
        3 -> exportCAKeys
        _ -> error "input ERROR"
    [x] -> do
      pcrProvision
      exportCAKeys
    _ ->
      putStrLn "Invalid arguments to ProvisioningMain."
      
      
  return ()

getInput :: IO Int
getInput = do
  putStrLn "What would you like to do?:"
  putStrLn "Enter 1 for exProvision"
  putStrLn "Enter 2 for pcrProvision"
  putStrLn "Enter 3 for exportCAKeys"

  c <- getChar
  let i = digitToInt c
  if (i < 1 || i > 3)
  then do
     putStrLn "Invalid input."
     getInput
  else
    return i
