module Main where

import System.Process (system)
import TPMUtil (pcrExtendDemo, myHash, pcrReset)
import Data.ByteString.Lazy hiding (putStrLn)

main = do
  putStrLn "App1 is running!"
  fn <- prependDemoDir "attestation/App2"
  h <- myHash fn
  putStrLn $ "Hash of App2: \n" ++ (show (fromStrict h))
  val <- pcrExtendDemo (fromStrict h)
  putStrLn "Extended into PCR.  New PCR value:"
  putStrLn (show val)
  system fn
  return ()
