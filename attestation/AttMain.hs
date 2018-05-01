module Main where

import Control.Concurrent
import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as C
import System.Clock

import TPM
import TPMUtil
import AttesterUtil
--import Comm
            
main = do
{-
  portListen
  threadDelay 1
  bString <- S.readFile "/home/adam/tpmEmulator/demo/attestation/temp.txt"
  putStr "from client: "
  C.putStrLn bString
  putStrLn "end"
-}

  totalTimesFile <- prependDemoDir "attestation/totalTimes.txt"
  
  
  let 
    ea :: Entity_Address
    ea = Entity_Address 0 0
  putStrLn "before attReceive in AttMain"
  appReq <- attReceive ea
  putStrLn "after attReceive in AttMain"

  startTime <- getTime Monotonic
  attResp <- caEntity_Att appReq
  endTime <- getTime Monotonic
  logTime totalTimesFile startTime endTime

  
  putStrLn "after attResp generated..."
  attSend attResp ea
  threadDelay 2000000
  putStrLn "after attSend"
  main



  
  {-
  let ps = mkTPMRequest [23]
      n = 36
      appReq :: Appraiser_Request
      appReq = Appraiser_Request ps n
      ea :: Entity_Address
      ea = Entity_Address 0 0
  appSend appReq ea
  --attResp <- appReceive ea
  --evaluate appReq attResp
-}
  return ()
