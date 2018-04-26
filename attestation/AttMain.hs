module Main where

import Control.Concurrent(threadDelay)

import TPM
import TPMUtil
import AttesterUtil
            
main = do
  let 
    ea :: Entity_Address
    ea = Entity_Address 0 0
  appReq <- attReceive ea
  attResp <- caEntity_Att appReq
  attSend attResp ea
  threadDelay 2000000
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
