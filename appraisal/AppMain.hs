module Main where

import Control.Concurrent

import TPM
import TPMUtil
import AppraiserUtil
            
main = do
  let ps = mkTPMRequest [23]
      n = 36
      appReq :: Appraiser_Request
      appReq = Appraiser_Request ps n
      ea :: Entity_Address
      ea = Entity_Address 0 0
  appSend appReq ea
  threadDelay 5
  --attResp <- appReceive ea
  --evaluate appReq attResp
  return ()
