module Main where

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
