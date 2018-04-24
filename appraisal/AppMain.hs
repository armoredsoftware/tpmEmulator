module Main where

import TPM
import TPMUtil
import AppraiserUtil
            
main = do
  let ps = mkTPMRequest [23]
      n = 34
      appReq :: Appraiser_Request
      appReq = Appraiser_Request ps n
      ea :: Entity_Address
      ea = Entity_Address 0 0
  appSend appReq ea
  attResp <- appReceive ea
  evaluate appReq attResp
  return ()
