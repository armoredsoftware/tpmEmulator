module Main where

import Control.Concurrent(threadDelay)
import System.Directory(removeFile)
import System.Environment(getArgs)

import TPM
import TPMUtil
import AppraiserUtil
--import Comm(portSend)
import Data.ByteString.Char8 as C
import Comm(getAppReqFile, getAttRespFile)
            
main = do
  args <- getArgs
  if (Prelude.length args == 1)
  then do
    let ps = mkTPMRequest [23]
        n = 36
        appReq :: Appraiser_Request
        appReq = Appraiser_Request ps n
        targetIP = Prelude.head args
        ea :: Entity_Address
        ea = Entity_Address 0 targetIP
    appSend appReq ea
  
    threadDelay 5
    attResp <- appReceive ea
    evaluate appReq attResp
    appReqFile <- getAppReqFile
    attRespFile <- getAttRespFile
    removeFile appReqFile
    removeFile attRespFile
    return ()
  else
    error "must provide target IP string to AppMain"
 
