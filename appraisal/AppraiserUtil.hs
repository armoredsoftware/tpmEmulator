{-# LANGUAGE DeriveGeneric, FlexibleInstances #-}

module AppraiserUtil where

import Data.Binary as B
import qualified Data.ByteString.Lazy as LB hiding (pack, map, putStrLn)
import Data.ByteString as BS hiding (putStrLn)
--import Crypto.Cipher.AES
--import qualified Codec.Crypto.RSA as C
import Data.Digest.Pure.SHA (bytestringDigest, sha1)
import qualified Data.Aeson as DA
import GHC.Generics
import System.Directory(removeFile)
import Control.Concurrent(threadDelay)
import System.Directory(doesFileExist)
import Data.ByteString.Char8 as C

import TPM
import TPMUtil
--import AttesterUtil (caEntity_Att)
import Keys
import Provisioning
import Comm

import qualified Data.Text.Encoding as TE
import qualified Data.ByteString.Base64 as Base64
import qualified Data.Text as T

--appReqFile = "/Users/adampetz/Documents/Spring_2018/tpmEmulator/appraisal/appReq.txt"
--attRespFile = "/Users/adampetz/Documents/Spring_2018/tpmEmulator/appraisal/attResp.txt"

--appReqFile = "/home/adam/tpmEmulator/appraisal/appReq.txt"
--attRespFile = "/home/adam/tpmEmulator/appraisal/attResp.txt"

--portNumber = "192.168.65.132"
--portNumber = "129.237.123.192"

waitForFile :: FilePath -> IO ()
waitForFile f = do
  fileExists <- (doesFileExist f)
  if (not fileExists)
    then do
      Prelude.putStrLn "Waiting for Attester Response..."
      threadDelay 2000000
      waitForFile f      
    else do
      return ()

appSend :: Appraiser_Request -> Entity_Address -> IO ()
appSend ar ea  = do
  let ps = apppcrSelect ar
      --n  = appnonce ar
      pn = ip ea
  Prelude.putStrLn "Main of entity Appraiser:" 
  Prelude.putStrLn $ "Sending Request: ( " ++ (show ps) ++ ", Nonce ) \n"
  let lbJsonAppReq = DA.encode ar

  portSend pn (LB.toStrict lbJsonAppReq)
  return ()

appReceive :: Entity_Address -> IO Attester_Response
appReceive ea = do
  attRespFile <- getAttRespFile
  portListen attRespFile
  waitForFile attRespFile
  lbsRead <- LB.readFile attRespFile
  Prelude.putStr "from server: "
  C.putStrLn (LB.toStrict lbsRead)
  Prelude.putStrLn "end"
  let
    maybeAttResp :: Maybe Attester_Response
    maybeAttResp = DA.decode (lbsRead)

  case maybeAttResp of
     (Just attResp) -> do
       Prelude.putStrLn $ "Received attester response: " ++ (show attResp) ++ "\n"
       return attResp
     _ -> error "error decoding attestation response"
     
  
evaluate :: Appraiser_Request -> Attester_Response -> IO String
evaluate appReq attResp   = do
  let nonceReq = appnonce appReq
      pcrSelect = apppcrSelect appReq
      nonceResp = attnonce attResp
      pcrComp = comp attResp
      cert = attcert attResp
      aikPub = dat cert
      aikSig = sig cert
      qSig = quoteSig attResp
  
  caPublicKey <- getCAPublicKey

  
  let blobEvidence :: LB.ByteString
      {-blobEvidence = packImpl [AEvidence ev, ANonce nonceResp,
                               ASignedData $ SignedData ( ATPM_PUBKEY (dat cert)) (sig cert)] --pubKey -}
      blobEvidence = packImpl [nonceResp]
      evBlobSha1 =  bytestringDigest $ sha1 blobEvidence

      quoteInfo :: TPM_QUOTE_INFO
      quoteInfo = TPM_QUOTE_INFO (tpm_pcr_composite_hash $ pcrComp)                                                        (TPM_NONCE evBlobSha1)

      aikPublicKey = tpm_get_rsa_PublicKey aikPub

      r1 = realVerify caPublicKey (B.encode aikPub) aikSig
      r2 = realVerify aikPublicKey (B.encode quoteInfo) qSig
      r3 = nonceReq == nonceResp
  goldenPcrComposite <- readGoldenComp

  let r4 = pcrComp == goldenPcrComposite
  Prelude.putStrLn ("Actual PCR Composite: \n" ++ (show pcrComp) ++ "\n")
  Prelude.putStrLn ("Golden PCR Composite: \n" ++ (show goldenPcrComposite) ++ "\n")

  sequence $ [{-logf, -}Prelude.putStrLn] <*> (pure ("CACert Signature: " ++ (show r1)))
  sequence $ [{-logf, -}Prelude.putStrLn] <*> (pure ( "Quote Package Signature: " ++ (show r2)  ))
  sequence $ [{-logf, -}Prelude.putStrLn] <*> (pure ( "Nonce: " ++ (show r3)))
  sequence $ [{-logf, -}Prelude.putStrLn] <*> (pure ( "PCR Values: " ++ (show r4)))

  return $ case (and [r1, r2, r3, r4]) of
    True -> "All checks succeeded"
    False -> "At least one check failed"
