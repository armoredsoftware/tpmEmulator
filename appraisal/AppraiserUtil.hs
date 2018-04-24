{-# LANGUAGE DeriveGeneric, FlexibleInstances #-}

module AppraiserUtil where

import Data.Binary as B
import qualified Data.ByteString.Lazy as LB hiding (pack, map, putStrLn)
import Data.ByteString as BS hiding (putStrLn)
--import Crypto.Cipher.AES
import qualified Codec.Crypto.RSA as C
import Data.Digest.Pure.SHA (bytestringDigest, sha1)
import qualified Data.Aeson as DA
import GHC.Generics
import System.Directory(removeFile)

import TPM
import TPMUtil
import AttesterUtil (caEntity_Att)
import Keys
import Provisioning

import qualified Data.Text.Encoding as TE
import qualified Data.ByteString.Base64 as Base64
import qualified Data.Text as T




appSend :: Appraiser_Request -> Entity_Address -> IO ()
appSend ar ea  = do
  let ps = apppcrSelect ar
      --n  = appnonce ar
  putStrLn "Main of entity Appraiser:" 
  putStrLn $ "Sending Request: ( " ++ (show ps) ++ ", Nonce ) \n"
  -- TODO:  socket send here
  let lbJsonAppReq = DA.encode ar
  LB.writeFile "./appReq.txt" lbJsonAppReq
  lbsRead <- LB.readFile "./appReq.txt"
  let
    newAppReq :: Maybe Appraiser_Request
    newAppReq = DA.decode lbsRead
  putStrLn (show newAppReq)
  --removeFile "./appReq.txt"
  return ()
  


  

  --(n, comp, cert, qSig) <- caEntity_Att nonce pcrSelect
  --evaluate (nonce, pcrSelect) (n, comp, cert, qSig)

appReceive :: Entity_Address -> IO Attester_Response
appReceive ea = do
  {-TODO:  socket receive here (using entity address parameter) -}
  let resp :: Attester_Response
      resp = Attester_Response undefined undefined undefined undefined
  return resp
  
evaluate :: {-(Nonce, TPM_PCR_SELECTION) ->
            (Nonce, TPM_PCR_COMPOSITE,
             (SignedData TPM_PUBKEY), Signature)-}
  Appraiser_Request -> Attester_Response
  -> IO String
evaluate appReq attResp   = do
{-(nonceReq, pcrSelect)
  (nonceResp, pcrComp, cert@(SignedData aikPub aikSig), qSig) -}


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
  putStrLn ("Actual PCR Composite: \n" ++ (show pcrComp) ++ "\n")
  putStrLn ("Golden PCR Composite: \n" ++ (show goldenPcrComposite) ++ "\n")

  sequence $ [{-logf, -}putStrLn] <*> (pure ("CACert Signature: " ++ (show r1)))
  sequence $ [{-logf, -}putStrLn] <*> (pure ( "Quote Package Signature: " ++ (show r2)  ))
  sequence $ [{-logf, -}putStrLn] <*> (pure ( "Nonce: " ++ (show r3)))
  sequence $ [{-logf, -}putStrLn] <*> (pure ( "PCR Values: " ++ (show r4)))

  return $ case (and [r1, r2, r3, r4]) of
    True -> "All checks succeeded"
    False -> "At least one check failed"
