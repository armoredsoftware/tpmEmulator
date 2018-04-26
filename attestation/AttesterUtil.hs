module AttesterUtil where

import Data.Binary
import qualified Data.ByteString.Lazy as LB hiding (map, putStrLn)
import Crypto.Cipher.AES
import qualified Codec.Crypto.RSA as C
import Data.Digest.Pure.SHA (bytestringDigest, sha1)
import System.Process (system)
import System.Environment (getEnv)
import qualified Data.Aeson as DA
import Control.Monad(unless)
import System.Directory(doesFileExist)
import Control.Concurrent


import TPM
import TPMUtil
import Keys
import Provisioning

--appReqFile = "/Users/adampetz/Documents/Spring_2018/tpmEmulator/appraisal/appReq.txt"
--attRespFile = "/Users/adampetz/Documents/Spring_2018/tpmEmulator/appraisal/attResp.txt"

appReqFile = "/home/adam/tpmEmulator/appraisal/appReq.txt"
attRespFile = "/home/adam/tpmEmulator/appraisal/attResp.txt"

waitForFile :: IO ()
waitForFile = do
  fileExists <- (doesFileExist appReqFile)
  if (not fileExists)
    then do
      putStrLn "Waiting for Appraiser Request..."
      threadDelay 2000000
      waitForFile      
    else do
      return ()

attReceive :: Entity_Address -> IO Appraiser_Request
attReceive ea = do
  {-TODO:  socket receive here (using entity address parameter) -}
      
    waitForFile
    lbsRead <- LB.readFile appReqFile
         
    let
      maybeAppReq :: Maybe Appraiser_Request
      maybeAppReq = DA.decode lbsRead

    case maybeAppReq of
     (Just appReq) -> do
       putStrLn $ "Received appraiser request: " ++ (show appReq) ++ "\n"
       return appReq
       
     _ -> error "error decoding appraiser request"

attSend :: Attester_Response -> Entity_Address -> IO ()
attSend attResp ea = do
  {- TODO:  socket send here -}

  let lbJsonAttResp = DA.encode attResp
  LB.writeFile attRespFile lbJsonAttResp
  putStrLn $ "Sent attester response: " ++ (show attResp) ++ "\n"
  return ()

caEntity_Att :: Appraiser_Request ->
                IO Attester_Response

                {-(Nonce, TPM_PCR_COMPOSITE,
                       (SignedData TPM_PUBKEY), Signature) -}
caEntity_Att appReq = do
  let
    nApp = appnonce appReq
    pcrSelect = apppcrSelect appReq

  putStrLn "Main of entity Attester:"
  {-takeInit
  pcrReset
  fn <- prependDemoDir "attestation/App1"
  h <- myHash fn
  putStrLn $ "Hash of App1: \n" ++ (show (LB.fromStrict h))
  val <- pcrExtendDemo (LB.fromStrict h)
  putStrLn "Extended into PCR.  New PCR value:"
  putStrLn $ (show val) ++ "\n"
  system fn
  -}

  --putStrLn "before tpmMK_Idddddd"
  (iKeyHandle, aikContents) <- tpmMk_Id
  --putStrLn "after tpmMK_Id"
  --(ekEncBlob, kEncBlob) <- caEntity_CA aikContents
  caResp <- caEntity_CA aikContents
  let ekEncBlob = symmKeyCipher caResp
      kEncBlob = certCipher caResp
  sessKey <- tpmAct_Id iKeyHandle ekEncBlob
  let caCert :: (SignedData TPM_PUBKEY)
      caCert = realDecrypt sessKey kEncBlob

      quoteExData = [nApp]
  --putStrLn "before quote"
  (pcrComp, qSig) <- tpmQuote iKeyHandle pcrSelect quoteExData
  let response = ({-evidence, -}nApp, pcrComp, caCert, qSig)

      attresponse :: Attester_Response
      attresponse = (Attester_Response nApp pcrComp caCert qSig)
  
  return attresponse --response

 {-(Nonce, TPM_PCR_COMPOSITE,
                       (SignedData TPM_PUBKEY), Signature) -}



caEntity_CA :: {-LibXenVChan -> -}AikContents -> IO CA_Response
caEntity_CA {-attChan-} aikContents = do

  {-[AEntityInfo eInfo,
   ASignedData (SignedData
                (ATPM_IDENTITY_CONTENTS pubKey)
                 sig)]  <- receive' attChan
  -}
  let pubKey = dat aikContents
      --sig = sig aikContents
  ekPubKey <- readEK

  let iPubKey = identityPubKey pubKey
      iDigest = tpm_digest $ Data.Binary.encode iPubKey
      asymContents = contents iDigest
      blob = Data.Binary.encode asymContents
  encBlob <- tpm_rsa_pubencrypt ekPubKey blob

  caPriKey <- getCAPrivateKey
  let caCert = realSign caPriKey (Data.Binary.encode iPubKey)
      certBytes = Data.Binary.encode (SignedData iPubKey caCert)

      strictCert = LB.toStrict certBytes
      encryptedCert = encryptCTR aes ctr strictCert
      enc = LB.fromStrict encryptedCert

  {-send' attChan [ACipherText encBlob, ACipherText enc]-}
  return $ CA_Response encBlob enc  --(encBlob, enc)
 where
   symKey =
     TPM_SYMMETRIC_KEY
     (tpm_alg_aes128)
     (tpm_es_sym_ctr)
     key

   v:: Word8
   v = 1
   key = ({-B.-}LB.pack $ Prelude.replicate 16 v)
   --strictKey = LB.toStrict key
   aes = initAES $ LB.toStrict key
   ctr = LB.toStrict key
   contents dig = TPM_ASYM_CA_CONTENTS symKey dig
