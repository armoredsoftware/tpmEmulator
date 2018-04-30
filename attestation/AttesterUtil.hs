module AttesterUtil where

import Data.Binary
import qualified Data.ByteString.Lazy as LB hiding (map, putStrLn)
import qualified Data.ByteString as S
import Crypto.Cipher.AES
--import qualified Codec.Crypto.RSA as C
import Data.Digest.Pure.SHA (bytestringDigest, sha1)
import System.Process (system)
import System.Environment (getEnv)
import qualified Data.Aeson as DA
import Control.Monad(unless)
import System.Directory(doesFileExist)
import Control.Concurrent
import Data.ByteString.Char8 as C


import TPM
import TPMUtil
import Keys
import Provisioning
import Comm

--appReqFile = "/Users/adampetz/Documents/Spring_2018/tpmEmulator/appraisal/appReq.txt"
--attRespFile = "/Users/adampetz/Documents/Spring_2018/tpmEmulator/appraisal/attResp.txt"

--appReqFile = "/home/adam/tpmEmulator/appraisal/appReq.txt"
--attRespFile = "/home/adam/tpmEmulator/appraisal/attResp.txt"

waitForFile :: FilePath -> IO ()
waitForFile f = do
  fileExists <- (doesFileExist f)
  if (not fileExists)
    then do
      Prelude.putStrLn "Waiting for Appraiser Request..."
      threadDelay 2000000
      waitForFile f      
    else do
      return ()


attReceive :: Entity_Address -> IO Appraiser_Request
attReceive ea = do
  {-TODO:  socket receive here (using entity address parameter) -}

  portListen appReqFile
  waitForFile appReqFile
  lbsRead <- LB.readFile appReqFile
  Prelude.putStr "from client: "
  C.putStrLn lbsRead
  Prelude.putStrLn "end"

  
  
  --waitForFile
  --lbsRead <- LB.readFile appReqFile
  
  let
    maybeAppReq :: Maybe Appraiser_Request
    maybeAppReq = DA.decode (lbsRead)
    
  case maybeAppReq of
   (Just appReq) -> do
     Prelude.putStrLn $ "Received appraiser request: " ++ (show appReq) ++ "\n"
     return appReq
       
   _ -> error "error decoding appraiser request"

attSend :: Attester_Response -> Entity_Address -> IO ()
attSend attResp ea = do
  {- TODO:  socket send here -}

  let lbJsonAttResp = DA.encode attResp
  Prelude.putStrLn "after encoded attResp..."

  portSend "192.168.65.132" (LB.toStrict lbJsonAttResp)
  --LB.writeFile attRespFile lbJsonAttResp
  Prelude.putStrLn $ "Sent attester response: " ++ (show attResp) ++ "\n"
  return ()

caEntity_Att :: Appraiser_Request ->
                IO Attester_Response

                {-(Nonce, TPM_PCR_COMPOSITE,
                       (SignedData TPM_PUBKEY), Signature) -}
caEntity_Att appReq = do
  let
    nApp = appnonce appReq
    pcrSelect = apppcrSelect appReq

  Prelude.putStrLn "Main of entity Attester:"
  {-takeInit
  pcrReset
  fn <- prependDemoDir "attestation/App1"
  h <- myHash fn
  Prelude.putStrLn $ "Hash of App1: \n" ++ (show (LB.fromStrict h))
  val <- pcrExtendDemo (LB.fromStrict h)
  Prelude.putStrLn "Extended into PCR.  New PCR value:"
  Prelude.putStrLn $ (show val) ++ "\n"
  system fn
  -}

  --Prelude.putStrLn "before tpmMK_Idddddd"
  (iKeyHandle, aikContents) <- tpmMk_Id
  --Prelude.putStrLn "after tpmMK_Id"
  --(ekEncBlob, kEncBlob) <- caEntity_CA aikContents
  caResp <- caEntity_CA aikContents
  let ekEncBlob = symmKeyCipher caResp
      kEncBlob = certCipher caResp
  sessKey <- tpmAct_Id iKeyHandle ekEncBlob
  let caCert :: (SignedData TPM_PUBKEY)
      caCert = realDecrypt sessKey kEncBlob

      quoteExData = [nApp]
  --Prelude.putStrLn "before quote"
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
