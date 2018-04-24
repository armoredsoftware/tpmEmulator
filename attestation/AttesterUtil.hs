module AttesterUtil where

import Data.Binary
import Data.ByteString.Lazy hiding (map, putStrLn)
import Crypto.Cipher.AES
import qualified Codec.Crypto.RSA as C
import Data.Digest.Pure.SHA (bytestringDigest, sha1)
import System.Process (system)
import System.Environment (getEnv)


import TPM
import TPMUtil
import Keys
import Provisioning

attReceive :: Entity_Address -> IO Appraiser_Request
attReceive ea = do
  {-TODO:  socket receive here (using entity address parameter) -}
  let appReq :: Appraiser_Request
      appReq = Appraiser_Request undefined undefined

  return appReq

attSend :: Attester_Response -> Entity_Address -> IO ()
attSend attResp ea = do
  {- TODO:  socket send here -}
  return ();

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
  putStrLn $ "Hash of App1: \n" ++ (show (fromStrict h))
  val <- pcrExtendDemo (fromStrict h)
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

      strictCert = toStrict certBytes
      encryptedCert = encryptCTR aes ctr strictCert
      enc = fromStrict encryptedCert

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
   key = ({-B.-}Data.ByteString.Lazy.pack $ Prelude.replicate 16 v)
   --strictKey = toStrict key
   aes = initAES $ toStrict key
   ctr = toStrict key
   contents dig = TPM_ASYM_CA_CONTENTS symKey dig
