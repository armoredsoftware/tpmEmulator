{-# LANGUAGE DeriveGeneric, FlexibleInstances#-}
module TPMUtil where

import TPM

import Data.ByteString.Lazy as L  hiding (putStrLn)
import Data.ByteString as S hiding (putStrLn)
import Data.Word
import Data.Binary
import Codec.Crypto.RSA as C hiding (sign, verify)
import Data.Digest.Pure.SHA (bytestringDigest, sha1)
import Crypto.Cipher.AES
--import Crypto.Hash.SHA1 (hashlazy)
import System.Environment (getEnv)
import GHC.Generics
import qualified Data.Aeson as DA

import qualified Data.Text.Encoding as TE
import qualified Data.ByteString.Base64 as Base64
import qualified Data.Text as T

tpm :: TPMSocket
tpm = tpm_socket "/var/run/tpm/tpmd_socket:0" --"/dev/tpm/tpmd_socket:0" 

ownerPass :: String
ownerPass = "adam"

srkPass :: String
srkPass = ""

aikPass :: String
aikPass = "i"

takeInit :: IO TPM_PUBKEY
takeInit = do
  --putStrLn "Before forceclearrrr"
  tpm_forceclear tpm
  {-sOwner <- tpm_getcap_owner tpm
  when (hasOwner == False) $ do
-}
  (pubkey, _) <- tpm_key_pubek tpm
  --putStrLn $ "Public EK: " ++ show pubkey
  tkShn <- tpm_session_oiap tpm
  tpm_takeownership tpm tkShn pubkey oPass sPass
  tpm_session_close tpm tkShn
  putStrLn "\nTPM OWNERSHIP TAKEN\n"
  return pubkey
 where oPass = tpm_digest_pass ownerPass
       sPass = tpm_digest_pass srkPass

mkTPMRequest :: [Word8] -> TPM_PCR_SELECTION
mkTPMRequest xs = do
  let max = 24  -- <- tpm_getcap_pcrs tpm  --Maybe add this to assumptions?(24)
  let selection = tpm_pcr_selection max xs in
    selection

makeAndLoadAIK :: IO (TPM_KEY_HANDLE, L.ByteString)
makeAndLoadAIK = do
  sShn <- tpm_session_oiap tpm
  oShn <- tpm_session_osap tpm oPass oKty ownerHandle
  (identKey, iSig) <- tpm_makeidentity tpm sShn oShn key sPass iPass iPass {-pass CALabelDigest here instead of iPass eventually?-}
  tpm_session_close tpm sShn --Check True val here!!(use clo?)
  tpm_session_close tpm oShn

  loadShn <- tpm_session_oiap tpm
  iKeyHandle <- tpm_loadkey2 tpm loadShn tpm_kh_srk identKey sPass
  tpm_session_close tpm loadShn
  --putStrLn "identKey Loaded"
  return (iKeyHandle, iSig)

 where key = tpm_key_create_identity tpm_auth_never
       oKty = tpm_et_xor_owner
       kty = tpm_et_xor_keyhandle
       ownerHandle = (0x40000001 :: Word32)
       oPass = tpm_digest_pass ownerPass
       sPass = tpm_digest_pass srkPass
       iPass = tpm_digest_pass aikPass


attGetPubKey :: TPM_KEY_HANDLE -> TPM_DIGEST -> IO TPM_PUBKEY
attGetPubKey handle pass = do
  shn <- tpm_session_oiap tpm
  pubKey <- tpm_getpubkey tpm shn handle pass
  tpm_session_close tpm shn
  return pubKey

mkQuote :: TPM_KEY_HANDLE -> TPM_DIGEST -> TPM_PCR_SELECTION
                  -> L.ByteString -> IO (TPM_PCR_COMPOSITE, L.ByteString)
mkQuote qKeyHandle qKeyPass pcrSelect exData = do
   quoteShn <- tpm_session_oiap tpm
   --putStrLn "Before quote packed and generatedddddddddddddddddddddd"
   (pcrComp, sig) <- tpm_quote tpm quoteShn qKeyHandle
                             (TPM_NONCE exData) pcrSelect qKeyPass
   tpm_session_close tpm quoteShn
   putStrLn $ "\nQuote generated:\n"
   return (pcrComp, sig)

pcrModify :: String -> IO TPM_PCRVALUE
pcrModify val = tpm_pcr_extend_with tpm (fromIntegral pcrNum) val

pcrExtendDemo :: L.ByteString -> IO TPM_PCRVALUE
pcrExtendDemo bs = tpm_pcr_extend tpm (fromIntegral pcrNum) (TPM_DIGEST bs)

pcrReset :: IO TPM_PCRVALUE
pcrReset = do
  tot <- tpm_getcap_pcrs tpm
  tpm_pcr_reset tpm (fromIntegral tot) [fromIntegral pcrNum]
  val <- tpm_pcr_read tpm (fromIntegral 23)
  --putStrLn $ show val
  return val

pcrNum = 23

myHash :: FilePath -> IO S.ByteString
myHash fp = do
  fb <- L.readFile fp
  let bs = bytestringDigest $ sha1 fb
  return (L.toStrict bs)
  
  --return (bytestringDigest $ sha1 fb)
  
--myHash = fmap bytestringDigest . sha1 . L.readFile
--myHash = fmap hashlazy . L.readFile

prependDemoDir :: String -> IO String
prependDemoDir suffix = do
  prefix <- getEnv "DEMO_PATH"
  let cleanPrefix = if ((Prelude.last prefix) == '/')
                    then prefix
                    else prefix ++ "/"
                      
  return (cleanPrefix ++ suffix)










{- Attester / Appraiser shared utils TODO:  Move these to separate library? -}
type Nonce = Int
type SymmKey = TPM_SYMMETRIC_KEY
type CipherText = L.ByteString;
--type PrivateKey = C.PrivateKey --L.ByteString;
--type PublicKey = C.PublicKey --L.ByteString;
type Signature = L.ByteString;
data SignedData a = SignedData {
  dat :: a,
  sig :: Signature
} deriving (Eq, Read, Show, Generic)

instance (Binary a) => Binary (SignedData a) where
  put (SignedData a b) =
    do
      put a
      put b

  get = do a <- get
           b <- get
           return $ SignedData a b
           
type AikContents = SignedData TPM_IDENTITY_CONTENTS



a :: Nonce
a = 3


generateNonce :: IO Nonce
generateNonce = do
  return 56 --faked

checkNonce :: Nonce -> Nonce -> IO ()
checkNonce expected actual = do
  case (expected == actual) of
    True -> return ()
    False -> putStrLn "Nonce check failed"


--Symmetric Key decryption
realDecrypt :: (Binary a) => SymmKey -> CipherText -> a
realDecrypt sessKey blob = let
  keyBytes = tpmSymmetricData sessKey
  strictKey = toStrict keyBytes
  aes = initAES strictKey
  ctr = strictKey
  decryptedBytes = decryptCTR aes ctr (toStrict blob)
  lazy = fromStrict decryptedBytes in
  (decode lazy)

realSign :: PrivateKey -> L.ByteString -> Signature --paramaterize over hash?
realSign priKey bytes = C.rsassa_pkcs1_v1_5_sign C.hashSHA1 priKey bytes --Concrete implementation plugs in here

realVerify :: PublicKey -> L.ByteString -> Signature -> Bool
realVerify pubKey m s = C.rsassa_pkcs1_v1_5_verify C.hashSHA1 pubKey m s

--Concrete packing(well-defined strategy for combining elements in preparation for encryption/signing) implementation
packImpl :: (Binary a) => [a] -> L.ByteString
packImpl as = encode as --mconcat bslist
 --where bslist = map tobs as

--Concrete unpacking implementation
unpackImpl :: Binary a => L.ByteString -> [a]
unpackImpl bs = decode bs


iPass = tpm_digest_pass aikPass
oPass = tpm_digest_pass ownerPass

tpmMk_Id :: IO (TPM_KEY_HANDLE, AikContents)
tpmMk_Id = do
  (aikHandle, iSig) <- makeAndLoadAIK
  aikPub <- attGetPubKey aikHandle iPass
  let aikContents = TPM_IDENTITY_CONTENTS iPass aikPub
  return (aikHandle, SignedData aikContents iSig)

tpmAct_Id :: TPM_KEY_HANDLE -> CipherText -> IO SymmKey
tpmAct_Id iKeyHandle actInput = do
  iShn <- tpm_session_oiap tpm
  oShn <- tpm_session_oiap tpm
  sessionKey <- tpm_activateidentity tpm iShn oShn
                iKeyHandle iPass oPass actInput
  return sessionKey

tpmQuote :: Binary a => TPM_KEY_HANDLE -> TPM_PCR_SELECTION -> [a] {-[ArmoredData]-}
         -> IO (TPM_PCR_COMPOSITE, Signature)
tpmQuote qKeyHandle pcrSelect exDataList = do
  let evBlob = packImpl exDataList
      evBlobSha1 = bytestringDigest $ sha1 evBlob
  (comp, sig) <- mkQuote qKeyHandle iPass pcrSelect evBlobSha1
  return (comp, sig)




-- Shared demo types -------------

data Appraiser_Request = Appraiser_Request {
  apppcrSelect :: TPM_PCR_SELECTION,
  appnonce :: Nonce
  }  deriving (Show, Read, Eq, Generic)

data Attester_Response = Attester_Response {
  attnonce :: Nonce,
  comp  :: TPM_PCR_COMPOSITE,
  attcert  :: (SignedData TPM_PUBKEY),
  quoteSig  :: Signature
  }  deriving (Show, Read, Eq, Generic)

data Entity_Address = Entity_Address {
  portNum :: Int,
  ip :: Int {- TODO: real host info here -}
  }  deriving (Show, Read, Eq, Generic)

data CA_Response = CA_Response {
  symmKeyCipher :: CipherText,
  certCipher    :: CipherText
  }  deriving (Show, Read, Eq, Generic)
                   

encodeToText :: S.ByteString -> T.Text
encodeToText = TE.decodeUtf8 . Base64.encode

decodeFromText :: T.Text -> L.ByteString
decodeFromText = {-either fail return .-} L.fromStrict . Base64.decodeLenient . TE.encodeUtf8


instance DA.ToJSON L.ByteString where
        toJSON = DA.String . encodeToText . L.toStrict
instance DA.FromJSON L.ByteString where
        parseJSON (DA.String str) = pure $ decodeFromText str
        
instance DA.ToJSON Appraiser_Request
instance DA.ToJSON Attester_Response
instance DA.ToJSON AikContents
instance DA.ToJSON TPM_IDENTITY_CONTENTS
--instance DA.ToJSON Entity_Address

instance DA.ToJSON TPM_PCR_SELECTION
instance DA.ToJSON TPM_PCR_COMPOSITE
instance DA.ToJSON TPM_DIGEST
instance DA.ToJSON TPM_PUBKEY
instance DA.ToJSON TPM_STORE_PUBKEY
instance DA.ToJSON TPM_KEY_PARMS
instance DA.ToJSON TPM_SYMMETRIC_KEY_PARMS
instance DA.ToJSON TPM_RSA_KEY_PARMS
instance DA.ToJSON TPM_KEY_PARMS_DATA
instance DA.ToJSON (SignedData TPM_PUBKEY)

instance DA.FromJSON Appraiser_Request
instance DA.FromJSON Attester_Response
--instance DA.FromJSON Entity_Address

instance DA.FromJSON TPM_PCR_SELECTION
instance DA.FromJSON TPM_PCR_COMPOSITE
instance DA.FromJSON TPM_DIGEST
instance DA.FromJSON TPM_PUBKEY
instance DA.FromJSON TPM_STORE_PUBKEY
instance DA.FromJSON TPM_KEY_PARMS
instance DA.FromJSON TPM_SYMMETRIC_KEY_PARMS
instance DA.FromJSON TPM_RSA_KEY_PARMS
instance DA.FromJSON TPM_KEY_PARMS_DATA
instance DA.FromJSON (SignedData TPM_PUBKEY)
