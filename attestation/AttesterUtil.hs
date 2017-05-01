module AttesterUtil where

import Data.Binary
import Data.ByteString.Lazy hiding (pack, map, putStrLn)
import Crypto.Cipher.AES
import qualified Codec.Crypto.RSA as C


import TPM
import TPMUtil

type Nonce = Int
type SymmKey = TPM_SYMMETRIC_KEY
type CipherText = ByteString;
type PrivateKey = C.PrivateKey --ByteString;
type PublicKey = C.PublicKey --ByteString;
type Signature = ByteString;
data SignedData a = SignedData {
  dat :: a,
  sig :: Signature
} deriving (Eq, Show)
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

realSign :: PrivateKey -> ByteString -> Signature --paramaterize over hash?
realSign priKey bytes = C.rsassa_pkcs1_v1_5_sign C.hashSHA1 priKey bytes --Concrete implementation plugs in here

realVerify :: PublicKey -> ByteString -> Signature -> Bool
realVerify pubKey m s = C.rsassa_pkcs1_v1_5_verify C.hashSHA1 pubKey m s

--Concrete packing(well-defined strategy for combining elements in preparation for encryption/signing) implementation
packImpl :: (Binary a) => [a] -> ByteString
packImpl as = encode as --mconcat bslist
 --where bslist = map tobs as

--Concrete unpacking implementation
unpackImpl :: Binary a => ByteString -> [a]
unpackImpl bs = decode bs
