{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ScopedTypeVariables #-}
module TPM.Cipher where
import TPM.Key
import TPM.Const
import TPM.Driver
import TPM.Types
import TPM.Utils
import TPM.Nonce
import Data.Binary
import Data.ByteString.Lazy
import qualified Data.ByteString.Lazy.Char8 as CHAR
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import Codec.Crypto.RSA hiding (sign, verify)
import Crypto.Random
import Control.Exception
import Control.Monad
import Data.Maybe
import Data.Bits
import Data.Digest.Pure.SHA (Digest(..),bytestringDigest,sha1)
import Prelude (IO(..),($),(==),error, Either(Left), Either(Right), undefined)
import qualified Prelude as P

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
class TPMEncryptable a where
    tobs :: a -> ByteString
    frombs :: ByteString -> a

instance TPMEncryptable P.String where
    tobs s = CHAR.pack s
    frombs s = CHAR.unpack s

instance TPMEncryptable ByteString where
    tobs s = s
    frombs s = s

instance TPMEncryptable (Maybe TPM_DIGEST) where
    tobs Nothing = replicate 20 0
    tobs (Just (TPM_DIGEST s)) = s
    frombs s = Just (TPM_DIGEST s)

instance TPMEncryptable TPM_DIGEST where
    tobs (TPM_DIGEST bs) = bs
    frombs bs = TPM_DIGEST bs

{-class Binary a => Signable a where
  sign :: a -> PrivateKey -> ByteString
  verify :: a -> PublicKey -> ByteString -> P.Bool
-}



--instance Signable TPM_PUBKEY


{-
instance TPMEncryptable TPM_ASYM_CA_CONTENTS where
  tobs a@(TPM_ASYM_CA_CONTENTS sym dig) = encode a
  frombs bs = ((decode bs)::TPM_ASYM_CA_CONTENTS)
-}


tpm_rsa_pubencrypt :: TPMEncryptable enc => TPM_PUBKEY -> enc -> IO enc
tpm_rsa_pubencrypt key dat = do
    let  size = (tpm_key_pubsize key) `P.div` 8
         expn = bs2int $ tpm_key_pubexp key
         modl = bs2int $ tpm_key_pubmod key
         rsa  = PublicKey (P.fromIntegral size) modl expn
         hf   = hashFunction hashSHA1
         mgf  = generateMGF1 hf
         labl = CHAR.pack "TCPA"
         --eitherg = newGen BS.empty
    g::SystemRandom <- newGenIO
         {-g = case eitherg of
           Left error -> undefined
           Right gen -> gen -}
    let ecbs = rsaes_oaep_encrypt g hf mgf rsa {-0-} labl (tobs dat)
    return $ frombs (P.fst ecbs)


tpm_get_rsa_PublicKey :: TPM_PUBKEY -> PublicKey
tpm_get_rsa_PublicKey key = PublicKey size modl expn
  where size = P.fromIntegral $ (tpm_key_pubsize key) `P.div` 8
        expn = bs2int $ tpm_key_pubexp key
        modl = bs2int $ tpm_key_pubmod key
