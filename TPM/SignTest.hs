module TPM.SignTest where
import TPM.Const
import TPM.Types
import TPM.Utils
import TPM.Nonce
import TPM.PCR
import TPM.Capability
import TPM.Cipher
import TPM.Driver
import Data.Binary
import Data.ByteString.Lazy
import qualified Data.ByteString.Lazy.Char8 as CHAR
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import Control.Exception
import Control.Monad
import Data.Bits
import Data.Digest.Pure.SHA (Digest(..),bytestringDigest,sha1)
import System.Random
import Codec.Crypto.RSA


makeQuoteInfo :: (TPM tpm) => tpm -> IO TPM_QUOTE_INFO
makeQuoteInfo tpm = do max <- tpm_getcap_pcrs tpm
                       nonce <- nonce_create
                       let pcrSelect = tpm_pcr_selection max list
                       comp <- tpm_pcr_composite tpm pcrSelect
                       return $ TPM_QUOTE_INFO (tpm_pcr_composite_hash $ comp) nonce

 where list = [0..23] :: [Word8]


{-getKeyPair :: (PublicKey, PrivateKey)
getKeyPair = let stdGen = mkStdGen 3
                 (pub, pri, _) = generateKeyPair stdGen 2048 in (pub, pri)

getPubKey = fst getKeyPair
getPriKey = snd getKeyPair -}

{-
quoteInfoSig :: TPM_QUOTE_INFO -> ByteString
quoteInfoSig q = let blob = encode q in
  rsassa_pkcs1_v1_5_sign ha_SHA1 getPriKey blob

sigVerify ::
-}
