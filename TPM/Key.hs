module TPM.Key where
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
import Control.Exception
import Control.Monad
import Data.Maybe
import Data.Bits
import Data.Digest.Pure.SHA (Digest(..),bytestringDigest,sha1)
-- import Prelude hiding (concat,length,map,splitAt)
import Prelude (IO(..),($),(==),error)
import qualified Prelude as P

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_key_pubexp (TPM_PUBKEY k _) = pubexp k
    where pubexp (TPM_KEY_PARMS _ _ _ d) = pubexp' d
          deflt = encode (65537 :: Word32)
          pubexp' NO_DATA = deflt
          pubexp' (RSA_DATA rsa) = pubrsa rsa
          pubexp' (AES_DATA aes) = pubaes aes
          pubrsa (TPM_RSA_KEY_PARMS _ _ exp) | length exp == 0 = deflt
          pubrsa (TPM_RSA_KEY_PARMS _ _ exp) = exp
          pubaes (TPM_SYMMETRIC_KEY_PARMS _ _ exp) | length exp == 0 = deflt
          pubaes (TPM_SYMMETRIC_KEY_PARMS _ _ exp) = exp

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_key_pubmod (TPM_PUBKEY _ m) = pubmod m
    where pubmod (TPM_STORE_PUBKEY d) = d

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_key_pubsize (TPM_PUBKEY k _) = pubsize k
    where pubsize (TPM_KEY_PARMS _ _ _ d) = pubsize' d
          pubsize' NO_DATA = 0
          pubsize' (RSA_DATA rsa) = pubrsa rsa
          pubsize' (AES_DATA aes) = pubaes aes
          pubrsa (TPM_RSA_KEY_PARMS l _ _) = l
          pubaes (TPM_SYMMETRIC_KEY_PARMS l _ _) = l

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_key_pubek :: (TPM tpm) => tpm -> IO (TPM_PUBKEY,TPM_DIGEST)
tpm_key_pubek tpm = do
    nonce <- nonce_create
    (rtag,size,resl,dat) <- tpm_transmit' tpm tag cod (encode nonce)
    return $ decode dat
    where tag = tpm_tag_rqu_command
          cod = tpm_ord_readpubek

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
{-
tpm_key_createwrap :: (TPM tpm) => 
                      tpm ->
                      Session ->
                      TPM_KEY_HANDLE ->
                      Maybe TPM_DIGEST ->
                      Maybe TPM_DIGEST ->
                      Maybe TPM_DIGEST ->
                      IO (TPM_KEY_HANDLE,TPM_NONCE)
tpm_key_createwrap tpm (OSAP sa oo en eo sk) pk pa na ma = do 
    (rtag,size,resl,dat) <- tpm_transmit tpm 24 tag cod dat
    return $ decode dat
    where tag = tpm_tag_rqu_auth1_command
          cod = tpm_ord_createwrapkey
          dat = concat [encode pk,pa',ma',key,sa,en',oo',ign,ath]
          en' = encode en
          oo' = encode oo
          pa' = tpm_auth_info pa
          na' = tpm_encauth_info sk en na
          ma' = tpm_encauth_info sk oo ma
          key = replicate 20 0
          ath = replicate 20 0
          ign = replicate 1 0
tpm_key_create_wrap _ _ _ _ _ _ = throwTPM msg
    where msg = "tpm_create_wrap requires an OSAP session"
-}

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_key_create :: TPM_AUTH_DATA_USAGE -> TPM_KEY
tpm_key_create auth = TPM_KEY tpm_key_storage 0 auth kprm empty spub empty
    where spub = TPM_STORE_PUBKEY empty
          kprm = TPM_KEY_PARMS tpm_alg_rsa
                               tpm_es_rsaesoaep_sha1_mgf1
                               tpm_ss_none
                               (RSA_DATA rsad)
          rsad = TPM_RSA_KEY_PARMS 2048 2 empty

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_key_create_signing :: TPM_AUTH_DATA_USAGE {-TPM_STORE_PUBKEY-} -> TPM_KEY
tpm_key_create_signing auth = TPM_KEY tpm_key_signing 0 auth kprm empty
                                      spub empty
    where spub = TPM_STORE_PUBKEY empty --sbub
          kprm = TPM_KEY_PARMS tpm_alg_rsa
                               tpm_es_none
                               tpm_ss_rsassapkcs1v15_sha1
                               (RSA_DATA rsad)
          rsad = TPM_RSA_KEY_PARMS 2048 2 empty -- (encode (65537 :: Word32))
-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_key_create_identity :: TPM_AUTH_DATA_USAGE -> TPM_KEY
tpm_key_create_identity auth = TPM_KEY tpm_key_identity 0 auth kprm empty
                                       spub empty
    where spub = TPM_STORE_PUBKEY empty
          kprm = TPM_KEY_PARMS tpm_alg_rsa
                               tpm_es_none
                               tpm_ss_rsassapkcs1v15_sha1
                               (RSA_DATA rsad)
          rsad = TPM_RSA_KEY_PARMS 2048 2 empty 
-------------------------------------------------------------------------------
-- Create a key which is suitable for use with the TPM_TakeOwnership
-- command. This kind of key does not actually contain any key data. It
-- only contains information about the desired key parameters.
-------------------------------------------------------------------------------
tpm_key_createowner :: TPM_AUTH_DATA_USAGE -> TPM_KEY
tpm_key_createowner auth = TPM_KEY tpm_key_storage 0 auth kprm empty spub empty
    where spub = TPM_STORE_PUBKEY empty
          kprm = TPM_KEY_PARMS tpm_alg_rsa
                               tpm_es_rsaesoaep_sha1_mgf1
                               tpm_ss_none
                               (RSA_DATA rprm)
          rprm = TPM_RSA_KEY_PARMS 2048 2 empty 

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_auth_info Nothing = replicate 20 0
tpm_auth_info (Just s) = encode s
