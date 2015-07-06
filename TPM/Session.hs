module TPM.Session where
import TPM.Const
import TPM.Driver
import TPM.Types
import TPM.Nonce
import TPM.Utils
import TPM.Digest
import Data.Word
import Data.Binary
import Data.ByteString.Lazy hiding (putStrLn)
import Data.Digest.Pure.SHA (hmacSha1,bytestringDigest)
import Prelude hiding (concat,length,map,splitAt,replicate)
import qualified Prelude as P

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_session_oiap :: TPM tpm => tpm -> IO Session
tpm_session_oiap tpm = do 
    (rtag,size,resl,dat) <- tpm_transmit tpm 24 tag cod empty
    let (handle,dat') = splitAt 4 dat
    return $ OIAP handle (decode dat')
    where tag = tpm_tag_rqu_command
          cod = tpm_ord_oiap

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_session_osap :: TPM tpm => 
                    tpm -> 
                    TPM_DIGEST ->
                    Word16 ->
                    Word32 ->
                    IO Session
tpm_session_osap tpm key etype eval = do 
    oosap <- nonce_create
    let dat = concat [encode etype, encode eval, encode oosap]
    (rtag,size,resl,dat) <- tpm_transmit tpm 44 tag cod dat
    let (handle,dat') = splitAt 4 dat
    let (enonce,eosap) = splitAt 20 dat'
    let secret = tpm_raw_hmac key (concat [eosap,encode oosap])
    return $ OSAP handle oosap (decode enonce) (decode eosap) secret
    where tag = tpm_tag_rqu_command
          cod = tpm_ord_osap

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_session_close :: TPM tpm => tpm -> Session -> IO ()
tpm_session_close tpm session = do
    let auth = case session of
                OIAP a _ -> a
                OSAP a _ _ _ _ -> a
    tpm_transmit' tpm tag cod auth
    return ()
    where tag = tpm_tag_rqu_command
          cod = tpm_ord_terminate_handle

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_session_auth Nothing = TPM_DIGEST $ replicate 20 0
tpm_session_auth (Just h) = h

