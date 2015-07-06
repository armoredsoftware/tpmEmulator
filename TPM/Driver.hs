{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE ExistentialQuantification #-}
module TPM.Driver where
import TPM.Const
import TPM.Error
import TPM.Utils
import Data.Word
import Data.ByteString.Lazy
import Data.Typeable
import Data.Binary
import Control.Exception
import Control.Monad
import Data.Maybe
import Prelude hiding (length,drop,splitAt,concat)
import qualified Prelude as P

-------------------------------------------------------------------------------
-- The TPMDriver class is used to collect together types which can be
-- used for interacting with TPM devices. These devices receive
-- transmitted commands and send requested results using C data
-- structures.
--
-- This class uses byte strings to transmit and receive data. Therefore,
-- the equivalent C data structures need to be marshalled into byte strings
-- before the driver transmits them.
-------------------------------------------------------------------------------
class TPM a where
    tpm_driver_transmit :: a -> ByteString -> IO ByteString
    tpm_log :: a -> String -> IO ()
    tpm_logging :: a -> Bool
    tpm_setlogging :: a -> Bool -> a

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_transmit :: TPM tpm =>
                tpm -> 
                Word32 ->
                Word16 ->
                Word32 ->
                ByteString ->
                IO (Word16, Word32, Word32, ByteString)
tpm_transmit tpm esize tag code cmd = do
    (tag,size,result,dat) <- tpm_transmit' tpm tag code cmd
    when (esize /= size) $ do
        throwTPM "TPM ERROR: unexpected result"
    return (tag,size,result,dat)

tpm_transmit' :: TPM tpm =>
                 tpm -> 
                 Word16 ->
                 Word32 ->
                 ByteString ->
                 IO (Word16, Word32, Word32, ByteString)
tpm_transmit' tpm tag code cmd = do
    let cmd' = concat [tag',size',code',cmd]
    tpm_log tpm $ "Sending:  " ++ (blkwrap hdr 60 $ bshex cmd') ++ "\n"
    resp <- tpm_driver_transmit tpm cmd'
    tpm_log tpm $ "Received: " ++ (blkwrap hdr 60 $ bshex resp) ++ "\n"
    let (tag,rest1) = splitAt 2 resp
    let (size,rest2) = splitAt 4 rest1
    let (result,rest3) = splitAt 4 rest2
    let tag' = (decode tag) :: Word16
    let size' = (decode size) :: Word32
    let result' = (decode result) :: Word32
    when (tag' /= tpm_tag_rsp_command && 
          tag' /= tpm_tag_rsp_auth1_command &&
          tag' /= tpm_tag_rsp_auth2_command) $ do
        throwTPM "TPM ERROR: unexpected tag"
    when (result' /= tpm_success) $ do
        throwTPMCode result'
    return (tag',size' - 10,result',rest3)
    where size :: Word32
          size = fromIntegral $ (length tag')+(length code')+(length cmd)+4
          tag' = encode tag
          code' = encode code
          size' = encode size
          hdr   = "          "
