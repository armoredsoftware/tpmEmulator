{-# LANGUAGE TypeSynonymInstances,
FlexibleInstances#-}
module TPM.PCR where
import TPM.Const
import TPM.Driver
import TPM.Types
import TPM.Utils
import TPM.Digest
import Data.Bits
import Data.Binary
import Data.ByteString.Lazy hiding (foldl)
import qualified Data.ByteString.Lazy.Char8 as CHAR
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import Control.Exception
import Control.Monad
import Data.Maybe
import Data.Digest.Pure.SHA (Digest(..),bytestringDigest,sha1)
import Prelude hiding (concat,length,map,replicate,drop,splitAt)
import qualified Prelude as P

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_pcr_selection :: Integer -> [Word8] -> TPM_PCR_SELECTION
tpm_pcr_selection tot pcrs = TPM_PCR_SELECTION bs
    where size = encode ((fromIntegral (P.length pcrs)) :: Word16)
          dat = P.map encode pcrs
          bs  = P.foldl set (replicate (fromIntegral tot') 0) pcrs
          tot' = tot `div` 8
          set c l = let (bi,bt) = divMod l 8
                        bi' = (fromIntegral bi)
                        bv = index c bi'
                    in replace c bi' (setBit bv (fromIntegral bt))
          replace c l v = let (before,after) = splitAt l c
                          in (concat [before,singleton v,drop 1 after])
-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_pcr_unselection :: TPM_PCR_SELECTION -> [Word8]
tpm_pcr_unselection (TPM_PCR_SELECTION sel) = P.map word8 (P.concat finis)
    where bytes = unpack sel
          units = P.map check bytes
          finis = P.map done (P.zip units [0,8..])
          check b = foldl (next b) [] [7,6..0]
          next b a v = if testBit b v then (v:a) else a
          word8 v = ((fromIntegral v) :: Word8)
          done (vals,sh) = P.map (+sh) vals
 
-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_pcr_composite :: TPM tpm => tpm -> TPM_PCR_SELECTION -> IO TPM_PCR_COMPOSITE
tpm_pcr_composite tpm sel = do
    vals <- mapM read selected
    return $ TPM_PCR_COMPOSITE sel vals
    where selected = tpm_pcr_unselection sel
          pcrs = []
          read n = tpm_pcr_read tpm (fromIntegral n)

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_pcr_composite_hash :: TPM_PCR_COMPOSITE -> TPM_DIGEST
tpm_pcr_composite_hash comp = tpm_digest (encode comp)

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_pcr_reset :: (TPM tpm) => tpm -> Integer -> [Word8] -> IO ()
tpm_pcr_reset tpm tot pcrs = do 
    (rtag,size,resl,_) <- tpm_transmit' tpm tag cod (encode dat)
    return ()
    where tag = tpm_tag_rqu_command
          cod = tpm_ord_pcr_reset
          dat = tpm_pcr_selection tot pcrs

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_pcr_read :: (TPM tpm) => tpm -> Word32 -> IO TPM_PCRVALUE
tpm_pcr_read tpm pcr = do 
    (rtag,size,resl,pcr) <- tpm_transmit tpm 20 tag cod ind
    return $ decode pcr
    where tag = tpm_tag_rqu_command
          cod = tpm_ord_pcrread
          ind = encode pcr

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_pcr_extend :: TPM tpm => 
                  tpm ->
                  Word32 ->
                  TPM_DIGEST -> 
                  IO TPM_PCRVALUE
tpm_pcr_extend tpm pcr hash = do 
    (rtag,size,resl,pcr) <- tpm_transmit tpm 20 tag cod dat
    return $ decode pcr
    where tag = tpm_tag_rqu_command
          cod = tpm_ord_extend
          ind = encode pcr
          dat = append ind (encode hash)
          
-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
class PCRExtendable a where
    tpm_pcr_extend_with :: (TPM tpm) =>
                           tpm ->
                           Word32 ->
                           a ->
                           IO TPM_PCRVALUE

instance PCRExtendable ByteString where
    tpm_pcr_extend_with tpm pcr dat = do
        let hash = bytestringDigest $ sha1 dat
        tpm_pcr_extend tpm pcr (decode hash)

instance PCRExtendable String where
    tpm_pcr_extend_with tpm pcr str = tpm_pcr_extend_with tpm pcr dat
        where dat = CHAR.pack str

instance PCRExtendable BS.ByteString where
    tpm_pcr_extend_with tpm pcr dat = tpm_pcr_extend_with tpm pcr dat'
        where dat' = fromChunks [dat]
