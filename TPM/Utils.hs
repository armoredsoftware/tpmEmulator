{-# LANGUAGE DeriveDataTypeable #-}
module TPM.Utils where
import Data.Bits
import Data.Char(ord)
import Data.Binary
import Data.Typeable
import Control.Exception
import qualified Data.ByteString.Lazy as BS
import Data.List (intersperse)
import TPM.Error
import Data.Word
import Network.Socket hiding (send, sendTo, recv, recvFrom)
import Network.Socket.ByteString.Lazy

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
data TPMException = TPMException String
                  | TPMCode Word32
                    deriving (Typeable)

instance Show TPMException where
    show (TPMException str) = str
    show (TPMCode code) = "TPM ERROR: " ++ mkerr code

instance Exception TPMException

tpmerror str = TPMException str
tpmerrcode code = TPMCode code
throwTPM str = throwIO $ tpmerror str
throwTPMCode code = throwIO $ tpmerrcode code

-------------------------------------------------------------------------------
-- Convert a number into the appropriate hexadecimal character.
-------------------------------------------------------------------------------
tohex :: (Num a, Eq a) => a -> Char
tohex 0  = '0'
tohex 1  = '1'
tohex 2  = '2'
tohex 3  = '3'
tohex 4  = '4'
tohex 5  = '5'
tohex 6  = '6'
tohex 7  = '7'
tohex 8  = '8'
tohex 9  = '9'
tohex 10 = 'A'
tohex 11 = 'B'
tohex 12 = 'C'
tohex 13 = 'D'
tohex 14 = 'E'
tohex 15 = 'F'


fourCharsToWord32 :: String -> Word32
fourCharsToWord32 s = final
   where char1 = ord $ head s
         char2 = ord $ head(tail s)
         char3 = ord $ head(tail(tail s))
         char4 = ord $ head(tail(tail(tail s)))

         list :: [Word32]
         list = map f [char1, char2, char3, char4]

         f :: Int -> Word32
         f x = (fromIntegral x) :: Word32

         q = rotateL (head list) 24
         u = rotateL (head (tail list)) 16
         o = rotateL (head (tail (tail list))) 8
         t = (head (tail (tail (tail list))))

         zeros :: Word32
         zeros = zeroBits
         final = foldr (.|.) zeros [q,u,o,t]



-------------------------------------------------------------------------------
-- Convert a bit value into a hexadecimal string.
-------------------------------------------------------------------------------
mkhex :: (Bits a, Num a) => a -> String
mkhex num = reverse $ map (mkhex' num) shifts
    where (Just numbits) = bitSizeMaybe (num-1)
          shifts = [0,-4 .. -numbits]
          mkhex' num sh = tohex ((shift num (fromIntegral sh)) .&. 0xF)

-------------------------------------------------------------------------------
-- Convert a byte string into a hexadecimal string.
-------------------------------------------------------------------------------
bshex :: BS.ByteString -> String
bshex bs | BS.length bs == 0 = "none"
bshex bs = concat $  intersperse " " (map mkhex (BS.unpack bs))

-------------------------------------------------------------------------------
-- Convert a byte strings into integers
-------------------------------------------------------------------------------
wl2int :: [Word8] -> Integer
wl2int l = foldr unstep 0 (reverse l)
  where unstep b a = a `shiftL` 8 .|. fromIntegral b

bs2int :: BS.ByteString -> Integer
bs2int bs = wl2int (BS.unpack bs)

-------------------------------------------------------------------------------
-- Wrap a long string into evenly sized blocks.
-------------------------------------------------------------------------------
blkwrap _ _ ""  = ""
blkwrap hdr len val = nxt ++ end
    where (nxt,rst) = splitAt len val
          end = if rst == [] then "" else "\n" ++ hdr ++ blkwrap hdr len rst
