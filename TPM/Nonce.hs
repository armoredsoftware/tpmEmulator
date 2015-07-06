module TPM.Nonce where
import TPM.Types
import Data.ByteString.Lazy
import qualified OpenSSL.Random as SSL

-------------------------------------------------------------------------------
-- Create a new nonce value by using cryptographically
-------------------------------------------------------------------------------
nonce_create :: IO TPM_NONCE
nonce_create = SSL.randBytes 20 >>= return . TPM_NONCE . (\c->fromChunks [c])
