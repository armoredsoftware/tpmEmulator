{-# LANGUAGE DeriveDataTypeable #-}
module TPM.Driver.Socket (
    TPMSocket(..), tpm_socket, tpm_logging_socket
) where
import TPM.Driver
import Network.Socket hiding (send, sendTo, recv, recvFrom)
import Network.Socket.ByteString.Lazy
import Data.ByteString.Lazy
import Data.Binary
import Prelude hiding (length,drop,splitAt,concat)
import qualified Prelude as P
import Control.Exception (bracket)
import Data.Typeable

-------------------------------------------------------------------------------
-- The data structure used by the socket based TPM driver. The socket is
-- opened and closed on each command so we just store the file path to
-- the socket instead of the socket connection itself.
-------------------------------------------------------------------------------
data TPMSocket = TPMSocket { path :: String 
                           , log  :: Bool
                           } deriving (Typeable)

-------------------------------------------------------------------------------
-- An instance of the TPMDriver class for the socket based TPM driver.
-------------------------------------------------------------------------------
instance TPM TPMSocket where
      tpm_driver_transmit (TPMSocket file _) dat = tpm_socket_transmit file dat
      tpm_setlogging (TPMSocket f _) l = TPMSocket f l
      tpm_logging (TPMSocket _ l) = l
      tpm_log (TPMSocket _ True) m = P.putStr m
      tpm_log (TPMSocket _ False) _ = return ()

-------------------------------------------------------------------------------
-- Create a socket based TPM driver. This driver is used to communicate
-- with a TPM which receives commands using a UNIX socket such as the
-- TPM emulator: http://tpm-emulator.berlios.de
-------------------------------------------------------------------------------
tpm_socket :: FilePath -> TPMSocket
tpm_socket f = TPMSocket f False

tpm_logging_socket :: FilePath -> TPMSocket
tpm_logging_socket f = TPMSocket f True

-------------------------------------------------------------------------------
-- Open a sock connection using the given file system path as the
-- location of the UNIX socket.
-------------------------------------------------------------------------------
tpm_socket_open tpm = do
    sock <- socket AF_UNIX Stream 0
    connect sock (SockAddrUnix tpm)
    return sock

-------------------------------------------------------------------------------
-- Close an open UNIX socket connection.
-------------------------------------------------------------------------------
tpm_socket_close sock = sClose sock

-------------------------------------------------------------------------------
-- Send all of the data in a bytestring using the socket. If all of the
-- data cannot be sent at once then we continue trying to send the rest
-- of the data using another socket send.
-------------------------------------------------------------------------------
tpm_socket_send sock cmd = do
    len <- send sock cmd
    case len < (length cmd) of
        True -> tpm_socket_send sock (drop len cmd)
        False -> return ()

-------------------------------------------------------------------------------
-- Read the given number of bytes from the UNIX socket. If all of the
-- data is not immediately available then continue reading from the
-- socket until we have received all of the data.
-------------------------------------------------------------------------------
tpm_socket_recv sock bytes = do
    bs <- recv sock bytes
    case (bytes - (length bs)) of
        0 -> return bs
        x | x > 0 -> tpm_socket_recv sock x >>= return . (append bs)

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_socket_transmit tpm dat = do
    bracket (tpm_socket_open tpm)
            tpm_socket_close
            dotrans
    where dotrans s = do tpm_socket_send s dat
                         header <- tpm_socket_recv s 6
                         let (tag,size) = splitAt 2 header
                         let size' = (decode size) :: Word32
                         body <- tpm_socket_recv s (fromIntegral $ size' - 6)
                         return (append header body)
