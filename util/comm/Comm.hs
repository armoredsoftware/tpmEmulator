-- This module was adapted from the examples found on the network.socket documentation page on hackage.haskell.org
-- Michael Neises

module Comm where

import Control.Concurrent (forkFinally)
import qualified Control.Exception as E
import Control.Monad (unless, forever, void)
import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as C
import Network.Socket hiding (recv)
import Network.Socket.ByteString (recv, sendAll)

portListen :: IO ()
portListen = withSocketsDo $ do
    addr <- resolve "3000"
    E.bracket (open addr) close loop
  where
    resolve port = do
        let hints = defaultHints {
                addrFlags = [AI_PASSIVE]
              , addrSocketType = Stream
              }
        addr:_ <- getAddrInfo (Just hints) Nothing (Just port)
        return addr
    open addr = do
        sock <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
        setSocketOption sock ReuseAddr 1
        bind sock (addrAddress addr)
        listen sock 10
        return sock
    loop sock = do
        (conn, peer) <- accept sock
        putStrLn $ "Connection from " ++ show peer
        void $ forkFinally (talk conn) (\_ -> do close conn)
    talk conn = do
        msg <- recv conn 1024
	putStrLn $ "Msg received: " ++ (C.unpack msg)
        S.writeFile "/home/adam/tpmEmulator/demo/attestation/temp.txt" msg
	return ()
	{-
        unless (S.null msg) $ do
          sendAll conn msg
          talk conn
	  -}

portSend :: String -> S.ByteString -> IO ()
portSend myIP myMsg = withSocketsDo $ do
    addr <- resolve myIP "3000"
    E.bracket (open addr) close talk
  where
    resolve host port = do
        let hints = defaultHints { addrSocketType = Stream }
        addr:_ <- getAddrInfo (Just hints) (Just host) (Just port)
        return addr
    open addr = do
        sock <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
        connect sock $ addrAddress addr
        return sock
    talk sock = do
        myInt <- send sock $ C.unpack myMsg
        putStrLn $ "portSend, sent (" ++ (show myInt) ++ " bytes): "
                 ++ (C.unpack myMsg)

        {-msg <- recv sock 1024
        putStr "Received: "
        C.putStrLn msg
        -}


{-
import Codec.Crypto.RSA
import Crypto.Random
import System.Random
import System.IO
import Data.Binary

--import TPM


caPublicKeyFile :: FilePath
caPublicKeyFile = "caPublicKey.txt"

caPrivateKeyFile :: FilePath
caPrivateKeyFile = "caPrivateKey.txt"

getCAPrivateKey :: IO PrivateKey
getCAPrivateKey = do
  readPrivateKey caPrivateKeyFile

getCAPublicKey :: IO PublicKey
getCAPublicKey = do
  readPublicKey caPublicKeyFile

generateArmoredKeyPair :: IO (Codec.Crypto.RSA.PublicKey,
                              Codec.Crypto.RSA.PrivateKey)
generateArmoredKeyPair = do
  gen::SystemRandom <- newGenIO
  let (pub, pri, _) = generateKeyPair gen 2048
  return (pub, pri)

exportPublicKey :: FilePath -> PublicKey -> IO ()
exportPublicKey fileName pubKey = do
  encodeFile fileName pubKey

exportPrivateKey :: FilePath -> PrivateKey -> IO ()
exportPrivateKey fileName priKey = do
  encodeFile fileName priKey

readPublicKey :: FilePath -> IO PublicKey
readPublicKey fileName = do
  either <- decodeFileOrFail fileName
  case either of
    Left (_, s) -> do putStrLn $ "Error reading/decoding from: " ++  fileName ++ "\n" ++ s
                      error "error reading/decoding file"
    Right a -> return a

readPrivateKey :: FilePath -> IO PrivateKey
readPrivateKey fileName = do
  either <- decodeFileOrFail fileName
  case either of
    Left (_, s) -> do putStrLn $ "Error reading/decoding from: " ++  fileName ++ "\n" ++ s
                      error "error reading/decoding file"
    Right a -> return a
-}
