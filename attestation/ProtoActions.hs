{-# LANGUAGE ScopedTypeVariables #-}
module ProtoActions where

import ArmoredTypes
--import CommTools(sendG', receiveG')
import ProtoMonad
import VChanUtil hiding (send, receive)
import TPM.Types

import Data.ByteString.Lazy hiding (pack, map, putStrLn)
import Data.Monoid
import Data.Binary
import qualified Codec.Crypto.RSA as C
import Crypto.Cipher.AES
import Crypto.Random
import System.Random
import Control.Monad.IO.Class
import Control.Monad.Error
import System.Environment
import System.IO
import Control.Applicative hiding (empty)

import AbstractedCommunication
import Data.Aeson (Result (..) )


send :: EntityId -> Message -> Proto ()
send toId ds = do
  chan <- getEntityChannel toId
  --liftIO $ send' chan ds
  liftIO $ AbstractedCommunication.send chan ds
  --liftIO $ putStrLn $ "Sent message! " ++ (show ds)
  return ()

send' :: LibXenVChan -> Message -> IO ()
send' chan ds = do
  logger <- createLogger
  sendChunkedMessageByteString logger chan (toStrict $ encode ds)
  putStrLn $ "Sending: " ++ (show ds)
  putStrLn $ "Sent message! " ++ (show ds)
  return ()

receive :: EntityId -> Proto Message
receive fromId = do
 -- liftIO $ putStrLn $ "In receive"
  chan <- getEntityChannel fromId
  --result <- liftIO $ receive' chan
  resultR <- liftIO $ (AbstractedCommunication.receive chan :: IO (Result Message))
  --TODO fix error
  case resultR of
    Error err -> error err
    Success result -> return result

receive' :: LibXenVChan -> IO Message
receive' chan = do
  putStrLn $ "In receive"
  ctrlWait chan
  logger <- createLogger
  bytes <- readChunkedMessageByteString logger chan
 -- liftIO $ putStrLn $ "Got bytes"
  let result = decode $ fromStrict bytes
  putStrLn $ "Received message!"   -- ++ (show result)
  return $ result



debugPrintP :: String -> Proto ()
debugPrintP s = liftIO $ debugPrint s
