{-# LANGUAGE ScopedTypeVariables #-}

module CAProtoMain where

import ArmoredTypes
import ProtoMonad
import ProtoActions
import Keys
import Provisioning
import TPM
import TPMUtil
import VChanUtil hiding (send, receive)
import CommTools(getMyIPString)
import MeasurerComm (debugSession,measureSession)
import Measurements 
import ArmoredConfig.Environment (getCaDomId, getPort, getPid)

import System.IO
import System.Random
import Control.Monad.IO.Class
import Data.Binary
import Data.Digest.Pure.SHA (bytestringDigest, sha1)
import Crypto.Cipher.AES
import Codec.Crypto.RSA hiding (sign, verify, PublicKey, PrivateKey, encrypt, decrypt)

import Control.Applicative hiding (empty)
import Data.ByteString.Lazy hiding (replicate, putStrLn)
import Control.Concurrent (threadDelay)
import Data.Text as Text hiding (replicate)
import Data.Aeson ((.:),(.:?),FromJSON(..),decodeStrict, encode, Value(..), fromJSON, Result(..))
import qualified Control.Monad.Remote.JSON as Jsonrpc
import Control.Monad.Remote.JSON hiding (send)
import Control.Monad.Remote.JSON.Debug (traceSessionAPI)
import Control.Monad.Remote.JSON.Types (SessionAPI(..))
import Network.Socket hiding (send)

import AbstractedCommunication hiding (send, receive)

measSession :: Socket -> Jsonrpc.Session
measSession socket = debugSession socket

getMeasurement1 :: String -> String -> String -> Proto Measurement
getMeasurement1 host port pidString = do

  --sock <- getSocket host {-"10.100.0.249"-} port
  sock <- getMeaSocket
  liftIO $ do
  a <- Jsonrpc.send (measSession sock) $ do
                       set_target_app pidString
                       hook_app_variable "test1.c" 12 False 1 "c"

  print a
  threadDelay 6000000
  t<- Jsonrpc.send (measSession sock) $ do
    m <- load_store 1
    return m
      --b <- method "eval" (List [String "(load 1)"])
      --notification "eval" (List [String "(quit)"])
      --return b
      --close sock
      --case fromJSON t of
      --   Success (m :: Measurement) -> return (m, sock)
      --   Error s ->  error s
  return t

getMeasurement2 :: String -> String -> String -> Proto (Measurement,Measurement)
getMeasurement2 host port pidString = do

  sock <- getMeaSocket
  liftIO $ do

  Jsonrpc.send (measSession sock) $ do
       set_target_app pidString

  t<- Jsonrpc.send (measSession sock) $ do
    b <- measure_variable "password"
    --notification "eval" (List [String "(quit)"])
    return b

  q<- Jsonrpc.send (measSession sock) $ do
    b <- measure_variable "session"
    return b

  putStrLn $ "ATTESTER MEASUREMENTS:\n\n\n" ++ (show t) ++ "\n\n" ++ (show q) ++ "\n\n\n"
  return (t, q)


getTest1cVarValue :: Proto Int
getTest1cVarValue = do
  host <- liftIO $ getMyIPString
  port <- liftIO $ getPort
  pid <- liftIO $ getPid
  m <- getMeasurement1 host port pid
  let text = topMeasurement m
      s = Text.unpack text
      i = read s
  return i

getTestBufferValues :: Proto (String, Int)
getTestBufferValues = do
  host <- liftIO $ getMyIPString
  port <- liftIO $ getPort
  pid <- liftIO $ getPid
  (password, session) <- getMeasurement2 host port pid
  let pText = topMeasurement password
      pString = {-read $ -} Text.unpack pText
      sText = topMeasurement session
      sString = Text.unpack sText
      sInt = read sString

  liftIO $ putStrLn $"END OF getTestBufferValues!!!\n"  ++ "Decoded evidence:  \n" ++ "pString:  " ++ pString ++ "\n\nsInt: " ++ (show sInt) ++ "\n\n"
  return (pString, sInt)





{-getMeasurement2 :: String -> String -> String -> Proto (Measurement,Measurement)
getMeasurement2 host port pidString = do

  --sock <- getSocket host {-"10.100.0.249"-} port
  sock <- getMeaSocket
  liftIO $ do

  a <- Jsonrpc.send (measSession sock) $ do
       set_target_app pidString
       hook_app_variable "buffer_overflow2.c" 37 False 1 "password"

  --print a
  --threadDelay 2000000

  b <- Jsonrpc.send (measSession sock) $ do
    hook_app_variable "buffer_overflow2.c" 38 False 2 "session"

  --threadDelay 8000000

  t<- Jsonrpc.send (measSession sock) $ do
    b <- load_store 1
    --notification "eval" (List [String "(quit)"])
    return b

  q<- Jsonrpc.send (measSession sock) $ do
    b <- load_store 2
         --notification "eval" (List [String "(quit)"])
    return b
  --close sock
  {-case fromJSON t of
    Success (m1 :: Measurement) ->
      case fromJSON q of
        Success (m2 :: Measurement) -> do
          putStrLn $ "ATTESTER MEASUREMENTS:\n\n\n" ++ (show m1) ++ "\n\n" ++ (show m2) ++ "\n\n\n"
          return (m1, m2)
        Error s ->  error s
    Error s ->  error s -}
  putStrLn $ "ATTESTER MEASUREMENTS:\n\n\n" ++ (show t) ++ "\n\n" ++ (show q) ++ "\n\n\n"
  return (t, q)
-}
