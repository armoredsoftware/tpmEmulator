module Provisioning where

import TPM
import TPMUtil
import Keys

import System.IO
import System.Directory (doesFileExist)
import Data.Word
import Data.Binary
import Data.ByteString.Lazy (fromStrict)
import System.Process (system)

goldenCompFileName :: String
goldenCompFileName= "goldenPcrComposite.txt"

readGoldenComp :: IO TPM_PCR_COMPOSITE
readGoldenComp = do
  fn <- prependDemoDir $ "appraisal/" ++ goldenCompFileName
  b <- doesFileExist fn
  --putStrLn fn
  case b of
    False -> error $ "***PROVISIONING ERROR***: '" ++ goldenCompFileName ++ "' is missing.  Make sure to provision the TPM (i.e. run 'make provision')."
    True -> do
      either <- decodeFileOrFail goldenCompFileName
      case either of
        Left (_, s) -> do
          putStrLn $ "Error reading/decoding from: " ++  goldenCompFileName ++
            "\n" ++ s
          error "error reading/decoding file"
        Right a -> return a

exportGoldenComp :: TPM_PCR_COMPOSITE -> IO ()
exportGoldenComp comp = do
  encodeFile goldenCompFileName comp
  putStrLn $ "Exported golden TPM_PCR_COMPOSITE to file: "
             ++ goldenCompFileName

exportCurrentComp :: IO ()
exportCurrentComp = do
  currentComp <- getCurrentComp
  exportGoldenComp currentComp

pcrProvision :: IO ()
pcrProvision = do
  {- TODO: do reset, golden hashing into PCRs here -}
  pcrReset
  let fn = "/home/user/stackTopLevel/tpmEmulator/demo/attestation/App1"
  h <- myHash fn
  putStrLn $ "Hash of App1: \n" ++ (show (fromStrict h))
  val <- pcrExtendDemo (fromStrict h)
  putStrLn "Extended into PCR.  New PCR value:"
  putStrLn (show val)
  system fn
  exportCurrentComp

getCurrentComp :: IO TPM_PCR_COMPOSITE
getCurrentComp = do
  let list = [23] :: [Word8]
      pcrSelect = tpm_pcr_selection 24 list
  compGolden <- tpm_pcr_composite tpm pcrSelect
  return compGolden

exportCAKeys :: IO ()
exportCAKeys = do
  (pub, pri) <- generateArmoredKeyPair
  exportPublicKey caPublicKeyFile pub
  putStrLn $ "Exported CA PublicKey to file: "
             ++ caPublicKeyFile
  exportPrivateKey caPrivateKeyFile pri
  putStrLn $ "Exported CA PrivateKey to file: "
             ++ caPrivateKeyFile

--One time functions to provision EK
exportEKFileName = "ekpub.txt"

readEK :: IO TPM_PUBKEY
readEK = do
  either <- decodeFileOrFail exportEKFileName
  case either of
    Left (_, s) -> do putStrLn $ "Error reading/decoding from: " ++  exportEKFileName ++ "\n" ++ s
                      error "error reading/decoding file"
    Right a -> return a

exportEK :: TPM_PUBKEY -> IO ()
exportEK ek = do
  encodeFile exportEKFileName ek
  putStrLn $ "Exported public EK to file: "
             ++ exportEKFileName

ekProvision :: IO ()
ekProvision = do
  ekPub <- takeInit
  exportEK ekPub
