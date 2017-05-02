module AttesterUtil where

import Data.Binary
import Data.ByteString.Lazy hiding (map, putStrLn)
import Crypto.Cipher.AES
import qualified Codec.Crypto.RSA as C
import Data.Digest.Pure.SHA (bytestringDigest, sha1)


import TPM
import TPMUtil
import Keys
import Provisioning





{-
caAtt_CA :: AikContents -> Proto (CipherText, CipherText)
caAtt_CA signedContents = do
  caDomId <- liftIO $ getCaDomId
  attChan <- liftIO $ client_init caDomId {-4-}
  let caEntityId :: EntityId
      caEntityId = 2
  myInfo <- getEntityInfo 0
  let val = SignedData
            (ATPM_IDENTITY_CONTENTS  (dat signedContents))
            (sig signedContents)
  liftIO $ send' attChan [AEntityInfo myInfo, ASignedData val]
  [ACipherText ekEncBlob, ACipherText kEncBlob] <- liftIO $ receive' attChan

  --attChan <- getEntityChannel caEntityId
  liftIO $ VChanUtil.close attChan
  --liftIO $ killChannel attChan
  return (ekEncBlob, kEncBlob)
-}




  
caEntity_Att :: {-EvidenceDescriptor -> -} Nonce -> TPM_PCR_SELECTION ->
                IO ({-Evidence, -}Nonce, TPM_PCR_COMPOSITE,
                       (SignedData TPM_PUBKEY), Signature)
caEntity_Att {-dList-} nApp pcrSelect = do
  pcrReset
  pcrModify "a"

  (iKeyHandle, aikContents) <- tpmMk_Id
  (ekEncBlob, kEncBlob) <- caEntity_CA aikContents
  sessKey <- tpmAct_Id iKeyHandle ekEncBlob
  let caCert :: (SignedData TPM_PUBKEY)
      caCert = realDecrypt sessKey kEncBlob

      quoteExData = []
  (pcrComp, qSig) <- tpmQuote iKeyHandle pcrSelect quoteExData
  let response = ({-evidence, -}nApp, pcrComp, caCert, qSig)

  return response




      --liftIO $ sequence $ [logf, putStrLn] <*> (pure ( "Sending Request to Measurer"))
   --evidence <- caAtt_Mea dList

      --liftIO $ sequence $ [logf, putStrLn] <*> (pure ( "Received response from Measurer: " ++ (show evidence)))

      {-let quoteExData =
            [AEvidence evidence,
             ANonce nApp,
             ASignedData $ SignedData (ATPM_PUBKEY (dat caCert)) (sig caCert)]
       -}
      {-
      let response =
            [(quoteExData !! 0),
             reqNonce,
             ATPM_PCR_COMPOSITE pcrComp,
             (quoteExData !! 2),
             ASignature qSig]
      -}

  
      --liftIO $ putStrLn $ "Sending response to Appraiser: \n\n" ++ (show response) ++ "\n\n"
      --send appraiserEntityId response




















   {- 2 -> do
      [reqNonce@(ANonce nApp),
       ATPM_PCR_SELECTION pcrSelect] <- receive appraiserEntityId

      (iKeyHandle, aikContents) <- tpmMk_Id
      (ekEncBlob, kEncBlob) <- caAtt_CA aikContents

      sessKey <- tpmAct_Id iKeyHandle ekEncBlob

      let caCert :: (SignedData TPM_PUBKEY)
          caCert = realDecrypt sessKey kEncBlob

      --evidence <- caAtt_Mea dList

      evidence <- return []
      let quoteExData =
            [AEvidence evidence, ANonce nApp,
             ASignedData $ SignedData (ATPM_PUBKEY (dat caCert)) (sig caCert)]
      (pcrComp, qSig) <- tpmQuote iKeyHandle pcrSelect quoteExData

      let response =
            [reqNonce,
             ATPM_PCR_COMPOSITE pcrComp,
             (quoteExData !! 2),
             ASignature qSig]
      send appraiserEntityId response
      return ()


--    _ -> error "Protocol id not yet implemented!"









{-

{-(s, i) <- getTestBufferValues
      return [M0 i, M1 s] -}
caAtt_Mea :: EvidenceDescriptor -> Proto Evidence
caAtt_Mea ed = do
  pId <- protoIs
  case pId of
    1 -> do
      cVarValue <- getTest1cVarValue
      return $ [M0 cVarValue]
    2 -> do
      (s, i) <- getTestBufferValues
      return [M0 i, M1 s]
      --x -> error $ "Evidence Descriptor" ++ (show x) ++ "not supported yet"

caEntity_App :: EvidenceDescriptor -> Nonce -> TPM_PCR_SELECTION ->
                Proto (Evidence, Nonce, TPM_PCR_COMPOSITE,
                       (SignedData TPM_PUBKEY), Signature)
caEntity_App d nonceA pcrSelect = do
 -- let nonceA = 34
  pId <- protoIs
  liftIO $ sequence $ [logf, putStrLn] <*> (pure ( "Got here......."))
  let request = case pId of
        _ -> [AAEvidenceDescriptor d, ANonce nonceA, ATPM_PCR_SELECTION pcrSelect]
        {-2 -> [ANonce nonceA, ATPM_PCR_SELECTION pcrSelect]

        _ -> error "Protocol id not yet implemented!"
             --return []-}

  send 1 request
  --liftIO $ logf "Sent Request \n"
  --liftIO $ threadDelay 5000000
  --liftIO $ logf "Appraiser receiving \n"
  case pId of
        _ -> do
          response@[AEvidence e, ANonce nA, ATPM_PCR_COMPOSITE pComp,
           ASignedData (SignedData (ATPM_PUBKEY aikPub) aikSig),
           ASignature sig] <- receive 1
          --liftIO $ logf $ "Appraiser received: \n" ++ (show response) ++ "\n\n"
          return (e, nA, pComp, SignedData aikPub aikSig, sig)

        {-2 -> do
          [ANonce nA, ATPM_PCR_COMPOSITE pComp,
           ASignedData (SignedData (ATPM_PUBKEY aikPub) aikSig),
           ASignature sig] <- receive 1
          return ([], nA, pComp, SignedData aikPub aikSig, sig) -}

        _ -> error "Protocol id not yet implemented!"
-}
-}

{-
AikContents -> Proto (CipherText, CipherText)
-}



caEntity_CA :: {-LibXenVChan -> -}AikContents -> IO (CipherText, CipherText)
caEntity_CA {-attChan-} aikContents = do

  {-[AEntityInfo eInfo,
   ASignedData (SignedData
                (ATPM_IDENTITY_CONTENTS pubKey)
                 sig)]  <- receive' attChan
  -}
  let pubKey = dat aikContents
      --sig = sig aikContents
  ekPubKey <- readEK

  let iPubKey = identityPubKey pubKey
      iDigest = tpm_digest $ Data.Binary.encode iPubKey
      asymContents = contents iDigest
      blob = Data.Binary.encode asymContents
  encBlob <- tpm_rsa_pubencrypt ekPubKey blob

  caPriKey <- getCAPrivateKey
  let caCert = realSign caPriKey (Data.Binary.encode iPubKey)
      certBytes = Data.Binary.encode (SignedData iPubKey caCert)

      strictCert = toStrict certBytes
      encryptedCert = encryptCTR aes ctr strictCert
      enc = fromStrict encryptedCert

  {-send' attChan [ACipherText encBlob, ACipherText enc]-}
  return (encBlob, enc)
 where
   symKey =
     TPM_SYMMETRIC_KEY
     (tpm_alg_aes128)
     (tpm_es_sym_ctr)
     key

   v:: Word8
   v = 1
   key = ({-B.-}Data.ByteString.Lazy.pack $ Prelude.replicate 16 v)
   --strictKey = toStrict key
   aes = initAES $ toStrict key
   ctr = toStrict key
   contents dig = TPM_ASYM_CA_CONTENTS symKey dig







{-
attCommInit :: Channel -> Int -> Socket -> IO ProtoEnv
attCommInit chan protoId sock {-domidS-} = do
  debugPrint "BEFORE INVOKING TPM!!!"
  ekPub <- takeInit --Taking ownership of TPM
  debugPrint "AFTER INVOKING TPM!!!!!"
  --exportEK exportEKFileName ekPub  -- <--This is for provisioning
  {-appChan <- server_init (domidS !! 0)
  caChan <- client_init (domidS !! 1)
  appChan <- server_init (chans !! 0)
  caChan <- client_init (chans !! 1) -}
  let appChan = chan
      caChan = chan
      myInfo = EntityInfo "Attester" 11 appChan
      appInfo = EntityInfo "Appraiser" 22 appChan
      caInfo = EntityInfo "Certificate Authority" 33 caChan
      mList = [(0, myInfo), (1, appInfo), (2, caInfo)]
      ents = M.fromList mList
  (appPub,myPri) <- generateArmoredKeyPair -- Currently not used
  --appPub <- getBPubKey
  --caPub <- getBPubKey
  let caPub = appPub --Not used
      pubs = M.fromList [(1,appPub), (2, caPub)]

  return $ ProtoEnv 0 myPri ents pubs 0 0 0 protoId (Just sock)
-}

--main = attmain' [1, 4]

{-
attmain' :: Int -> Channel -> Socket -> IO String
attmain' protoId chan sock = do
  putStrLn "Main of entity Attestation"
  env <- attCommInit chan protoId sock --[1, 4]--[appId, caId]
  eitherResult <- runProto caEntity_Att env
  let str = case eitherResult of
             Left s -> "Error occured: " ++ s
             Right _ ->"End of Attestation"
  putStrLn str
  return str
-}
