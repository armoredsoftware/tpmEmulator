module AppraiserUtil where

import Data.Binary
import Data.ByteString.Lazy hiding (pack, map, putStrLn)
import Crypto.Cipher.AES
import qualified Codec.Crypto.RSA as C
import Data.Digest.Pure.SHA (bytestringDigest, sha1)

import TPM
import TPMUtil
import Keys
import AttesterUtil (caEntity_Att)

{-
type Nonce = Int
type SymmKey = TPM_SYMMETRIC_KEY
type CipherText = ByteString;
type PrivateKey = C.PrivateKey --ByteString;
type PublicKey = C.PublicKey --ByteString;
type Signature = ByteString;
data SignedData a = SignedData {
  dat :: a,
  sig :: Signature
} deriving (Eq, Show)
type AikContents = SignedData TPM_IDENTITY_CONTENTS
-}


{-appCommInit :: Channel -> Int -> IO ProtoEnv
appCommInit attChan protoId {-domid-} = do
  --attChan <- client_init domid
  let myInfo = EntityInfo "Appraiser" 22 attChan
      attInfo = EntityInfo "Attester" 22 attChan
      mList = [(0, myInfo), (1, attInfo)]
      ents = M.fromList mList
  (attPub,myPri) <- generateArmoredKeyPair --Currently not used
  --attPub <-getBPubKey
  let pubs = M.fromList [(1,attPub)]


  return $ ProtoEnv 0 myPri ents pubs 0 0 0 protoId Nothing
-}

--main = appmain' 1

appmain' :: {-Int -> Channel -> -} IO String
appmain' {-protoId chan-} = do
  putStrLn "Main of entity Appraiser"
  {-env <- appCommInit chan protoId {-3-} -}
  let pcrSelect = mkTPMRequest [0..23]
      nonce = 34
  (n, comp, cert, qSig) <- caEntity_Att nonce pcrSelect
  evaluate (nonce, pcrSelect) (n, comp, cert, qSig)
  return ""

  {-
  str <- case eitherResult of
              Left s -> return $ "Error occured: " ++ s
              Right  resp@(ev, n, comp, cert@(SignedData aikPub aikSig), qSig) ->
                evaluate protoId ([D0, D1, D2], nonce, pcrSelect) (ev, n, comp, cert, qSig) -- "Response received:\n" ++ (show resp)
              Right x@_ -> do
                let strr =  "ERROR: resp from runproto did not match expected.\n\n\n"
                return strr
  putStrLn str
  return str
-}


evaluate :: {-Int -> -}({-[EvidenceDescriptor],-} Nonce, TPM_PCR_SELECTION) ->
            ({-Evidence,-} Nonce, TPM_PCR_COMPOSITE,
             (SignedData TPM_PUBKEY), Signature) -> IO (){-String-}
evaluate {-pId-} ({-d, -}nonceReq, pcrSelect)
  ({-ev, -}nonceResp, pcrComp, cert@(SignedData aikPub aikSig), qSig) = do
  --debugPrint "Inside Evaluate" --sequence $ [logf, putStrLn] <*> (pure ( "Inside Evaluate..."))
  caPublicKey <- getCAPublicKey
  return ()

  {-
  let blobEvidence :: ByteString
      blobEvidence = packImpl [AEvidence ev, ANonce nonceResp,
                               ASignedData $ SignedData ( ATPM_PUBKEY (dat cert)) (sig cert)] --pubKey
      evBlobSha1 =  bytestringDigest $ sha1 blobEvidence

      quoteInfo :: TPM_QUOTE_INFO
      quoteInfo = TPM_QUOTE_INFO (tpm_pcr_composite_hash $ pcrComp)                                                        (TPM_NONCE evBlobSha1)

      aikPublicKey = tpm_get_rsa_PublicKey aikPub

      r1 = realVerify caPublicKey (encode aikPub) aikSig
      r2 = realVerify aikPublicKey (encode quoteInfo) qSig
      r3 = nonceReq == nonceResp
  goldenPcrComposite <- readGoldenComp

  let r4 = pcrComp == goldenPcrComposite
      intVal = let m0 = Prelude.head ev in
                 case m0 of
                   M0 i -> i
                   _ -> error "Measurement descriptor not implemented!!"
      passString = case pId of
        1 -> ""
        2 -> let m1 = (ev !! 1) in
                case m1 of
                  M1 s -> s
                  _ -> error "Measurement descriptor not implemented!!"

      r5 = case pId of
        1 -> (intVal >= (20 :: Int))


        2 -> let goldenPassword = "\"12345\\000\\000\\000\\260\\005\"" in
          or [intVal == 0,  and [intVal == 1, passString == goldenPassword]]


  putStrLn $ show ev
  sequence $ [logf, putStrLn] <*> (pure ("CACert Signature: " ++ (show r1)))
  sequence $ [logf, putStrLn] <*> (pure ( "Quote Package Signature: " ++ (show r2)  ))
  sequence $ [logf, putStrLn] <*> (pure ( "Nonce: " ++ (show r3)))
  sequence $ [logf, putStrLn] <*> (pure ( "PCR Values: " ++ (show r4)))
  let guardString = case pId of
        1 -> "(Value >= 20?)"
        2 -> "(session == 0 OR session == 1 AND password == \"12345\":  False implies a buffer overflow)"
  if (or[pId == 1, pId == 2] )
    then sequence ([logf, putStrLn] <*> (pure ("Evidence" ++ guardString ++ ": " ++ (show r5))))
    else return [()]

  case pId of
    1 -> sequence ([logf, putStrLn] <*> (pure ("(Evidence Value: " ++ (show intVal) ++ ")")))
    2 -> sequence ([logf, putStrLn] <*> (pure ("(Session: " ++ (show intVal) ++ ", \n Password: " ++ passString ++ ")")))


    _ -> return [()]

  --if (or[pId == 1, pId == 2] ) then sequence ([logf, putStrLn] <*> (pure ("Evidence: " ++ (show r6) ++ ", Password Value: " ++ (show passString) ++ ", session Int Value: " ++ (show evVal)))) else return [()]
  return $ case (and [r1, r2, r3, r4, r5 {-,r6-}]) of
    True -> "All checks succeeded"
    False -> "At least one check failed"



-}

































{-
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





















{-

a :: Nonce
a = 3


generateNonce :: IO Nonce
generateNonce = do
  return 56 --faked

checkNonce :: Nonce -> Nonce -> IO ()
checkNonce expected actual = do
  case (expected == actual) of
    True -> return ()
    False -> putStrLn "Nonce check failed"


--Symmetric Key decryption
realDecrypt :: (Binary a) => SymmKey -> CipherText -> a
realDecrypt sessKey blob = let
  keyBytes = tpmSymmetricData sessKey
  strictKey = toStrict keyBytes
  aes = initAES strictKey
  ctr = strictKey
  decryptedBytes = decryptCTR aes ctr (toStrict blob)
  lazy = fromStrict decryptedBytes in
  (decode lazy)

realSign :: PrivateKey -> ByteString -> Signature --paramaterize over hash?
realSign priKey bytes = C.rsassa_pkcs1_v1_5_sign C.hashSHA1 priKey bytes --Concrete implementation plugs in here

realVerify :: PublicKey -> ByteString -> Signature -> Bool
realVerify pubKey m s = C.rsassa_pkcs1_v1_5_verify C.hashSHA1 pubKey m s

--Concrete packing(well-defined strategy for combining elements in preparation for encryption/signing) implementation
packImpl :: (Binary a) => [a] -> ByteString
packImpl as = encode as --mconcat bslist
 --where bslist = map tobs as

--Concrete unpacking implementation
unpackImpl :: Binary a => ByteString -> [a]
unpackImpl bs = decode bs


iPass = tpm_digest_pass aikPass
oPass = tpm_digest_pass ownerPass

tpmMk_Id :: IO (TPM_KEY_HANDLE, AikContents)
tpmMk_Id = do
  (aikHandle, iSig) <- makeAndLoadAIK
  aikPub <- attGetPubKey aikHandle iPass
  let aikContents = TPM_IDENTITY_CONTENTS iPass aikPub
  return (aikHandle, SignedData aikContents iSig)

tpmAct_Id :: TPM_KEY_HANDLE -> CipherText -> IO SymmKey
tpmAct_Id iKeyHandle actInput = do
  iShn <- tpm_session_oiap tpm
  oShn <- tpm_session_oiap tpm
  sessionKey <- tpm_activateidentity tpm iShn oShn
                iKeyHandle iPass oPass actInput
  return sessionKey

tpmQuote :: TPM_KEY_HANDLE -> TPM_PCR_SELECTION -> [Int] {-[ArmoredData]-}
         -> IO (TPM_PCR_COMPOSITE, Signature)
tpmQuote qKeyHandle pcrSelect exDataList = do
  let evBlob = packImpl exDataList
      evBlobSha1 = bytestringDigest $ sha1 evBlob
  (comp, sig) <- mkQuote qKeyHandle iPass pcrSelect evBlobSha1
  return (comp, sig)
-}


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



{-  
caEntity_Att :: Proto ()
caEntity_Att = do

  debugPrintP "\nBEGINNING OF ENTITY_ATT!!!!!!!!!!!!!!!!!!!\n"
  let appraiserEntityId :: EntityId
      appraiserEntityId = 1
  pId <- protoIs
  liftIO $ pcrReset
  liftIO $ pcrModify "a"

  case pId of
    _ -> do

      req@ [AAEvidenceDescriptor dList,
            reqNonce@(ANonce nApp),
            ATPM_PCR_SELECTION pcrSelect] <- receive appraiserEntityId

      (iKeyHandle, aikContents) <- tpmMk_Id
      (ekEncBlob, kEncBlob) <- caAtt_CA aikContents

      sessKey <- tpmAct_Id iKeyHandle ekEncBlob

      let caCert :: (SignedData TPM_PUBKEY)
          caCert = realDecrypt sessKey kEncBlob
      liftIO $ sequence $ [logf, putStrLn] <*> (pure ( "Sending Request to Measurer"))
      evidence <- caAtt_Mea dList

      liftIO $ sequence $ [logf, putStrLn] <*> (pure ( "Received response from Measurer: " ++ (show evidence)))

      let quoteExData =
            [AEvidence evidence,
             ANonce nApp,
             ASignedData $ SignedData (ATPM_PUBKEY (dat caCert)) (sig caCert)]
      (pcrComp, qSig) <- tpmQuote iKeyHandle pcrSelect quoteExData

      let response =
            [(quoteExData !! 0),
             reqNonce,
             ATPM_PCR_COMPOSITE pcrComp,
             (quoteExData !! 2),
             ASignature qSig]
      liftIO $ putStrLn $ "Sending response to Appraiser: \n\n" ++ (show response) ++ "\n\n"
      send appraiserEntityId response
      return ()



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
-}

    _ -> error "Protocol id not yet implemented!"
-}









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

caEntity_CA :: LibXenVChan -> IO ()
caEntity_CA attChan = do

  [AEntityInfo eInfo,
   ASignedData (SignedData
                (ATPM_IDENTITY_CONTENTS pubKey)
                 sig)]  <- receive' attChan

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

  send' attChan [ACipherText encBlob, ACipherText enc]
 where
   symKey =
     TPM_SYMMETRIC_KEY
     (tpm_alg_aes128)
     (tpm_es_sym_ctr)
     key

   v:: Word8
   v = 1
   key = ({-B.-}Data.ByteString.Lazy.pack $ replicate 16 v)
   --strictKey = toStrict key
   aes = initAES $ toStrict key
   ctr = toStrict key
   contents dig = TPM_ASYM_CA_CONTENTS symKey dig

-}





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
