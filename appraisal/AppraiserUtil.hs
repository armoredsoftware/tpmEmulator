module AppraiserUtil where

import Data.Binary
import Data.ByteString.Lazy hiding (pack, map, putStrLn)
--import Crypto.Cipher.AES
import qualified Codec.Crypto.RSA as C
import Data.Digest.Pure.SHA (bytestringDigest, sha1)

import TPM
import TPMUtil
import AttesterUtil (caEntity_Att)
import Keys
import Provisioning

appmain' :: {-Int -> Channel -> -} IO String
appmain' {-protoId chan-} = do
  putStrLn "Main of entity Appraiser:"
  {-env <- appCommInit chan protoId {-3-} -}
  let pcrSelect = mkTPMRequest [23]
      nonce = 34
  putStrLn $ "Sending Request: ( " ++ (show pcrSelect) ++ ", Nonce ) \n"
  (n, comp, cert, qSig) <- caEntity_Att nonce pcrSelect
  evaluate (nonce, pcrSelect) (n, comp, cert, qSig)

evaluate :: {-Int -> -}({-[EvidenceDescriptor],-} Nonce, TPM_PCR_SELECTION) ->
            ({-Evidence,-} Nonce, TPM_PCR_COMPOSITE,
             (SignedData TPM_PUBKEY), Signature) -> IO String
evaluate {-pId-} ({-d, -}nonceReq, pcrSelect)
  ({-ev, -}nonceResp, pcrComp, cert@(SignedData aikPub aikSig), qSig) = do
  --debugPrint "Inside Evaluate" --sequence $ [logf, putStrLn] <*> (pure ( "Inside Evaluate..."))
  caPublicKey <- getCAPublicKey

  
  let blobEvidence :: ByteString
      {-blobEvidence = packImpl [AEvidence ev, ANonce nonceResp,
                               ASignedData $ SignedData ( ATPM_PUBKEY (dat cert)) (sig cert)] --pubKey -}
      blobEvidence = packImpl [nonceResp]
      evBlobSha1 =  bytestringDigest $ sha1 blobEvidence

      quoteInfo :: TPM_QUOTE_INFO
      quoteInfo = TPM_QUOTE_INFO (tpm_pcr_composite_hash $ pcrComp)                                                        (TPM_NONCE evBlobSha1)

      aikPublicKey = tpm_get_rsa_PublicKey aikPub

      r1 = realVerify caPublicKey (encode aikPub) aikSig
      r2 = realVerify aikPublicKey (encode quoteInfo) qSig
      r3 = nonceReq == nonceResp
  goldenPcrComposite <- readGoldenComp

  let r4 = pcrComp == goldenPcrComposite
  putStrLn ("Actual PCR Composite: \n" ++ (show pcrComp) ++ "\n")
  putStrLn ("Golden PCR Composite: \n" ++ (show goldenPcrComposite) ++ "\n")

  sequence $ [{-logf, -}putStrLn] <*> (pure ("CACert Signature: " ++ (show r1)))
  sequence $ [{-logf, -}putStrLn] <*> (pure ( "Quote Package Signature: " ++ (show r2)  ))
  sequence $ [{-logf, -}putStrLn] <*> (pure ( "Nonce: " ++ (show r3)))
  sequence $ [{-logf, -}putStrLn] <*> (pure ( "PCR Values: " ++ (show r4)))

  return $ case (and [r1, r2, r3, r4]) of
    True -> "All checks succeeded"
    False -> "At least one check failed"
