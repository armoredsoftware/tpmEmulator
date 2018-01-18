module PrivacyCADemo where

import UserSoftware as U
import PrivacyCA as P
import Appraiser as A

main = do
  A.attestationRequest n pcrMask
  U.makeIdentity caDigest
  -- prepare packet to send to CA
  P.verifyAndSign
  U.activateIdentity
  U.tpm_quote
  -- prepare evidence for Appraiser
  A.appraiseEvidence
