module UserSoftware where

import TPM.Admin
import TPM.Const
import TPM.Session
import TPM.Key
import TPM.Socket

{- TODO: - Initialize TPM
- Accept appraisal requests
- Send requests to CACert
-}


tpm :: TPMSocket
tpm = tpm_socket "/var/run/tpm/tpmd_socket:0" --"/dev/tpm/tpmd_socket:0"

ownerpass = "ownerpass"
srkpass = "srkpass"

initialize_tpm :: IO TPM_PUBKEY
initialize_tpm = do
  tpm_startup tpm tpm_st_clear
  oiap_session <- tpm_session_oiap tpm
  (publicEK, _) <- tpm_key_pubek tpm
  public_srk <- tpm_takeownership tpm oiap_session publicEK owner_pass_digest srk_pass_digest
  putStrLn (show public_srk)
  tpm_session_close oiap_session
  return publicEK
    where
      owner_pass_digest = tpm_digest_pass ownerpass
      srk_pass_digest   = tpm_digest_pass srkpass

--tpm_makeidentity tpm (OIAP sah sen) (OSAP oah oosn oen oesn oscr) key spass ipass privCA = do

-- tpm_makeidentity :: TPM tpm => tpm -> Session -> Session -> TPM_KEY ->
--                                TPM_DIGEST -> TPM_DIGEST -> TPM_DIGEST ->
--                                IO (TPM_KEY, ByteString)

-- tpm_session_osap :: TPM tpm =>
--                     tpm ->
--                     TPM_DIGEST ->
--                     Word16 ->
--                     Word32 ->
--                     IO Session
make_identity ca_digest = do
  oiap_sess <- tpm_session_oiap tpm
  osap_sess <- tpm_session_osap tpm ownerpass_digest
  tpm_makeidentity tpm oiap_sess osap_sess xxx_key srkpass_digest ownerpass_digest ca_digest
    where
      ownerpass_digest = tpm_digest_pass ownerpass
      srkpass_digest   = tpm_digest_pass srkpass
