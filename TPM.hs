module TPM (
    module TPM.Admin,
    module TPM.Capability,
    module TPM.Const,
    module TPM.Driver,
    module TPM.Driver.Socket,
    module TPM.Error,
    module TPM.Key,
    module TPM.Nonce,
    module TPM.PCR,
    module TPM.Digest,
    module TPM.Session,
    module TPM.Storage,
    module TPM.Types,
    module TPM.Utils,
    module TPM.Cipher,
    module TPM.Eviction,
    tpm_with_socket
) where
import TPM.Admin
import TPM.Capability
import TPM.Const
import TPM.Driver
import TPM.Driver.Socket
import TPM.Error
import TPM.Key
import TPM.Nonce
import TPM.PCR
import TPM.Digest
import TPM.Session
import TPM.Types
import TPM.Utils
import TPM.Cipher
import TPM.Storage
import TPM.Eviction
import Control.Exception
import TPM.SignTest

tpm_with_socket c = c (tpm_socket "/var/run/tpm/tpmd_socket:0") 
tpm_with_socket' c = c (tpm_logging_socket "/var/run/tpm/tpmd_socket:0")

tpm_with_oiap c = tpm_with_socket $ \s -> do 
    oiap <- tpm_session_oiap s
    c s oiap
    tpm_session_close s oiap
    return ()

tpm_take = tpm_with_socket $ \tpm -> do
    (pub,_) <- tpm_key_pubek tpm
    key <- bracket (tpm_session_oiap tpm)
                (tpm_session_close tpm)
                (\sess -> tpm_takeownership tpm sess pub (tpm_digest_pass "wesley") (tpm_digest_pass ""))
    putStrLn $ show key
    return ()
