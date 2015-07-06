-------------------------------------------------------------------------------
-- This module provides functions which perform all of the commands
-- listed in sections 3, 4, 5, and 6 of the document:
--  TPM Main: Part 3 - Commands
-------------------------------------------------------------------------------
module TPM.Admin where
import TPM.Const
import TPM.Driver
import TPM.Types
import TPM.Key
import TPM.Nonce
import TPM.Cipher
import TPM.Digest
import Data.Binary
import Data.ByteString.Lazy
import Prelude hiding (concat,length,map,replicate,splitAt)

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_startup :: TPM tpm => tpm -> TPM_STARTUP_TYPE -> IO ()
tpm_startup tpm st = tpm_transmit tpm 0 tag cod ste >> return ()
    where tag = tpm_tag_rqu_command
          cod = tpm_ord_startup
          ste = encode st

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_savestate :: (TPM tpm) => tpm -> IO ()
tpm_savestate tpm = tpm_transmit tpm 0 tag cod empty >> return ()
    where tag = tpm_tag_rqu_command
          cod = tpm_ord_savestate

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_selftestfull :: TPM tpm => tpm -> IO ()
tpm_selftestfull tpm = tpm_transmit tpm 0 tag cod empty >> return ()
    where tag = tpm_tag_rqu_command
          cod = tpm_ord_selftestfull

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_continueselftest :: TPM tpm => tpm -> IO ()
tpm_continueselftest tpm = tpm_transmit tpm 0 tag cod empty >> return ()
    where tag = tpm_tag_rqu_command
          cod = tpm_ord_continueselftest

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_gettestresult :: TPM tpm => tpm -> IO ByteString
tpm_gettestresult tpm = do
    (rtag,rsize,resl,dat) <- tpm_transmit' tpm tag cod empty
    let (_,tdata) = splitAt 4 dat
    return tdata
    where tag = tpm_tag_rqu_command
          cod = tpm_ord_gettestresult

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_setownerinstall :: TPM tpm => tpm -> Bool -> IO ()
tpm_setownerinstall tpm install = tpm_transmit tpm 0 tag cod ins >> return ()
    where tag = tpm_tag_rqu_command
          cod = tpm_ord_setownerinstall
          ins = encode install

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_ownersetdisable :: TPM tpm => tpm -> Session -> Bool -> TPM_DIGEST -> IO ()
tpm_ownersetdisable tpm (OIAP ah en) ena pass = do
    on <- nonce_create
    (rtag,size,resl,_) <- tpm_transmit' tpm tag cod (dat on)
    return ()
    where tag = tpm_tag_rqu_auth1_command
          cod = tpm_ord_ownersetdisable
          dat on = concat [encode ena,ah,encode on,encode False,encode (ath on)]
          ath on = tpm_auth_hmac pass en on 0 $ concat [encode cod,encode ena]

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_physicalenable :: TPM tpm => tpm -> IO ()
tpm_physicalenable tpm = tpm_transmit tpm 0 tag cod empty >> return ()
    where tag = tpm_tag_rqu_command
          cod = tpm_ord_physicalenable

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_physicaldisable :: TPM tpm => tpm -> IO ()
tpm_physicaldisable tpm = tpm_transmit tpm 0 tag cod empty >> return ()
    where tag = tpm_tag_rqu_command
          cod = tpm_ord_physicaldisable

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_physicalsetdeactivated :: TPM tpm => tpm -> Bool -> IO ()
tpm_physicalsetdeactivated tpm de = tpm_transmit tpm 0 tag cod dea >> return ()
    where tag = tpm_tag_rqu_command
          cod = tpm_ord_physicalsetdeactivated
          dea = encode de

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_settempdeactivated :: TPM tpm => tpm -> Session -> TPM_DIGEST -> IO ()
tpm_settempdeactivated tpm (OIAP ah en) pass = do
    on <- nonce_create
    (rtag,size,resl,_) <- tpm_transmit' tpm tag cod (dat on)
    return ()
    where tag = tpm_tag_rqu_auth1_command
          cod = tpm_ord_settempdeactivated
          dat on = concat [ah, encode on, encode False, encode (ath on)]
          ath on = tpm_auth_hmac pass en on 0 (encode cod)

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_setoperatorauth :: TPM tpm => tpm -> TPM_DIGEST -> IO ()
tpm_setoperatorauth tpm pass = tpm_transmit tpm 0 tag cod dat >> return ()
    where tag = tpm_tag_rqu_command
          cod = tpm_ord_setoperatorauth
          dat = encode pass

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_takeownership :: TPM tpm => tpm -> Session -> TPM_PUBKEY ->
                                TPM_DIGEST -> TPM_DIGEST ->  IO TPM_KEY
tpm_takeownership tpm (OIAP ah en) pubkey pass srkpass = do
    ownenc' <- tpm_rsa_pubencrypt pubkey pass
    on <- nonce_create
    let   ownenc = encode $ ownenc'
          ownlen = encode ((fromIntegral $ length ownenc) :: UINT32)
    srkenc' <- tpm_rsa_pubencrypt pubkey srkpass
    let   srkenc = encode $ srkenc'
          srklen = encode ((fromIntegral $ length srkenc) :: UINT32)
          tag = tpm_tag_rqu_auth1_command
          cod = tpm_ord_takeownership
          pro = tpm_pid_owner
          key = tpm_key_createowner tpm_auth_priv_use_only
          ath on = tpm_auth_hmac pass en on 0 $ concat [
                      encode cod, encode pro, ownlen, ownenc
                    , srklen, srkenc, encode key ]
          dat on = concat [ encode pro, ownlen, ownenc, srklen, srkenc
                          , encode key, ah, encode on, singleton 0x0
                          , encode (ath on) ]
    (rtag,size,resl,dat) <- tpm_transmit' tpm tag cod (dat on)
    return (decode dat)




-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_ownerclear :: TPM tpm => tpm -> Session -> TPM_DIGEST -> IO ()
tpm_ownerclear tpm (OIAP ah en) pass = do
    on <- nonce_create
    (rtag,size,resl,_) <- tpm_transmit' tpm tag cod (dat on)
    return ()
    where tag = tpm_tag_rqu_auth1_command
          cod = tpm_ord_ownerclear
          dat on = concat [ah, encode on, encode False, encode (ath on) ]
          ath on = tpm_auth_hmac pass en on 0 (encode cod)

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_forceclear :: TPM tpm => tpm -> IO ()
tpm_forceclear tpm = tpm_transmit tpm 0 tag cod empty >> return ()
    where tag = tpm_tag_rqu_command
          cod = tpm_ord_forceclear

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_disableownerclear :: TPM tpm => tpm -> Session -> TPM_DIGEST -> IO ()
tpm_disableownerclear tpm (OIAP ah en) pass = do
    on <- nonce_create
    (rtag,size,resl,_) <- tpm_transmit' tpm tag cod (dat on)
    return ()
    where tag = tpm_tag_rqu_auth1_command
          cod = tpm_ord_disableownerclear
          dat on = concat [ah, encode on, encode False, encode (ath on)]
          ath on = tpm_auth_hmac pass en on 0 (encode cod)

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_disableforceclear :: TPM tpm => tpm -> IO ()
tpm_disableforceclear tpm = tpm_transmit tpm 0 tag cod empty >> return ()
    where tag = tpm_tag_rqu_command
          cod = tpm_ord_disableforceclear

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tsc_physicalpresence :: TPM tpm => tpm -> TPM_PHYSICAL_PRESENCE -> IO ()
tsc_physicalpresence tpm pp = tpm_transmit tpm 0 tag cod ppe >> return ()
    where tag = tpm_tag_rqu_command
          cod = tsc_ord_physicalpresence
          ppe = encode pp

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tsc_resetestablishmentbit :: TPM tpm => tpm -> IO ()
tsc_resetestablishmentbit tpm = tpm_transmit tpm 0 tag cod empty >> return ()
    where tag = tpm_tag_rqu_command
          cod = tsc_ord_resetestablishmentbit
