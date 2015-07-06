-------------------------------------------------------------------------------
-- This module provides functions which perform all of the commands
-- listed in section 7 of the document: TPM Main: Part 3 - Commands
-------------------------------------------------------------------------------
module TPM.Capability where
import TPM.Utils
import TPM.Const
import TPM.Driver
import TPM.Types
import TPM.Nonce
import TPM.Digest
import Data.Word
import Data.Binary
import Control.Monad
import Control.Exception
import Data.ByteString.Lazy
import Prelude hiding (concat,length,map,splitAt,replicate)

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_getcapability :: TPM tpm => tpm -> TPM_CAPABILITY_AREA -> ByteString -> 
                                IO (Word32,ByteString)
tpm_getcapability tpm cap sub = do 
    (rtag,size,resl,dat) <- tpm_transmit' tpm tag cod dat
    let (rsize,rdat) = splitAt 4 dat
    return (decode rsize, rdat)
    where tag = tpm_tag_rqu_command
          cod = tpm_ord_getcapability
          dat = concat [ encode cap
                       , encode ((fromIntegral $ length sub) :: UINT32)
                       , sub ]

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_setcapability :: TPM tpm => tpm -> Session -> TPM_CAPABILITY_AREA -> 
                                ByteString -> ByteString -> TPM_DIGEST -> 
                                IO ()
tpm_setcapability tpm (OIAP ah en) cap sub set pass = do 
    on <- nonce_create
    (rtag,size,resl,_) <- tpm_transmit' tpm tag cod (dat on)
    return ()
    where tag = tpm_tag_rqu_auth1_command
          cod = tpm_ord_setcapability
          sbl = encode ((fromIntegral $ length sub) :: UINT32)
          stl = encode ((fromIntegral $ length set) :: UINT32)
          dat on = concat [ encode cap, sbl, sub, stl, set, ah, encode on 
                          , encode False, encode (ath on)]
          ath on = tpm_auth_hmac pass en on 0 $ concat [ encode cod, encode cap
                                                       , sbl, sub, stl, set ]

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_getcapabilityowner :: TPM tpm => tpm -> Session -> TPM_DIGEST -> 
                                     IO (TPM_VERSION,UINT32,UINT32)
tpm_getcapabilityowner tpm (OIAP ah en) pass = do 
    on <- nonce_create
    (rtag,size,resl,dat) <- tpm_transmit' tpm tag cod (dat on)
    return $ decode dat
    where tag = tpm_tag_rqu_auth1_command
          cod = tpm_ord_getcapabilityowner
          dat on = concat [ah, encode on, encode False, encode (ath on)]
          ath on = tpm_auth_hmac pass en on 0 (encode cod)

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_setcap_readsrkpub t sh v p = tpm_setcap_bool t sh c s v p
    where c = tpm_set_perm_flags
          s = tpm_pf_readsrkpub

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_setcap_disablefulldalogicinfo t sh v p = tpm_setcap_bool t sh c s v p
    where c = tpm_set_perm_flags 
          s = tpm_pf_disablefulldalogicinfo

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_setcap_tospresent t sh p = tpm_setcap_bool t sh c s False p
    where c = tpm_set_stany_flags 
          s = tpm_af_tospresent

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_setcap_deferredphysicalpresence t sh v p = tpm_setcap_bool t sh c s v p
    where c = tpm_set_stclear_data
          s = tpm_sd_deferredphysicalpresence

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_setcap_daaproof t sh p = tpm_setcapability t sh c s empty p
    where c = tpm_set_perm_data
          s = encode tpm_pd_daaproof

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_getcap_key_handle :: TPM tpm => tpm -> IO TPM_KEY_HANDLE_LIST
tpm_getcap_key_handle tpm = do
    (size,resl) <- tpm_getcapability tpm tpm_cap_key_handle empty
    return $ decode resl

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_getcap_version :: TPM tpm => tpm -> IO TPM_VERSION
tpm_getcap_version tpm = do 
    (rsize,rdat) <- tpm_getcap tpm tpm_cap_version 4 empty
    return $ decode rdat

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_getcap_ord tpm ord = tpm_getcap_bool tpm tpm_cap_ord (encode (ord::Word32))
tpm_getcap_alg tpm alg = tpm_getcap_bool tpm tpm_cap_alg (encode (alg::Word32))
tpm_getcap_pid tpm pid = tpm_getcap_bool tpm tpm_cap_pid (encode (pid::Word32))

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_getcap_tis_timeout :: TPM tpm => tpm -> IO (Integer,Integer,Integer,Integer)
tpm_getcap_tis_timeout tpm = do 
    (rsize,rdat) <- tpm_getprop tpm 16 tpm_cap_prop_tis_timeout
    let (ta,ta') = splitAt 4 rdat
    let (tb,tb') = splitAt 4 ta'
    let (tc,td) = splitAt 4 tb'
    let ta' = fromIntegral $ ((decode ta) :: Word32)
    let tb' = fromIntegral $ ((decode tb) :: Word32)
    let tc' = fromIntegral $ ((decode tc) :: Word32)
    let td' = fromIntegral $ ((decode td) :: Word32)
    return (ta',tb',tc',td')

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_getcap_duration :: TPM tpm => tpm -> IO TPMDuration
tpm_getcap_duration tpm = do 
    (rsize,rdat) <- tpm_getprop tpm 12 tpm_cap_prop_duration
    let (ts,ts') = splitAt 4 rdat
    let (tm,tl) = splitAt 4 ts'
    let ts' = fromIntegral $ ((decode ts) :: Word32)
    let tm' = fromIntegral $ ((decode tm) :: Word32)
    let tl' = fromIntegral $ ((decode tl) :: Word32)
    return $ TPMDuration ts' tm' tl'

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_getcap_active_counter :: TPM tpm => tpm -> IO (Maybe Integer)
tpm_getcap_active_counter tpm = do 
    active <- tpm_getprop_word32 tpm tpm_cap_prop_active_counter
    case active of
        0xFFFFFFFF -> return Nothing
        _          -> return $ Just (fromIntegral active)

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_getcap_startup_effect :: TPM tpm => tpm -> IO TPM_STARTUP_EFFECTS
tpm_getcap_startup_effect tpm = do 
    (rsize,rdat) <- tpm_getprop tpm 4 tpm_cap_prop_startup_effect
    return $ decode rdat

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_getcap_pcrs tpm = tpm_getprop_integer tpm tpm_cap_prop_pcr
tpm_getcap_mnft tpm = tpm_getprop_integer tpm tpm_cap_prop_manufacturer
tpm_getcap_dir tpm = tpm_getprop_integer tpm tpm_cap_prop_dir
tpm_getcap_keys tpm = tpm_getprop_integer tpm tpm_cap_prop_keys
tpm_getcap_min_counter tpm = tpm_getprop_integer tpm tpm_cap_prop_min_counter
tpm_getcap_authsess tpm = tpm_getprop_integer tpm tpm_cap_prop_authsess
tpm_getcap_transess tpm = tpm_getprop_integer tpm tpm_cap_prop_transess
tpm_getcap_daasess tpm = tpm_getprop_integer tpm tpm_cap_prop_daasess
tpm_getcap_counters tpm = tpm_getprop_integer tpm tpm_cap_prop_counters
tpm_getcap_max_authsess tpm = tpm_getprop_integer tpm tpm_cap_prop_max_authsess
tpm_getcap_max_transess tpm = tpm_getprop_integer tpm tpm_cap_prop_max_transess
tpm_getcap_max_daasess tpm = tpm_getprop_integer tpm tpm_cap_prop_max_daasess
tpm_getcap_max_counters tpm = tpm_getprop_integer tpm tpm_cap_prop_max_counters
tpm_getcap_max_keys tpm = tpm_getprop_integer tpm tpm_cap_prop_max_keys
tpm_getcap_owner tpm = tpm_getprop_bool tpm tpm_cap_prop_owner
tpm_getcap_context tpm = tpm_getprop_integer tpm tpm_cap_prop_context
tpm_getcap_max_context tpm = tpm_getprop_integer tpm tpm_cap_prop_max_context
tpm_getcap_familyrows tpm = tpm_getprop_integer tpm tpm_cap_prop_familyrows
tpm_getcap_delegaterow tpm = tpm_getprop_integer tpm tpm_cap_prop_delegate_row
tpm_getcap_context_dist tpm = tpm_getprop_integer tpm tpm_cap_prop_context_dist
tpm_getcap_daa_intr tpm = tpm_getprop_bool tpm tpm_cap_prop_daa_interrupt
tpm_getcap_sessions tpm = tpm_getprop_integer tpm tpm_cap_prop_sessions
tpm_getcap_max_sessions tpm = tpm_getprop_integer tpm tpm_cap_prop_max_sessions
tpm_getcap_cmk_restr tpm = tpm_getprop_word32 tpm tpm_cap_prop_cmk_restriction
tpm_getcap_buffer tpm = tpm_getprop_integer tpm tpm_cap_prop_input_buffer

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_getcap :: TPM tpm => tpm -> TPM_CAPABILITY_AREA -> Word32 -> ByteString -> IO (Word32,ByteString)
tpm_getcap tpm cap esize sub = do
    (rsize,rdata) <- tpm_getcapability tpm cap sub
    when (rsize /= esize) $ do
        throwTPM "Unexpected TPM response."
    return (rsize,rdata)

tpm_getcap_word32 :: TPM tpm => tpm -> Word32 -> ByteString -> IO Word32
tpm_getcap_word32 tpm cap extra = do
    (rsize,rdat) <- tpm_getcap tpm cap 4 extra
    return $ ((decode rdat) :: Word32)

tpm_getcap_word16 :: TPM tpm => tpm -> Word32 -> ByteString -> IO Word16
tpm_getcap_word16 tpm cap extra = do
    (rsize,rdat) <- tpm_getcap tpm cap 2 extra
    return $ ((decode rdat) :: Word16)

tpm_getcap_word8 :: TPM tpm => tpm -> Word32 -> ByteString -> IO Word8
tpm_getcap_word8 tpm cap extra = do
    (rsize,rdat) <- tpm_getcap tpm cap 1 extra
    return $ ((decode rdat) :: Word8)

tpm_getcap_bool :: TPM tpm => tpm -> Word32 -> ByteString -> IO Bool
tpm_getcap_bool tpm cap extra = do
    rdat <- tpm_getcap_word8 tpm cap extra
    return $ rdat /= 0
    
-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_getprop_integer :: TPM tpm => tpm -> Word32 -> IO Integer
tpm_getprop_integer t p = tpm_getprop_word32 t p >>= return . fromIntegral

tpm_getprop_bool :: TPM tpm => tpm -> Word32 -> IO Bool
tpm_getprop_bool t p = tpm_getprop_word8 t p >>= return . (/= 0)

tpm_getprop_word32 :: TPM tpm => tpm -> Word32 -> IO Word32
tpm_getprop_word32 tpm prop = do 
    (rsize,rdat) <- tpm_getprop tpm 4 prop
    return (fromIntegral ((decode rdat) :: Word32))

tpm_getprop_word8 :: TPM tpm => tpm -> Word32 -> IO Word8
tpm_getprop_word8 tpm prop = do 
    (rsize,rdat) <- tpm_getprop tpm 1 prop
    return (fromIntegral ((decode rdat) :: Word8))

tpm_getprop :: TPM tpm => tpm -> Word32 -> Word32 -> IO (Word32,ByteString)
tpm_getprop tpm size prop = tpm_getcap tpm cap size (encode prop)
    where cap = tpm_cap_property

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_setcap_bool :: TPM tpm => tpm -> Session -> TPM_CAPABILITY_AREA ->
                              Word32 -> Bool -> TPM_DIGEST -> IO ()
tpm_setcap_bool tpm sn cap sub vl pass = tpm_setcapability tpm sn c s v pass
    where c = cap
          s = encode sub
          v = encode vl
