module TPM.Const where
import Data.Word
import Data.ByteString.Lazy hiding (filter)
import Data.Binary
import Data.Bits
-- import TPM.Types

-------------------------------------------------------------------------------
-- TPM command and response tags as defined by section 6 of the document:
--  TPM Main: Part 2 - TPM Structures
-- Type: TPM_TAG
-------------------------------------------------------------------------------
tpm_tag_rqu_command = (0x00c1 :: Word16)
tpm_tag_rqu_auth1_command = (0x00c2 :: Word16)
tpm_tag_rqu_auth2_command = (0x00c3 :: Word16)
tpm_tag_rsp_command = (0x00c4 :: Word16)
tpm_tag_rsp_auth1_command = (0x00c5 :: Word16)
tpm_tag_rsp_auth2_command = (0x00c6 :: Word16)

-------------------------------------------------------------------------------
-- TPM structure tags as defined by section 3.1 of the document:
--  TPM Main: Part 2 - TPM Structures
-- Type: TPM_STRUCTURE_TAG
-------------------------------------------------------------------------------
tpm_tag_contextblob = (0x0001 :: Word16)
tpm_tag_context_sensitive = (0x0002 :: Word16)
tpm_tag_contextpointer = (0x0003 :: Word16)
tpm_tag_contextlist = (0x0004 :: Word16)
tpm_tag_signinfo = (0x0005 :: Word16)
tpm_tag_pcr_info_long = (0x0006 :: Word16)
tpm_tag_persistent_flags = (0x0007 :: Word16) --
tpm_tag_volatile_flags = (0x0008 :: Word16)
tpm_tag_persistent_data = (0x0009 :: Word16)
tpm_tag_volatile_data = (0x000a :: Word16)
tpm_tag_sv_data = (0x000b :: Word16)
tpm_tag_ek_blob = (0x000c :: Word16)
tpm_tag_ek_blob_auth = (0x000d :: Word16)
tpm_tag_counter_value = (0x000e :: Word16)
tpm_tag_transport_internal = (0x000f :: Word16)
tpm_tag_transport_log_in = (0x0010 :: Word16)
tpm_tag_transport_log_out = (0x0011 :: Word16)
tpm_tag_audit_event_in = (0x0012 :: Word16)
tpm_tag_audit_event_out = (0x0013 :: Word16)
tpm_tag_current_ticks = (0x0014 :: Word16)
tpm_tag_key12 = (0x0015 :: Word16) -- find out why not following 1.2 spec (Backward compat with tpm-emulator?)
tpm_tag_stored_data12 = (0x0016 :: Word16)
tpm_tag_nv_attributes = (0x0017 :: Word16)
tpm_tag_nv_data_public = (0x0018 :: Word16)
tpm_tag_nv_data_sensitive = (0x0019 :: Word16)
tpm_tag_delegations = (0x001a :: Word16)
tpm_tag_delegate_public = (0x001b :: Word16)
tpm_tag_delegate_table_row = (0x001c :: Word16)
tpm_tag_transport_auth = (0x001d :: Word16)
tpm_tag_transport_public = (0x001e :: Word16)
tpm_tag_permanent_flags = (0x001f :: Word16)
tpm_tag_stclear_flags = (0x0020 :: Word16)
tpm_tag_stany_flags = (0x0021 :: Word16)
tpm_tag_permanent_data = (0x0022 :: Word16)
tpm_tag_stclear_data = (0x0023 :: Word16)
tpm_tag_stany_data = (0x0024 :: Word16)
tpm_tag_family_table_entry = (0x0025 :: Word16)
tpm_tag_delegate_sensitive = (0x0026 :: Word16)
tpm_tag_delg_key_blob = (0x0027 :: Word16)
-- tpm_tag_key12 = (0x0028 :: Word16)
tpm_tag_certify_info2 = (0x0029 :: Word16)
tpm_tag_delegate_owner_blob = (0x002A :: Word16)
tpm_tag_ek_blob_activate = (0x002B :: Word16)
tpm_tag_daa_blob = (0x002C :: Word16)
tpm_tag_daa_context = (0x002D :: Word16)
tpm_tag_daa_enforce = (0x002E :: Word16)
tpm_tag_daa_issuer = (0x002F :: Word16)
tpm_tag_cap_version_info = (0x0030 :: Word16)
tpm_tag_daa_sensitive = (0x0031 :: Word16)
tpm_tag_daa_tpm = (0x0032 :: Word16)
tpm_tag_cmk_migauth = (0x0033 :: Word16)
tpm_tag_cmk_sigticket = (0x0034 :: Word16)
tpm_tag_cmk_ma_approval = (0x0035 :: Word16)
tpm_tag_quote_info2 = (0x0036 :: Word16)
tpm_tag_da_info = (0x0037 :: Word16)
tpm_tag_da_info_limited = (0x0038 :: Word16)
tpm_tag_da_action_type = (0x0039 :: Word16)

-------------------------------------------------------------------------------
-- TPM resource types as defined by section 4.1 of the document:
--  TPM Main: Part 2 - TPM Structures
-- Type: TPM_RESOURCE_TYPE
-------------------------------------------------------------------------------
tpm_rt_key = (0x00000001 :: Word32)
tpm_rt_auth = (0x00000002 :: Word32)
tpm_rt_hash = (0x00000003 :: Word32)
tpm_rt_trans = (0x00000004 :: Word32)
tpm_rt_context = (0x00000005 :: Word32)
tpm_rt_counter = (0x00000006 :: Word32)
tpm_rt_delegate = (0x00000007 :: Word32)
tpm_rt_daa_tpm = (0x00000008 :: Word32)
tpm_rt_daa_v0 = (0x00000009 :: Word32)
tpm_rt_daa_v1 = (0x0000000a :: Word32)

-------------------------------------------------------------------------------
-- TPM payload types as defined by section 4.2 of the document:
--  TPM Main: Part 2 - TPM Structures
-- Type: TPM_PAYLOAD_TYPE
-------------------------------------------------------------------------------
tpm_pt_asym = (0x01 :: Word8)
tpm_pt_bind = (0x02 :: Word8)
tpm_pt_migrate = (0x03 :: Word8)
tpm_pt_maint = (0x04 :: Word8)
tpm_pt_seal = (0x05 :: Word8)
tpm_pt_migrate_restricted = (0x06 :: Word8)
tpm_pt_migrate_external = (0x07 :: Word8)
tpm_pt_cmk_migrate = (0x08 :: Word8)

-------------------------------------------------------------------------------
-- TPM entity types as defined by section 4.3 of the document:
--  TPM Main: Part 2 - TPM Structures
-- Type: TPM_ENTITY_TYPE
-------------------------------------------------------------------------------
tpm_et_xor_keyhandle = (0x0001 :: Word16)
tpm_et_xor_owner = (0x0002 :: Word16) -- key handle: 0x40000001
tpm_et_xor_data = (0x0003 :: Word16)
tpm_et_xor_srk = (0x0004 :: Word16) -- key handle: 0x40000000
tpm_et_xor_key = (0x0005 :: Word16)
tpm_et_xor_revoke = (0x0006 :: Word16) -- key handle: 0x40000002
tpm_et_xor_del_owner_blob = (0x0007 :: Word16)
tpm_et_xor_del_row = (0x0008 :: Word16)
tpm_et_xor_del_key_blob = (0x0009 :: Word16)
tpm_et_xor_counter = (0x000a :: Word16)
tpm_et_xor_nv = (0x000B :: Word16)
tpm_et_xor_operator = (0x000c :: Word16)
tpm_et_xor_reserved_handle = (0x0040 :: Word16)

tpm_et_aes_keyhandle = (0x0601 :: Word16)
tpm_et_aes_owner = (0x0602 :: Word16) -- key handle: 0x40000001
tpm_et_aes_data = (0x0603 :: Word16)
tpm_et_aes_srk = (0x0604 :: Word16) -- key handle: 0x40000000
tpm_et_aes_key = (0x0605 :: Word16)
tpm_et_aes_revoke = (0x0606 :: Word16) -- key handle: 0x40000002
tpm_et_aes_del_owner_blob = (0x0607 :: Word16)
tpm_et_aes_del_row = (0x0608 :: Word16)
tpm_et_aes_del_key_blob = (0x0609 :: Word16)
tpm_et_aes_counter = (0x060a :: Word16)
tpm_et_aes_nv = (0x060B :: Word16)
tpm_et_aes_operator = (0x060c :: Word16)
tpm_et_aes_reserved_handle = (0x0640 :: Word16)

-------------------------------------------------------------------------------
-- TPM well known key handles as defined by section 4.4.1 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
tpm_kh_srk = (0x40000000 :: Word32)
tpm_kh_owner = (0x40000001 :: Word32)
tpm_kh_revoke = (0x40000002 :: Word32)
tpm_kh_transport = (0x40000003 :: Word32)
tpm_kh_operator = (0x40000004 :: Word32)
tpm_kh_admin = (0x40000005 :: Word32)
tpm_kh_ek = (0x40000006 :: Word32)

-------------------------------------------------------------------------------
-- TPM startup types as defined by section 4.5 of the document:
--  TPM Main: Part 2 - TPM Structures
-- Type: TPM_STARTUP_TYPE
-------------------------------------------------------------------------------
tpm_st_clear = (0x0001 :: Word16)
tpm_st_state = (0x0002 :: Word16)
tpm_st_deactivated = (0x0003 :: Word16)

-------------------------------------------------------------------------------
-- TPM protocol identifiers as defined by section 4.7 of the document:
--  TPM Main: Part 2 - TPM Structures
-- Type: TPM_PROTOCOL_ID
-------------------------------------------------------------------------------
tpm_pid_oiap = (0x0001 :: Word16)
tpm_pid_osap = (0x0002 :: Word16)
tpm_pid_adip = (0x0003 :: Word16)
tpm_pid_adcp = (0x0004 :: Word16)
tpm_pid_owner = (0x0005 :: Word16)
tpm_pid_dsap = (0x0006 :: Word16)
tpm_pid_transport = (0x0007 :: Word16)

-------------------------------------------------------------------------------
-- TPM algorithm identifiers as defined by section 4.8 of the document:
--  TPM Main: Part 2 - TPM Structures
-- Type: TPM_ALGORITHM_ID
-------------------------------------------------------------------------------
tpm_alg_rsa = (0x00000001 :: Word32)
tpm_alg_sha = (0x00000004 :: Word32)
tpm_alg_hmac = (0x00000005 :: Word32)
tpm_alg_aes128 = (0x00000006 :: Word32)
tpm_alg_mgf1 = (0x00000007 :: Word32)
tpm_alg_aes192 = (0x00000008 :: Word32)
tpm_alg_aes256 = (0x00000009 :: Word32)
tpm_alg_xor = (0x0000000a :: Word32)

-- helper functions not defined in spec
tpm_alg_names = [ (tpm_alg_rsa,"RSA")
                , (tpm_alg_sha,"SHA-1")
                , (tpm_alg_hmac, "HMAC SHA-1")
                , (tpm_alg_aes128, "AES 128")
                , (tpm_alg_mgf1, "MGF1")
                , (tpm_alg_aes192, "AES 192")
                , (tpm_alg_aes256, "AES 256")
                , (tpm_alg_xor, "XOR") ]
tpm_alg_getname alg = case lookup alg tpm_alg_names of
                        Nothing -> "Unknown Algorithm"
                        Just x  -> x

-------------------------------------------------------------------------------
-- TPM physical presence values as defined by section 4.9 of the document:
--  TPM Main: Part 2 - TPM Structures
-- Type: TPM_PHYSICAL_PRESENCE
-------------------------------------------------------------------------------
tpm_physical_presence_hw_disable = (0x0200 :: Word16)
tpm_physical_presence_cmd_disable = (0x0100 :: Word16)
tpm_physical_presence_lifetime_lock = (0x0080 :: Word16)
tpm_physical_presence_hw_enable = (0x0040 :: Word16)
tpm_physical_presence_cmd_enable = (0x0020 :: Word16)
tpm_physical_presence_notpresent = (0x0010 :: Word16)
tpm_physical_presence_present = (0x0008 :: Word16)
tpm_physical_presence_lock = (0x0004 :: Word16)

-------------------------------------------------------------------------------
-- TPM migration schemes as defiend by section 4.10 of the document:
--  TPM Main: Part 2 - TPM Structures
-- Type: TPM_MIGRATE_SCHEME
-------------------------------------------------------------------------------
tpm_ms_migrate = (0x0001 :: Word16)
tpm_ms_rewrap = (0x0002 :: Word16)
tpm_ms_maint = (0x0003 :: Word16)
tpm_ms_restrict_migrate = (0x0004 :: Word16)
tpm_ms_restrict_approve = (0x0005 :: Word16)

-------------------------------------------------------------------------------
-- TPM ek types as defined by section 4.11 of the document:
--  TPM Main: Part 2 - TPM Structures
-- Type: TPM_EK_TYPE
-------------------------------------------------------------------------------
tpm_ek_type_activate = (0x0001 :: Word16)
tpm_ek_type_auth = (0x0002 :: Word16)

-------------------------------------------------------------------------------
-- TPM capability flags
-- Type: TPM_CAPABILITY_AREA
-- TPM Func: TPM_GetCapability
-------------------------------------------------------------------------------
tpm_cap_ord = (0x0\0000001 :: Word32)
tpm_cap_alg = (0x00000002 :: Word32)
tpm_cap_pid = (0x00000003 :: Word32)
tpm_cap_flag = (0x00000004 :: Word32)
-------------------------------------------------------------------------------
-- TPM sub capability flags for tpm_cap_flag
tpm_cap_flag_permanent = (0x00000108 :: Word32)
tpm_cap_flag_volatile = (0x00000109 :: Word32)
-------------------------------------------------------------------------------

tpm_cap_property = (0x00000005 :: Word32)
tpm_cap_version = (0x00000006 :: Word32)
tpm_cap_key_handle = (0x00000007 :: Word32)
tpm_cap_check_loaded = (0x00000008 :: Word32)
tpm_cap_sym_mode = (0x00000009 :: Word32)
tpm_cap_key_status = (0x0000000c :: Word32)
tpm_cap_nv_list = (0x0000000d :: Word32)
tpm_cap_mfr = (0x00000010 :: Word32)
tpm_cap_nv_index = (0x00000011 :: Word32)
tpm_cap_trans_alg = (0x00000012 :: Word32)
tpm_cap_handle = (0x00000014 :: Word32)
tpm_cap_trans_es = (0x00000015 :: Word32)
tpm_cap_auth_encrypt = (0x00000017 :: Word32)
tpm_cap_select_size = (0x00000018 :: Word32)
tpm_cap_da_logic = (0x00000019 :: Word32)
tpm_cap_version_val = (0x0000001a :: Word32)

-------------------------------------------------------------------------------
-- TPM capability flags
-- Type: TPM_CAPABILITY_AREA
-- TPM Func: TPM_SetCapability
-------------------------------------------------------------------------------
tpm_set_perm_flags = (0x00000001 :: Word32)
tpm_set_perm_data = (0x00000002 :: Word32)
tpm_set_stclear_flags = (0x00000003 :: Word32)
tpm_set_stclear_data = (0x00000004 :: Word32)
tpm_set_stany_flags = (0x00000005 :: Word32)
tpm_set_stany_data = (0x00000006 :: Word32)
tpm_set_vendor = (0x00000007 :: Word32)

-------------------------------------------------------------------------------
-- TPM sub capability flags (is this the best description??)
-- Type: TPM_PERMANENT_FLAGS
-- TPM Func: TPM_SetCapability
-------------------------------------------------------------------------------
tpm_pf_readsrkpub = (17 :: Word32)
tpm_pf_disablefulldalogicinfo = (20 :: Word32)
tpm_af_tospresent = (4 :: Word32)
tpm_sd_deferredphysicalpresence = (6 :: Word32)
tpm_pd_daaproof = (25 :: Word32)

-------------------------------------------------------------------------------
-- TPM localities as defined by section 8.6 of the document:
--  TPM Main: Part 2 - TPM Structures
-- Type: TPM_LOCALITY_SELECTION
-------------------------------------------------------------------------------
tpm_loc_four = (0x10 :: Word8)
tpm_loc_three = (0x08 :: Word8)
tpm_loc_two = (0x04 :: Word8)
tpm_loc_one = (0x02 :: Word8)
tpm_loc_zero = (0x01 :: Word8)

-------------------------------------------------------------------------------
-- TPM key control values as defined by section 10.9 of the document:
--  TPM Main: Part 2 - TPM Structures
-- Type: TPM_KEY_CONTROL
-------------------------------------------------------------------------------
tpm_key_control_owner_evict = (0x00000001 :: Word32)

-------------------------------------------------------------------------------
-- TPM sub capability flags for tpm_cap_property
-- Type: TPM_CAP_PROPERTY
-- TPM Func: TPM_GetCapability
-------------------------------------------------------------------------------
tpm_cap_prop_pcr = (0x00000101 :: Word32)
tpm_cap_prop_dir = (0x00000102 :: Word32)
tpm_cap_prop_manufacturer = (0x00000103 :: Word32)
tpm_cap_prop_keys = (0x00000104 :: Word32)
tpm_cap_prop_min_counter = (0x00000107 :: Word32)
tpm_cap_prop_authsess = (0x0000010a :: Word32)
tpm_cap_prop_transess = (0x0000010b :: Word32)
tpm_cap_prop_counters = (0x0000010c :: Word32)
tpm_cap_prop_max_authsess = (0x0000010d :: Word32)
tpm_cap_prop_max_transess = (0x0000010e :: Word32)
tpm_cap_prop_max_counters = (0x0000010f :: Word32)
tpm_cap_prop_max_keys = (0x00000110 :: Word32)
tpm_cap_prop_owner = (0x00000111 :: Word32)
tpm_cap_prop_context = (0x00000112 :: Word32)
tpm_cap_prop_max_context = (0x00000113 :: Word32)
tpm_cap_prop_familyrows = (0x00000114 :: Word32)
tpm_cap_prop_tis_timeout = (0x00000115 :: Word32)
tpm_cap_prop_startup_effect = (0x00000116 :: Word32)
tpm_cap_prop_delegate_row = (0x00000117 :: Word32)
tpm_cap_prop_max_daasess = (0x00000119 :: Word32)
tpm_cap_prop_daasess = (0x0000011a :: Word32)
tpm_cap_prop_context_dist = (0x0000011b :: Word32)
tpm_cap_prop_daa_interrupt = (0x0000011c :: Word32)
tpm_cap_prop_sessions = (0x0000011d :: Word32)
tpm_cap_prop_max_sessions = (0x0000011e :: Word32)
tpm_cap_prop_cmk_restriction = (0x0000011f :: Word32)
tpm_cap_prop_duration = (0x00000120 :: Word32)
tpm_cap_prop_active_counter = (0x00000122 :: Word32)
tpm_cap_prop_max_nv_available = (0x00000123 :: Word32)
tpm_cap_prop_input_buffer = (0x00000124 :: Word32)

-------------------------------------------------------------------------------
-- TPM key usage values as defined by section 5.8 of the document:
--  TPM Main: Part 2 - TPM Structures
-- Type: TPM_KEY_USAGE
-------------------------------------------------------------------------------
tpm_key_signing = (0x0010 :: Word16)
tpm_key_storage = (0x0011 :: Word16)
tpm_key_identity = (0x0012 :: Word16)
tpm_key_authchange = (0x0013 :: Word16)
tpm_key_bind = (0x0014 :: Word16)
tpm_key_legacy = (0x0015 :: Word16)
tpm_key_migrate = (0x0016 :: Word16)
-- Why??
tpm_key_names = [ (tpm_key_signing, "Signing")
                , (tpm_key_storage, "Storage")
                , (tpm_key_storage, "Identification")
                , (tpm_key_storage, "Authentication Change")
                , (tpm_key_storage, "Binding")
                , (tpm_key_storage, "Legacy Usage")
                , (tpm_key_storage, "Migration")
                , (tpm_key_identity, "Identity") ]
tpm_key_getname k = case lookup k tpm_key_names of
                        Nothing -> "Unknown Key Usage"
                        Just x  -> x

-------------------------------------------------------------------------------
-- TPM encryption schemes as defined by section 5.8.1 of the document:
--  TPM Main: Part 2 - TPM Structures
-- Type: TPM_ENC_SCHEME
-------------------------------------------------------------------------------
tpm_es_none = (0x0001 :: Word16)
tpm_es_rsaespkcsv15 = (0x0002 :: Word16)
tpm_es_rsaesoaep_sha1_mgf1 = (0x0003 :: Word16)
tpm_es_sym_ctr = (0x0004 :: Word16)
tpm_es_sym_ofb = (0x0005 :: Word16)
tpm_es_names = [ (tpm_es_none, "none")
               , (tpm_es_rsaespkcsv15, "RSA")
               , (tpm_es_rsaesoaep_sha1_mgf1, "RSA SHA-1 MGF1")
               , (tpm_es_sym_ctr, "SYM CTR")
               , (tpm_es_sym_ofb, "SYM OFB") ]
tpm_es_getname es = case lookup es tpm_es_names of
                        Nothing -> "Unknown Encryption Scheme"
                        Just x  -> x

-------------------------------------------------------------------------------
-- TPM signature schemes as defined by section 5.8.1 of the document:
--  TPM Main: Part 2 - TPM Structures
-- Type: TPM_SIG_SCHEME
-------------------------------------------------------------------------------
tpm_ss_none = (0x0001 :: Word16)
tpm_ss_rsassapkcs1v15_sha1 = (0x0002 :: Word16)
tpm_ss_rsassapkcs1v15_der = (0x0003 :: Word16)
tpm_ss_rsassapkcs1v15_info = (0x0004 :: Word16)
tpm_ss_names = [ (tpm_ss_none, "none")
               , (tpm_ss_rsassapkcs1v15_sha1, "RSA SHA-1")
               , (tpm_ss_rsassapkcs1v15_der, "RSA DER")
               , (tpm_ss_rsassapkcs1v15_info, "RSA INFO") ]
tpm_ss_getname ss = case lookup ss tpm_ss_names of
                        Nothing -> "Unknown Signature Scheme"
                        Just x  -> x

-------------------------------------------------------------------------------
-- TPM authentication values as defined by section 5.9 of the document:
--  TPM Main: Part 2 - TPM Structures
-- Type: TPM_AUH_DATA_USAGE
-------------------------------------------------------------------------------
tpm_auth_never = (0x00 :: Word8)
tpm_auth_always = (0x01 :: Word8)
tpm_auth_priv_use_only = (0x03 :: Word8)
tpm_auth_names = [ (tpm_auth_never, "Never Authenticate")
                 , (tpm_auth_always, "Always Authenticate")
                 , (tpm_auth_priv_use_only, "Authenticate Private Key Usage") ]
tpm_auth_getname auth = case lookup auth tpm_auth_names of
                            Nothing -> "Unknown Authetication Requirements"
                            Just x  -> x

-------------------------------------------------------------------------------
-- TPM key flags as defined by section 5.10 of the document:
--  TPM Main: Part 2 - TPM Structures
-- Type: TPM_KEY_FLAGS
-------------------------------------------------------------------------------
tpm_kf_redirection = (0x00000001 :: Word32)
tpm_kf_migratable = (0x00000002 :: Word32)
tpm_kf_isvolatile = (0x00000004 :: Word32)
tpm_kf_pcrignoredonread = (0x00000008 :: Word32)
tpm_kf_migrateauthority = (0x00000010 :: Word32)
tpm_kf_names = [ (tpm_kf_redirection, "[REDIR]")
               , (tpm_kf_migratable, "[MIG]")
               , (tpm_kf_isvolatile, "[VOL]")
               , (tpm_kf_pcrignoredonread, "[PCR IGN]")
               , (tpm_kf_migrateauthority, "[MIG AUTH]") ]
tpm_kf_getname kf = unwords $ filter (/= "") [ lu tpm_kf_redirection
                                             , lu tpm_kf_migratable
                                             , lu tpm_kf_isvolatile
                                             , lu tpm_kf_pcrignoredonread
                                             , lu tpm_kf_migrateauthority ]
    where lu kfc = case lookup (kf .&. kfc) tpm_kf_names of
                     Nothing -> ""
                     Just x  -> x

-------------------------------------------------------------------------------
-- TPM CMK delegate values as defined by section 5.17 of the document:
--  TPM Main: Part 2 - TPM Structures
-- Type: iTPM_CMK_DELEGATE
-------------------------------------------------------------------------------
tpm_cmk_delegate_signing = (0x80000000 :: Word32)
tpm_cmk_delegate_storage = (0x40000000 :: Word32)
tpm_cmk_delegate_bind = (0x20000000 :: Word32)
tpm_cmk_delegate_legacy = (0x10000000 :: Word32)
tpm_cmk_delegate_migrate = (0x08000000 :: Word32)


-------------------------------------------------------------------------------
-- TPM delegate types as defiend by section 20.2 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
tpm_del_owner_bits = (0x00000001 :: Word32)
tpm_del_key_bits = (0x00000002 :: Word32)

-------------------------------------------------------------------------------
-- TPM delegate permissions as defiend by section 20.2.1 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
tpm_delegate_setordinalauditstatus = (0x40000000 :: Word32)
tpm_delegate_dirwriteauth = (0x20000000 :: Word32)
tpm_delegate_cmk_approvema = (0x10000000 :: Word32)
tpm_delegate_nv_writevalue = (0x08000000 :: Word32)
tpm_delegate_cmk_createticket = (0x04000000 :: Word32)
tpm_delegate_nv_readvalue = (0x02000000 :: Word32)
tpm_delegate_delegate_loadownerdelegation = (0x01000000 :: Word32)
tpm_delegate_daa_join = (0x00800000 :: Word32)
tpm_delegate_authorizemigrationkey = (0x00400000 :: Word32)
tpm_delegate_createmaintenancearchive = (0x00200000 :: Word32)
tpm_delegate_loadmaintenancearchive = (0x00100000 :: Word32)
tpm_delegate_killmaintenancefeature = (0x00080000 :: Word32)
tpm_delegate_ownerreadinternalpub = (0x00040000 :: Word32)
tpm_delegate_resetlockvalue = (0x00020000 :: Word32)
tpm_delegate_ownerclear = (0x00010000 :: Word32)
tpm_delegate_disableownerclear = (0x00008000 :: Word32)
tpm_delegate_nv_definespace = (0x00004000 :: Word32)
tpm_delegate_ownersetdisable = (0x00002000 :: Word32)
tpm_delegate_setcapability = (0x00001000 :: Word32)
tpm_delegate_makeidentity = (0x00000800 :: Word32)
tpm_delegate_activateidentity = (0x00000400 :: Word32)
tpm_delegate_ownerreadpubek = (0x00000200 :: Word32)
tpm_delegate_disablepubekread = (0x00000100 :: Word32)
tpm_delegate_setredirection = (0x00000080 :: Word32)
tpm_delegate_fieldupgrade = (0x00000040 :: Word32)
tpm_delegate_delegate_updateverification = (0x00000020 :: Word32)
tpm_delegate_createcounter = (0x00000010 :: Word32)
tpm_delegate_releasecounterowner = (0x00000008 :: Word32)
tpm_delegate_delegate_manage = (0x00000004 :: Word32)
tpm_delegate_delegate_createownerdelegation = (0x00000002 :: Word32)
tpm_delegate_daa_sign = (0x00000001 :: Word32)

-------------------------------------------------------------------------------
-- TPM family flags as defiend by section 20.3 of the document:
--  TPM Main: Part 2 - TPM Structures
-- Type: TPM_FAMILY_FLAG
-------------------------------------------------------------------------------
tpm_delegate_admin_lock = (0x00000002 :: Word32)
tpm_famflag_enabled = (0x00000001 :: Word32)

-------------------------------------------------------------------------------
-- TPM fatal error codes as defined by section 16 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
tpm_base = (0x0 :: Word32)
tpm_success = (tpm_base :: Word32)
tpm_non_fatal = (0x00000800 :: Word32)
tpm_authfail = tpm_base + 1
tpm_badindex = tpm_base + 2
tpm_bad_parameter = tpm_base + 3
tpm_auditfailure = tpm_base + 4
tpm_clear_disabled = tpm_base + 5
tpm_deactivated = tpm_base + 6
tpm_disabled = tpm_base + 7
tpm_disabled_cmd = tpm_base + 8
tpm_fail = tpm_base + 9
tpm_bad_ordinal = tpm_base + 10
tpm_install_disabled = tpm_base + 11
tpm_invalid_keyhandle = tpm_base + 12
tpm_keynotfound = tpm_base + 13
tpm_inappropriate_enc = tpm_base + 14
tpm_migratefail = tpm_base + 15
tpm_invalid_pcr_info = tpm_base + 16
tpm_nospace = tpm_base + 17
tpm_nosrk = tpm_base + 18
tpm_notsealed_blob = tpm_base + 19
tpm_owner_set = tpm_base + 20
tpm_resources = tpm_base + 21
tpm_shortrandom = tpm_base + 22
tpm_size = tpm_base + 23
tpm_wrongpcrval = tpm_base + 24
tpm_bad_param_size = tpm_base + 25
tpm_sha_thread = tpm_base + 26
tpm_sha_error = tpm_base + 27
tpm_failedselftest = tpm_base + 28
tpm_auth2fail = tpm_base + 29
tpm_badtag = tpm_base + 30
tpm_ioerror = tpm_base + 31
tpm_encrypt_error = tpm_base + 32
tpm_decrypt_error = tpm_base + 33
tpm_invalid_authhandle = tpm_base + 34
tpm_no_endorsement = tpm_base + 35
tpm_invalid_keyusage = tpm_base + 36
tpm_wrong_entitytype = tpm_base + 37
tpm_invalid_postinit = tpm_base + 38
tpm_inappropriate_sig = tpm_base + 39
tpm_bad_key_property = tpm_base + 40
tpm_bad_migration = tpm_base + 41
tpm_bad_scheme = tpm_base + 42
tpm_bad_datasize = tpm_base + 43
tpm_bad_mode = tpm_base + 44
tpm_bad_presence = tpm_base + 45
tpm_bad_version = tpm_base + 46
tpm_no_wrap_transport = tpm_base + 47
tpm_auditfail_unsuccessful = tpm_base + 48
tpm_auditfail_successful = tpm_base + 49
tpm_notresetable = tpm_base + 50
tpm_notlocal = tpm_base + 51
tpm_bad_type = tpm_base + 52
tpm_invalid_resource = tpm_base + 53
tpm_notfips = tpm_base + 54
tpm_invalid_family = tpm_base + 55
tpm_no_nv_permission = tpm_base + 56
tpm_requires_sign = tpm_base + 57
tpm_key_notsupported = tpm_base + 58
tpm_auth_conflict = tpm_base + 59
tpm_area_locked = tpm_base + 60
tpm_bad_locality = tpm_base + 61
tpm_read_only = tpm_base + 62
tpm_per_nowrite = tpm_base + 63
tpm_familycount = tpm_base + 64
tpm_write_locked = tpm_base + 65
tpm_bad_attributes = tpm_base + 66
tpm_invalid_structure = tpm_base + 67
tpm_key_owner_control = tpm_base + 68
tpm_bad_counter = tpm_base + 69
tpm_not_fullwrite = tpm_base + 70
tpm_context_gap = tpm_base + 71
tpm_maxnvwrites = tpm_base + 72
tpm_nooperator = tpm_base + 73
tpm_resourcemissing = tpm_base +74
tpm_delegate_lock = tpm_base + 75
tpm_delegate_family = tpm_base + 76
tpm_delegate_admin = tpm_base + 77
tpm_transport_notexclusive = tpm_base + 78
tpm_owner_control = tpm_base + 79
tpm_daa_resources = tpm_base + 80
tpm_daa_input_data0 = tpm_base + 81
tpm_daa_input_data1 = tpm_base + 82
tpm_daa_issuer_settings = tpm_base + 83
tpm_daa_tpm_settings = tpm_base + 84
tpm_daa_stage = tpm_base + 85
tpm_daa_issuer_validity = tpm_base + 86
tpm_daa_wrong_w = tpm_base + 87
tpm_bad_handle = tpm_base + 88
tpm_bad_delegate = tpm_base + 89
tpm_badcontext = tpm_base + 90
tpm_toomanycontexts = tpm_base + 91
tpm_ma_ticket_signature = tpm_base + 92
tpm_ma_destination = tpm_base + 93
tpm_ma_source = tpm_base + 94
tpm_ma_authority = tpm_base + 95
tpm_permanentek = tpm_base + 97
tpm_bad_signature = tpm_base + 98
tpm_nocontextspace = tpm_base + 99

-------------------------------------------------------------------------------
-- TPM non-fatal error codes as defined by section 16 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
tpm_retry = tpm_base + tpm_non_fatal
tpm_needs_selftest = tpm_base + tpm_non_fatal + 1
tpm_doing_selftest = tpm_base + tpm_non_fatal + 2
tpm_defend_lock_running = tpm_base + tpm_non_fatal + 3

-------------------------------------------------------------------------------
-- TPM command codes as defined by section 17 of the document:
--  TPM Main: Part 2 - TPM Structures
-- Type: TPM_COMMAND_CODE
-------------------------------------------------------------------------------
tpm_ord_activateidentity = (0x0000007a :: Word32)
tpm_ord_authorizemigrationkey = (0x0000002b :: Word32)
tpm_ord_certifykey = (0x00000032 :: Word32)
tpm_ord_certifykey2 = (0x00000033 :: Word32)
tpm_ord_certifyselft est = (0x00000052 :: Word32)
tpm_ord_changeauth = (0x0000000c :: Word32)
tpm_ord_changeauthasymfinish = (0x0000000f :: Word32)
tpm_ord_changeauthasymstart = (0x0000000e :: Word32)
tpm_ord_changeauthowner = (0x00000010 :: Word32)
tpm_ord_cmk_approvema = (0x0000001d :: Word32)
tpm_ord_cmk_convertmigration = (0x00000024 :: Word32)
tpm_ord_cmk_createblob = (0x0000001b :: Word32)
tpm_ord_cmk_createkey = (0x00000013 :: Word32)
tpm_ord_cmk_createticket = (0x00000012 :: Word32)
tpm_ord_cmk_setrestrictions = (0x0000001c :: Word32)
tpm_ord_continueselftest = (0x00000053 :: Word32)
tpm_ord_convertmigrationblob = (0x0000002a :: Word32)
tpm_ord_createcounter = (0x000000dc :: Word32)
tpm_ord_createendorsementkeypair = (0x00000078 :: Word32)
tpm_ord_createmaintenancearchive = (0x0000002c :: Word32)
tpm_ord_createmigrationblob = (0x00000028 :: Word32)
tpm_ord_createrevocableek = (0x0000007f :: Word32)
tpm_ord_createwrapkey = (0x0000001f :: Word32)
tpm_ord_daa_join = (0x00000029 :: Word32)
tpm_ord_daa_sign = (0x00000031 :: Word32)
tpm_ord_delegate_createkeydelegation = (0x000000d4 :: Word32)
tpm_ord_delegate_createownerdelegation = (0x000000d5 :: Word32)
tpm_ord_delegate_loadownerdelegation = (0x000000d8 :: Word32)
tpm_ord_delegate_manage = (0x000000d2 :: Word32)
tpm_ord_delegate_readtable = (0x000000db :: Word32)
tpm_ord_delegate_updateverification = (0x000000d1 :: Word32)
tpm_ord_delegate_verifydelegation = (0x000000d6 :: Word32)
tpm_ord_dirread = (0x0000001a :: Word32)
tpm_ord_dirwriteauth = (0x00000019 :: Word32)
tpm_ord_disableforceclear = (0x0000005e :: Word32)
tpm_ord_disableownerclear = (0x0000005c :: Word32)
tpm_ord_disablepubekread = (0x0000007e :: Word32)
tpm_ord_dsap = (0x00000011 :: Word32)
tpm_ord_establishtransport = (0x000000e6 :: Word32)
tpm_ord_evictkey = (0x00000022 :: Word32)
tpm_ord_executetransport = (0x000000e7 :: Word32)
tpm_ord_extend = (0x00000014 :: Word32)
tpm_ord_fieldupgrade = (0x000000aa :: Word32)
tpm_ord_flushspecific = (0x000000ba :: Word32)
tpm_ord_forceclear = (0x0000005d :: Word32)
tpm_ord_getauditdigest = (0x00000085 :: Word32)
tpm_ord_getauditdigestsigned = (0x00000086 :: Word32)
tpm_ord_getauditevent = (0x00000082 :: Word32)
tpm_ord_getauditeventsigned = (0x00000083 :: Word32)
tpm_ord_getcapability = (0x00000065 :: Word32)
tpm_ord_getcapabilityowner = (0x00000066 :: Word32)
tpm_ord_getcapabilitysigned = (0x00000064 :: Word32)
tpm_ord_getordinalauditstatus = (0x0000008c :: Word32)
tpm_ord_getpubkey = (0x00000021 :: Word32)
tpm_ord_getrandom = (0x00000046 :: Word32)
tpm_ord_gettestresult = (0x00000054 :: Word32)
tpm_ord_getticks = (0x000000f1 :: Word32)
tpm_ord_incrementcounter = (0x000000dd :: Word32)
tpm_ord_init = (0x00000097 :: Word32)
tpm_ord_keycontrolowner = (0x00000023 :: Word32)
tpm_ord_killmaintenancefeature = (0x0000002e :: Word32)
tpm_ord_loadauthcontext = (0x000000b7 :: Word32)
tpm_ord_loadcontext = (0x000000b9 :: Word32)
tpm_ord_loadkey = (0x00000020 :: Word32)
tpm_ord_loadkey2 = (0x00000041 :: Word32)
tpm_ord_loadkeycontext = (0x000000b5 :: Word32)
tpm_ord_loadmaintenancearchive = (0x0000002d :: Word32)
tpm_ord_loadmanumaintpub = (0x0000002f :: Word32)
tpm_ord_makeidentity = (0x00000079 :: Word32)
tpm_ord_migratekey = (0x00000025 :: Word32)
tpm_ord_nv_definespace = (0x000000cc :: Word32)
tpm_ord_nv_readvalue = (0x000000cf :: Word32)
tpm_ord_nv_readvalueauth = (0x000000d0 :: Word32)
tpm_ord_nv_writevalue = (0x000000cd :: Word32)
tpm_ord_nv_writevalueauth = (0x000000ce :: Word32)
tpm_ord_oiap = (0x0000000a :: Word32)
tpm_ord_osap = (0x0000000b :: Word32)
tpm_ord_ownerclear = (0x0000005b :: Word32)
tpm_ord_ownerreadinternalpub = (0x00000081 :: Word32)
tpm_ord_ownerreadpubek = (0x0000007d :: Word32)
tpm_ord_ownersetdisable = (0x0000006e :: Word32)
tpm_ord_pcr_reset = (0x000000c8 :: Word32)
tpm_ord_pcrread = (0x00000015 :: Word32)
tpm_ord_physicaldisable = (0x00000070 :: Word32)
tpm_ord_physicalenable = (0x0000006f :: Word32)
tpm_ord_physicalsetdeactivated = (0x00000072 :: Word32)
tpm_ord_quote = (0x00000016 :: Word32)
tpm_ord_quote2 = (0x0000003e :: Word32)
tpm_ord_readcounter = (0x000000de :: Word32)
tpm_ord_readmanumaintpub = (0x00000030 :: Word32)
tpm_ord_readpubek = (0x0000007c :: Word32)
tpm_ord_releasecounter = (0x000000df :: Word32)
tpm_ord_releasecounterowner = (0x000000e0 :: Word32)
tpm_ord_releasetransportsigned = (0x000000e8 :: Word32)
tpm_ord_reset = (0x0000005a :: Word32)
tpm_ord_resetlockvalue = (0x00000040 :: Word32)
tpm_ord_revoketrust = (0x00000080 :: Word32)
tpm_ord_saveauthcontext = (0x000000b6 :: Word32)
tpm_ord_savecontext = (0x000000b8 :: Word32)
tpm_ord_savekeycontext = (0x000000b4 :: Word32)
tpm_ord_savestate = (0x00000098 :: Word32)
tpm_ord_seal = (0x00000017 :: Word32)
tpm_ord_sealx = (0x0000003d :: Word32)
tpm_ord_selftestfull = (0x00000050 :: Word32)
tpm_ord_setcapability = (0x0000003f :: Word32)
tpm_ord_setoperatorauth = (0x00000074 :: Word32)
tpm_ord_setordinalauditstatus = (0x0000008d :: Word32)
tpm_ord_setownerinstall = (0x00000071 :: Word32)
tpm_ord_setownerpointer = (0x00000075 :: Word32)
tpm_ord_setredirection = (0x0000009a :: Word32)
tpm_ord_settempdeactivated = (0x00000073 :: Word32)
tpm_ord_sha1complete = (0x000000a2 :: Word32)
tpm_ord_sha1completeextend = (0x000000a3 :: Word32)
tpm_ord_sha1start = (0x000000a0 :: Word32)
tpm_ord_sha1update = (0x000000a1 :: Word32)
tpm_ord_sign = (0x0000003c :: Word32)
tpm_ord_startup = (0x00000099 :: Word32)
tpm_ord_stirrandom = (0x00000047 :: Word32)
tpm_ord_takeownership = (0x0000000d :: Word32)
tpm_ord_terminate_handle = (0x00000096 :: Word32)
tpm_ord_tickstampblob = (0x000000f2 :: Word32)
tpm_ord_unbind = (0x0000001e :: Word32)
tpm_ord_unseal = (0x00000018 :: Word32)
tsc_ord_physicalpresence = (0x4000000A :: Word32)
tsc_ord_resetestablishmentbit = (0x4000000B :: Word32)
