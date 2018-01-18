{-# LANGUAGE FlexibleContexts, UndecidableInstances, RecordWildCards, OverloadedStrings#-}

module TPM.Types where
import TPM.Utils
import TPM.Const
import Data.Word
import Data.Bits
import Data.Char(ord)
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteString.Lazy hiding (putStrLn,map,reverse)
import qualified Data.ByteString as B (ByteString)
import qualified Data.ByteString.Lazy.Char8 as C (pack)
import Control.Monad
import Control.Exception
import Prelude hiding (take,length)
import qualified Prelude as P

-------------------------------------------------------------------------------
-- Basic data types as defined by section 2.2.1 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
type BOOL   = Bool
type BYTE   = Word8
type UINT16 = Word16
type UINT32 = Word32
type UINT64 = Word64

-------------------------------------------------------------------------------
-- Helper definitions which are not directly defined in the TPM
-- specification but which are informative none the less.
-------------------------------------------------------------------------------
type NIBBLE = Word8 -- Should be Word4 but this type does not exist

-------------------------------------------------------------------------------
-- TPM helper definitions as defined by section 2.2.3 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
type TPM_AUTH_DATA_USAGE = BYTE
type TPM_PAYLOAD_TYPE = BYTE
-- type TPM_VERSION_BYTE = BYTE
type TPM_DA_STATE = BYTE
type TPM_TAG = UINT16
type TPM_PROTOCOL_ID = UINT16
type TPM_STARTUP_TYPE = UINT16
type TPM_ENC_SCHEME = UINT16
type TPM_SIG_SCHEME = UINT16
type TPM_MIGRATE_SCHEME = UINT16
type TPM_PHYSICAL_PRESENCE = UINT16
type TPM_ENTITY_TYPE = UINT16
type TPM_KEY_USAGE = UINT16
type TPM_EK_TYPE = UINT16
type TPM_STRUCTURE_TAG = UINT16
type TPM_PLATFORM_SPECIFIC = UINT16
type TPM_COMMAND_CODE = UINT32
type TPM_CAPABILITY_AREA = UINT32
type TPM_KEY_FLAGS = UINT32
type TPM_ALGORITHM_ID = UINT32
type TPM_MODIFIER_INDICATOR = UINT32
type TPM_ACTUAL_COUNT = UINT32
type TPM_TRANSPORT_ATTRIBUTES = UINT32
type TPM_AUTHHANDLE = UINT32
type TPM_DIRINDEX = UINT32
type TPM_KEY_HANDLE = UINT32
type TPM_PCRINDEX = UINT32
type TPM_RESULT = UINT32
type TPM_RESOURCE_TYPE = UINT32
type TPM_KEY_CONTROL = UINT32
type TPM_NV_INDEX = UINT32
type TPM_FAMILY_ID = UINT32
type TPM_FAMILY_VERIFICATION = UINT32
-- type TPM_STARTUP_EFFECTS = UINT32
type TPM_SYM_MODE = UINT32
type TPM_FAMILY_FLAGS = UINT32
type TPM_DELEGATE_INDEX = UINT32
type TPM_CMK_DELEGATE = UINT32
type TPM_COUNT_ID = UINT32
type TPM_REDIT_COMMAND = UINT32
type TPM_TRANSHANDLE = UINT32
type TPM_HANDLE = UINT32
type TPM_FAMILY_OPERATION = UINT32


-- Section 12.8
data TPM_ASYM_CA_CONTENTS = TPM_ASYM_CA_CONTENTS {
  sessKey :: TPM_SYMMETRIC_KEY,
  idDigest :: TPM_DIGEST
  }
     deriving (Eq)

instance Binary TPM_ASYM_CA_CONTENTS where
  put(TPM_ASYM_CA_CONTENTS sym dig) = do
    put sym
    put dig
  get = do
    sym <- get
    dig <- get
    return $ TPM_ASYM_CA_CONTENTS sym dig

-- Section 12.5
data TPM_IDENTITY_CONTENTS = TPM_IDENTITY_CONTENTS {
  labelPrivCADigest :: TPM_CHOSENID_HASH,
  identityPubKey :: TPM_PUBKEY
  }  deriving (Show, Read, Eq)

instance Binary TPM_IDENTITY_CONTENTS where
  put(TPM_IDENTITY_CONTENTS label pubkey) = do
    put tpm_struct_ver_default
    put tpm_ord_makeidentity
    put label
    put pubkey
  get = do
    get :: (Get TPM_STRUCT_VER)
    get :: (Get UINT32)
    label <- get
    pubkey <- get
    return $ TPM_IDENTITY_CONTENTS label pubkey

-------------------------------------------------------------------------------
-- TPM helper aliases as defined throughout the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
type TPM_LOCALITY_SELECTION = BYTE -- Section 8.6
type TPM_FAMILY_LABEL = BYTE -- Section 20.4
type TPM_DELEGATE_LABEL = BYTE -- Section 20.7

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
data Session = OIAP { authHandle :: ByteString
                    , nonceEven  :: TPM_NONCE
                    }
             | OSAP { authHandle    :: ByteString
                    , nonceOddOSAP  :: TPM_NONCE
                    , nonceEven     :: TPM_NONCE
                    , nonceEvenOSAP :: TPM_NONCE
                    , secret        :: TPM_DIGEST
                    }
             deriving (Eq)
instance Show Session where
    show (OIAP a n) = "OIAP Session:\n" ++
                      "    Auth Handle: " ++ (bshex a) ++ "\n" ++
                      "    Even Nonce:  " ++ (show n)
    show (OSAP a o e s k) = "OSAP Session:\n" ++
                            "    Auth Handle:     "++(bshex a)++"\n"++
                            "    Even Nonce:      "++(show e)++"\n"++
                            "    Odd OSAP Nonce:  "++(show o)++"\n"++
                            "    Even OSAP Nonce: "++(show s)++"\n"++
                            "    Secret Hash:     "++(show k)

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
data TPMDuration = TPMDuration { small :: Integer
                               , medium :: Integer
                               , large :: Integer
                               } deriving (Show,Eq)

-------------------------------------------------------------------------------
-- TPM startup effects as defined by section 4.6 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_STARTUP_EFFECTS = TPM_STARTUP_EFFECTS {
      contextInit :: BOOL
    , transInit :: BOOL
    , hashInit :: BOOL
    , authInit :: BOOL
    , auditDigestClearedAll :: BOOL
    , auditDigestCleared :: BOOL
    , auditDigestClearedNone :: BOOL
    , daaInit :: BOOL
    } deriving (Show,Eq)

instance Binary TPM_STARTUP_EFFECTS where
    put (TPM_STARTUP_EFFECTS ci ti hi ai aa ad an di) = do
        put (ci' .|. ti' .|. hi' .|. ai' .|. aa' .|. ad' .|. an')
        put di'
        put (0 :: Word8)
        put (0 :: Word8)
        where ci' = if ci then setBit (0 :: Word8) 0 else (0 :: Word8)
              ti' = if ci then setBit (0 :: Word8) 1 else (0 :: Word8)
              hi' = if ci then setBit (0 :: Word8) 2 else (0 :: Word8)
              ai' = if ci then setBit (0 :: Word8) 3 else (0 :: Word8)
              aa' = if ci then setBit (0 :: Word8) 5 else (0 :: Word8)
              ad' = if ci then setBit (0 :: Word8) 6 else (0 :: Word8)
              an' = if ci then setBit (0 :: Word8) 7 else (0 :: Word8)
              di' = if ci then setBit (0 :: Word8) 0 else (0 :: Word8)
    get = do
        b1 <- (get :: Get Word8)
        b2 <- (get :: Get Word8)
        b3 <- (get :: Get Word8)
        b4 <- (get :: Get Word8)
        return $ TPM_STARTUP_EFFECTS (testBit b1 0) (testBit b1 1)
                                     (testBit b1 2) (testBit b1 3)
                                     (testBit b1 5) (testBit b1 6)
                                     (testBit b1 7) (testBit b2 0)

-------------------------------------------------------------------------------
-- TPM version structure as defined by section 5.1 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_STRUCT_VER = TPM_STRUCT_VER {
      tpmStructVerMajor :: BYTE
    , tpmStructVerMinor :: BYTE
    , tpmStructVerRevMajor :: BYTE
    , tpmStructVerRevMinor :: BYTE
    } deriving (Show,Eq)

tpm_struct_ver_default = TPM_STRUCT_VER 0x01 0x01 0x00 0x00

instance Binary TPM_STRUCT_VER where
    put (TPM_STRUCT_VER vmj vmi rmj rmi) = do
        put vmj
        put vmi
        put rmj
        put rmi
    get = do
        vmj <- get
        vmi <- get
        rmj <- get
        rmi <- get
        return $ TPM_STRUCT_VER vmj vmi rmj rmi

-------------------------------------------------------------------------------
-- TPM version bytes as defined by section 5.2 of the document:
--  TPM Main: Part 2 - TPM Structures
--
-- Each of the nibbles in this structure represents a BCD value. Thus is
-- mostSigVersion was 0010 and leastSigVersion was 0011 then the version
-- represented is 23.
-------------------------------------------------------------------------------
newtype TPM_VERSION_BYTE = TPM_VERSION_BYTE BYTE deriving (Eq)
tpm_version (TPM_VERSION_BYTE b) = ((shift b (-4)) * 10) + (b .&. 0xF)


instance Show TPM_VERSION_BYTE where
    show b = show (tpm_version b)

instance Binary TPM_VERSION_BYTE where
    put (TPM_VERSION_BYTE b) = put b
    get = get >>= return . TPM_VERSION_BYTE

-------------------------------------------------------------------------------
-- TPM version bytes as defined by section 5.3 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_VERSION = TPM_VERSION {
      major :: TPM_VERSION_BYTE
    , minor :: TPM_VERSION_BYTE
    , revMajor :: BYTE
    , revMinor :: BYTE
    } deriving (Eq)

instance Show TPM_VERSION where
    show (TPM_VERSION mj mi _ _) = (show mj) ++ "." ++ (show mi)

instance Binary TPM_VERSION where
    put (TPM_VERSION mj mi rmj rmi) = do
        put mj
        put mi
        put rmj
        put rmi
    get = do
        mj <- get
        mi <- get
        rmj <- get
        rmi <- get
        return $ TPM_VERSION mj mi rmj rmi

-------------------------------------------------------------------------------
-- TPM digest as defined by section 5.4 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
newtype TPM_DIGEST = TPM_DIGEST ByteString deriving (Eq, Read, Show)

{-
instance Show TPM_DIGEST where
    show (TPM_DIGEST bs) = bshex bs
-}

instance Binary TPM_DIGEST where
    put (TPM_DIGEST bs) = putLazyByteString bs
    get = getLazyByteString 20 >>= return . TPM_DIGEST

-------------------------------------------------------------------------------
-- TPM digest aliases as defined by section 5.4 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
type TPM_CHOSENID_HASH = TPM_DIGEST
type TPM_COMPOSITE_HASH = TPM_DIGEST
type TPM_DIRVALUE = TPM_DIGEST
type TPM_HMAC = TPM_DIGEST
type TPM_PCRVALUE = TPM_DIGEST
type TPM_AUDITDIGEST = TPM_DIGEST

-------------------------------------------------------------------------------
-- TPM nonce as defined by section 5.5 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
newtype TPM_NONCE = TPM_NONCE ByteString deriving (Eq)

instance Show TPM_NONCE where
    show (TPM_NONCE bs) = bshex bs

instance Binary TPM_NONCE where
    put (TPM_NONCE bs) = putLazyByteString bs
    get = getLazyByteString 20 >>= return . TPM_NONCE

-------------------------------------------------------------------------------
-- TPM nonce aliases as defined by section 5.5 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
type TPM_DAA_TPM_SEED = TPM_NONCE
type TPM_DAA_CONTEXT_SEED = TPM_NONCE

-------------------------------------------------------------------------------
-- TPM authentication data as defined by section 5.6 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
newtype TPM_AUTHDATA = TPM_AUTHDATA ByteString deriving (Eq)

instance Show TPM_AUTHDATA where
    show (TPM_AUTHDATA bs) = bshex bs

instance Binary TPM_AUTHDATA where
    put (TPM_AUTHDATA bs) = putLazyByteString bs
    get = getLazyByteString 20 >>= return . TPM_AUTHDATA

-------------------------------------------------------------------------------
-- TPM authentication data aliases as defined by section 5.6 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
type TPM_SECRET = TPM_AUTHDATA
type TPM_ENCAUTH = TPM_AUTHDATA

-------------------------------------------------------------------------------
-- TPM key handle lists as defined by section 5.7 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_KEY_HANDLE_LIST = TPM_KEY_HANDLE_LIST {
      tpmKeyHandles :: [TPM_KEY_HANDLE]
    } deriving (Eq)

instance Show TPM_KEY_HANDLE_LIST where
    show (TPM_KEY_HANDLE_LIST handles) = unwords (map showit handles)
        where showit a = "0x" ++ mkhex a

instance Binary TPM_KEY_HANDLE_LIST where
    put (TPM_KEY_HANDLE_LIST l) = do
        put ((fromIntegral $ P.length l) :: UINT16)
        mapM_ put l
    get = do
        num <- (get :: Get UINT16)
        lst <- replicateM (fromIntegral num) get
        return $ TPM_KEY_HANDLE_LIST lst


-------------------------------------------------------------------------------
-- TPM change auth structure as defined by section 5.11 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_CHANGEAUTH_VALIDATE = TPM_CHANGEAUTH_VALIDATE {
      tpmChangeAuthValidateSecret :: TPM_SECRET
    , tpmChangeAuthValidateNonce  :: TPM_NONCE
    } deriving (Show,Eq)

instance Binary TPM_CHANGEAUTH_VALIDATE where
    put (TPM_CHANGEAUTH_VALIDATE vs vn) = put vs >> put vn
    get = get >>= \vs -> get >>= \vn -> return $ TPM_CHANGEAUTH_VALIDATE vs vn

-------------------------------------------------------------------------------
-- TPM migration auth structure as defined by section 5.12 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_MIGRATIONKEYAUTH = TPM_MIGRATIONKEYAUTH {
      tpmMigrationKeyAuthKey    :: TPM_PUBKEY
    , tpmMigrationKeyAuthScheme :: TPM_MIGRATE_SCHEME
    , tpmMigrationKeyAuthDigest :: TPM_DIGEST
    } deriving (Show,Eq)

instance Binary TPM_MIGRATIONKEYAUTH where
    put (TPM_MIGRATIONKEYAUTH ak as ad) = do
        put ak
        put as
        put ad
    get = do
        ak <- get
        as <- get
        ad <- get
        return $ TPM_MIGRATIONKEYAUTH ak as ad

-------------------------------------------------------------------------------
-- TPM counter value structure as defined by section 5.13 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_COUNTER_VALUE = TPM_COUNTER_VALUE {
      tpmCounterValueTag   :: TPM_STRUCTURE_TAG
    , tpmCounterValueLabel :: Word32
    , tpmCounterValueCount :: TPM_ACTUAL_COUNT
    } deriving (Show,Eq)

instance Binary TPM_COUNTER_VALUE where
    put (TPM_COUNTER_VALUE t l c) = do
        put t
        put l
        put c
    get = do
        t <- get
        l <- get
        c <- get
        return $ TPM_COUNTER_VALUE t l c

-------------------------------------------------------------------------------
-- TPM sign info structure as defined by section 5.14 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_SIGN_INFO = TPM_SIGN_INFO {
      tpmSignInfoTag    :: TPM_STRUCTURE_TAG
    , tpmSignInfoFixed  :: Word32
    , tpmSignInfoReplay :: TPM_NONCE
    , tpmSignInfoData   :: ByteString
    } deriving (Show,Eq)

instance Binary TPM_SIGN_INFO where
    put (TPM_SIGN_INFO t f r d) = do
        put t
        put f
        put r
        put ((fromIntegral $ length d) :: Word32)
        putLazyByteString d
    get = do
        t <- get
        f <- get
        r <- get
        num <- (get :: Get Word32)
        d <- getLazyByteString (fromIntegral num)
        return $ TPM_SIGN_INFO t f r d

-------------------------------------------------------------------------------
-- TPM quote info structure as defined by section 11.3 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_QUOTE_INFO = TPM_QUOTE_INFO {
      tpmQuoteInfoCompHash :: TPM_COMPOSITE_HASH
    , tpmQuoteInfoExData   :: TPM_NONCE
    } deriving (Show,Eq)

--TODO:  is this instance necessary since all components implement Binary?
instance Binary TPM_QUOTE_INFO where
    put (TPM_QUOTE_INFO c d) = do
        put tpm_struct_ver_default
        put tpm_quote_info_fixed
        put c
        put d
    get = do
        t  <- (get :: Get TPM_STRUCT_VER)
        f  <- getLazyByteString (fromIntegral 4)
        c <- get
        d <- get
        return $ TPM_QUOTE_INFO c d

tpm_quote_info_fixed :: Word32
tpm_quote_info_fixed = fourCharsToWord32 "QUOT"

-------------------------------------------------------------------------------
-- TPM msa composite structure as defined by section 5.15 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
newtype TPM_MSA_COMPOSITE = TPM_MSA_COMPOSITE [TPM_DIGEST] deriving (Show,Eq)

instance Binary TPM_MSA_COMPOSITE where
    put (TPM_MSA_COMPOSITE digests) = do
        put ((fromIntegral size) :: UINT32)
        mapM_ put digests
        where size = 20 * (P.length digests)
    get = do
        size <- (get :: Get UINT32)
        let num = size `div` 20
        digests <- replicateM (fromIntegral num) (get :: Get TPM_DIGEST)
        return $ TPM_MSA_COMPOSITE digests

-------------------------------------------------------------------------------
-- TPM CMK auth structure as defined by section 5.16 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_CMK_AUTH = TPM_CMK_AUTH {
      tpmCmkAuthMigration :: TPM_DIGEST
    , tpmCmkAuthDest      :: TPM_DIGEST
    , tpmCmkAuthSource    :: TPM_DIGEST
    } deriving (Show,Eq)

instance Binary TPM_CMK_AUTH where
    put (TPM_CMK_AUTH m d s) = do
        put m
        put d
        put s
    get = do
        m <- get
        d <- get
        s <- get
        return $ TPM_CMK_AUTH m d s

-------------------------------------------------------------------------------
-- TPM select size structure as defined by section 5.18 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_SELECT_SIZE = TPM_SELECT_SIZE {
      tpmSelectSizeMajor :: BYTE
    , tpmSelectSizeMinor :: BYTE
    , tpmSelectSizeReq   :: UINT16
    } deriving (Show,Eq)

instance Binary TPM_SELECT_SIZE where
    put (TPM_SELECT_SIZE mj mi rq) = do
        put mj
        put mi
        put rq
    get = do
        mj <- get
        mi <- get
        rq <- get
        return $ TPM_SELECT_SIZE mj mi rq

-------------------------------------------------------------------------------
-- TPM CMK migration auth structure as defined by section 5.19 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_CMK_MIGAUTH = TPM_CMK_MIGAUTH {
      tpmCmkMigAuthTag :: TPM_STRUCTURE_TAG
    , tpmCmkMigAuthMsa :: TPM_DIGEST
    , tpmCmkMigAuthPub :: TPM_DIGEST
    } deriving (Show,Eq)

-------------------------------------------------------------------------------
-- TPM CMK sigticket structure as defined by section 5.20 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_CMK_SIGTICKET = TPM_CMK_SIGTICKET {
      tpmCmkSigTicketTag  :: TPM_STRUCTURE_TAG
    , tpmCmkSigTicketVer  :: TPM_DIGEST
    , tpmCmkSigTicketData :: TPM_DIGEST
    } deriving (Show,Eq)

-------------------------------------------------------------------------------
-- TPM CMK MA approval structure as defined by section 5.21 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_CMK_MA_APPROVAL = TPM_CMK_MA_APPROVAL {
      tpmCmkMaApprovalTag    :: TPM_STRUCTURE_TAG
    , tpmCmkMaApprovalDigest :: TPM_DIGEST
    } deriving (Show,Eq)

-------------------------------------------------------------------------------
-- TPM permanent flags structure as defined by section 7 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_PERMANENT_FLAGS = TPM_PERMANENT_FLAGS {
      tpmPermanentTag                :: TPM_STRUCTURE_TAG
    , tpmPermanentDisable            :: BOOL
    , tpmPermanentOwnership          :: BOOL
    , tpmPermanentDeactivated        :: BOOL
    , tpmPermanentReadPubEK          :: BOOL
    , tpmPermanentDisableOwnerClear  :: BOOL
    , tpmPermanentAllowMaintenance   :: BOOL
    , tpmPermanentPPLifetimeLock     :: BOOL
    , tpmPermanentPPHWEnable         :: BOOL
    , tpmPermanentPPCMDEnable        :: BOOL
    , tpmPermanentCEKPUsed           :: BOOL
    , tpmPermanentPost               :: BOOL
    , tpmPermanentPostLock           :: BOOL
    , tpmPermanentFips               :: BOOL
    , tpmPermanentOperator           :: BOOL
    , tpmPermanentEnableRevokeEK     :: BOOL
    , tpmPermanentLocked             :: BOOL
    , tpmPermanentReadPubSRK         :: BOOL
    , tpmPermanentEstablished        :: BOOL
    , tpmPermanentMaintenanceDone    :: BOOL
    , tpmPermanentDisableFullDALogic :: BOOL
    } deriving (Show,Eq)

-------------------------------------------------------------------------------
-- TPM startup clear flags structure as defined by section 7.2 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_STCLEAR_FLAGS = TPM_STCLEAR_FLAGS {
      tpmStartupClearTag               :: TPM_STRUCTURE_TAG
    , tpmStartupClearDeactivated       :: BOOL
    , tpmStartupClearDisableForceClear :: BOOL
    , tpmStartupClearPP                :: BOOL
    , tpmStartupClearPPLock            :: BOOL
    , tpmStartupClearGlobalLock        :: BOOL
    } deriving (Show,Eq)

-------------------------------------------------------------------------------
-- TPM startup any flags structure as defined by section 7.3 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_STANY_FLAGS = TPM_STANY_FLAGS {
      tpmStartupAnyTag        :: TPM_STRUCTURE_TAG
    , tpmStartupAnyPostInit   :: BOOL
    , tpmStartupAnyLocality   :: TPM_MODIFIER_INDICATOR
    , tpmStartupAnyExclusive  :: BOOL
    , tpmStartupAnyTOSPresent :: BOOL
    } deriving (Show,Eq)

-------------------------------------------------------------------------------
-- TPM internal data as defined by section 7.4 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_PERMANENT_DATA = TPM_PERMANENT_DATA {
      tpmInternalTag           :: TPM_STRUCTURE_TAG
    , tpmInternalRevMajor      :: BYTE
    , tpmInternalRevMinor      :: BYTE
    , tpmInternalProof         :: TPM_NONCE
    , tpmInternalEKRest        :: TPM_NONCE
    , tpmInternalOwnerAuth     :: TPM_SECRET
    , tpmInternalOperAuth      :: TPM_SECRET
    , tpmInternalAuthDir       :: TPM_DIRVALUE
    , tpmInternalMaintPub      :: TPM_PUBKEY
    , tpmInternalEK            :: TPM_KEY
    , tpmInternalSRK           :: TPM_KEY
    , tpmInternalContext       :: TPM_KEY
    , tpmInternalDelegate      :: TPM_KEY
    , tpmInternalAudit         :: TPM_COUNTER_VALUE
    , tpmInternalCounters      :: [TPM_COUNTER_VALUE]
    , tpmInternalPcrAttrs      :: [TPM_PCR_ATTRIBUTES]
    , tpmInternalOrdinal       :: [BYTE]
    , tpmInternalRNG           :: [BYTE]
    , tpmInternalFamilyTB      :: TPM_FAMILY_TABLE
    , tpmInternalDelegateTB    :: TPM_DELEGATE_TABLE
    , tpmInternalBufferSize    :: UINT32
    , tpmInternalLastFamily    :: UINT32
    , tpmInternalNoOwnerWrite  :: UINT32
    , tpmInternalRestrDelegate :: TPM_CMK_DELEGATE
    , tpmInternalDAASeed       :: TPM_DAA_TPM_SEED
    , tpmInternalDAAProof      :: TPM_NONCE
    , tpmInternalDAAKey        :: TPM_KEY
    } deriving (Show,Eq)

-------------------------------------------------------------------------------
-- TPM cleared internal data as defined by section 7.5 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_STCLEAR_DATA = TPM_STCLEAR_DATA {
      tpmClrInternalTag         :: TPM_STRUCTURE_TAG
    , tpmClrInternalKey         :: TPM_NONCE
    , tpmClrInternalCountID     :: TPM_COUNT_ID
    , tpmClrInternalOwner       :: UINT32
    , tpmClrInternalDisableLock :: BOOL
    , tpmClrInternalPcrs        :: [TPM_PCRVALUE]
    , tpmClrInternalDeferPP     :: UINT32
    } deriving (Show,Eq)

-------------------------------------------------------------------------------
-- TPM any internal data as defined by section 7.6 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_SESSION_DATA = TPM_SESSION_DATA {
    --  vendor specific
    } deriving (Show,Eq)

data TPM_STANY_DATA = TPM_STANY_DATA {
      tpmAnyInternalTag      :: TPM_STRUCTURE_TAG
    , tpmAnyInternalContext  :: TPM_NONCE
    , tpmAnyInternalAudit    :: TPM_DIGEST
    , tpmAnyInternalTicks    :: TPM_CURRENT_TICKS
    , tpmAnyInternalCtxCount :: UINT32
    , tpmAnyInternalCtx      :: [UINT32]
    , tpmAnyInternalSessions :: [TPM_SESSION_DATA]
    } deriving (Show,Eq)

-------------------------------------------------------------------------------
-- TPM pcr selection structure as defined by section 8.1 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
newtype TPM_PCR_SELECTION = TPM_PCR_SELECTION ByteString deriving (Eq, Read, Show)


{-instance Show TPM_PCR_SELECTION where
    show (TPM_PCR_SELECTION bs) = bshex bs -}


instance Binary TPM_PCR_SELECTION where
    put (TPM_PCR_SELECTION bs) = do
        put ((fromIntegral $ length bs) :: UINT16)
        putLazyByteString bs
    get = do
        len <- (get :: Get UINT16)
        bs  <- getLazyByteString (fromIntegral len)
        return $ TPM_PCR_SELECTION bs

-------------------------------------------------------------------------------
-- TPM pcr composite structure as defined by section 8.2 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_PCR_COMPOSITE = TPM_PCR_COMPOSITE {
      tpmPcrCompositeSelection :: TPM_PCR_SELECTION
    , tpmPcrCompositePcrs      :: [TPM_PCRVALUE]
    } deriving (Show,Eq, Read)

instance Binary TPM_PCR_COMPOSITE where
    put (TPM_PCR_COMPOSITE s pcrs) = do
        put s
        put ((fromIntegral $ (P.length pcrs) * 20) :: UINT32)
        mapM_ put pcrs
    get = do
        s <- get
        size <- (get :: Get UINT32)
        let num = size `div` 20
        pcrs <- replicateM (fromIntegral num) (get :: Get TPM_PCRVALUE)
        return $ TPM_PCR_COMPOSITE s pcrs

-------------------------------------------------------------------------------
-- TPM pcr info structure as defined by section 8.3 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_PCR_INFO = TPM_PCR_INFO {
      tpmPcrInfoSelection  :: TPM_PCR_SELECTION
    , tpmPcrInfoAtRelease  :: TPM_COMPOSITE_HASH
    , tpmPcrINfoAtCreation :: TPM_COMPOSITE_HASH
    } deriving (Show,Eq)

instance Binary TPM_PCR_INFO where
    put (TPM_PCR_INFO s r c) = do
        put s
        put r
        put c
    get = do
        s <- get
        r <- get
        c <- get
        return $ TPM_PCR_INFO s r c

-------------------------------------------------------------------------------
-- TPM pcr info long structure as defined by section 8.4 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_PCR_INFO_LONG = TPM_PCR_INFO_LONG {
      tpmPcrInfoLongLocalAtCreation  :: TPM_LOCALITY_SELECTION
    , tpmPcrInfoLongLocalAtRelease   :: TPM_LOCALITY_SELECTION
    , tpmPcrInfoLongSelectAtCreation :: TPM_PCR_SELECTION
    , tpmPcrInfoLongSelectAtRelease  :: TPM_PCR_SELECTION
    , tpmPcrInfoLongDigestAtCreation :: TPM_COMPOSITE_HASH
    , tpmPcrInfoLongDigestAtRelease  :: TPM_COMPOSITE_HASH
    } deriving (Show,Eq)

instance Binary TPM_PCR_INFO_LONG where
    put (TPM_PCR_INFO_LONG lc lr sc sr dc dr) = do
        put tpm_tag_pcr_info_long
        put lc
        put lr
        put sc
        put sr
        put dc
        put dr
    get = do
        t <- (get :: Get UINT16)
        when (t /= tpm_tag_pcr_info_long) $ do
            error "Unexpected tag value."
        lc <- get
        lr <- get
        sc <- get
        sr <- get
        dc <- get
        dr <- get
        return $ TPM_PCR_INFO_LONG lc lr sc sr dc dr

-------------------------------------------------------------------------------
-- TPM pcr info short structure as defined by section 8.5 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_PCR_INFO_SHORT = TPM_PCR_INFO_SHORT {
      tpmPcrInfoShortSelect :: TPM_PCR_SELECTION
    , tpmPcrInfoShortLocal  :: TPM_LOCALITY_SELECTION
    , tpmPcrInfoShortDigest :: TPM_COMPOSITE_HASH
    } deriving (Show,Eq)

instance Binary TPM_PCR_INFO_SHORT where
    put (TPM_PCR_INFO_SHORT s l d) = do
        put s
        put l
        put d
    get = do
        s <- get
        l <- get
        d <- get
        return $ TPM_PCR_INFO_SHORT s l d

-------------------------------------------------------------------------------
-- TPM pcr info short structure as defined by section 8.8 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_PCR_ATTRIBUTES = TPM_PCR_ATTRIBUTES {
      tpmPcrAttrCanReset :: BOOL
    , tpmPcrAttrExtend   :: TPM_LOCALITY_SELECTION
    , tpmPcrAttrReset    :: TPM_LOCALITY_SELECTION
    } deriving (Show,Eq)

instance Binary TPM_PCR_ATTRIBUTES where
    put (TPM_PCR_ATTRIBUTES cr e r) = do
        put cr
        put e
        put r
    get = do
        cr <- get
        e <- get
        r <- get
        return $ TPM_PCR_ATTRIBUTES cr e r

-------------------------------------------------------------------------------
-- TPM stored data structure as defined by section 9.1 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_STORED_DATA = TPM_STORED_DATA {
      tpmStoredDataInfo    :: ByteString
    , tpmStoredDataEncData :: ByteString
    } deriving (Eq)

instance Show TPM_STORED_DATA where
    show (TPM_STORED_DATA inf enc) =
        "Stored Info: " ++ (blkwrap hdr 60 $ bshex inf) ++ "\n" ++
        "Stored Data: " ++ (blkwrap hdr 60 $ bshex enc)
        where hdr = "             "

instance Binary TPM_STORED_DATA where
    put (TPM_STORED_DATA inf enc) = do
        put tpm_struct_ver_default
        put ((fromIntegral $ length inf) :: UINT32)
        putLazyByteString inf
        put ((fromIntegral $ length enc) :: UINT32)
        putLazyByteString enc
    get = do
        ver <- (get :: Get TPM_STRUCT_VER)
        when (ver /= tpm_struct_ver_default) $ do
            error "Unexpected structure version."
        ilen <- (get :: Get UINT32)
        inf <- getLazyByteString (fromIntegral ilen)
        elen <- (get :: Get UINT32)
        enc <- getLazyByteString (fromIntegral elen)
        return $ TPM_STORED_DATA inf enc

-------------------------------------------------------------------------------
-- TPM stored data v1.2 structure as defined by section 9.2 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_STORED_DATA12 = TPM_STORED_DATA12 {
      tpmStoredData12Tag     :: TPM_STRUCTURE_TAG
    , tpmStoredData12Type    :: TPM_ENTITY_TYPE
    , tpmStoredData12Size    :: UINT32
    , tpmStoredData12Info    :: ByteString
    , tpmStoredData12EncSize :: UINT32
    , tpmStoredData12EncData :: ByteString
    } deriving (Show,Eq)

-------------------------------------------------------------------------------
-- TPM sealed data structure as defined by section 9.3 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_SEALED_DATA = TPM_SEALED_DATA {
      tpmSealedType   :: TPM_PAYLOAD_TYPE
    , tpmSealedSecret :: TPM_SECRET
    , tpmSealedProof  :: TPM_NONCE
    , tpmSealedDigest :: TPM_DIGEST
    , tpmSealedSize   :: UINT32
    , tpmSealedData   :: ByteString
    } deriving (Show,Eq)

-------------------------------------------------------------------------------
-- TPM symmetric key structure as defined by section 9.4 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_SYMMETRIC_KEY = TPM_SYMMETRIC_KEY {
      tpmSymmetricAlg    :: TPM_ALGORITHM_ID
    , tpmSymmetricScheme :: TPM_ENC_SCHEME
    {-, tpmSymmetricSize   :: UINT16 -}
    , tpmSymmetricData   :: {-B.-}ByteString  --Made strict here for cooperation with encryption library, but encoded lazy(see binary instance below) for transmission advantages.
    } deriving (Show, Eq)

x :: Word32
x = 0x3333

instance Binary TPM_SYMMETRIC_KEY where
  put(TPM_SYMMETRIC_KEY alg enc dat) = do
    put alg
    put enc
    put ((fromIntegral $ length ({-fromStrict-} dat)) :: UINT16)
    putLazyByteString ({-fromStrict-} dat)
  get = do
    alg <- get
    enc <- get
    size <- (get :: Get UINT16)
    dat <-  getLazyByteString (fromIntegral size)
    return $ TPM_SYMMETRIC_KEY alg enc ({-toStrict-} dat)

-------------------------------------------------------------------------------
-- TPM bound data structure as defined by section 9.5 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_BOUND_DATA = TPM_BOUND_DATA {
      tpmBoundVer  :: TPM_STRUCT_VER
    , tpmBoundType :: TPM_PAYLOAD_TYPE
    , tpmBoundData :: ByteString
    } deriving (Show,Eq)

-------------------------------------------------------------------------------
-- TPM key parameters structure as defined by section 10.1 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_KEY_PARMS_DATA = RSA_DATA TPM_RSA_KEY_PARMS
                        | AES_DATA TPM_SYMMETRIC_KEY_PARMS
                        | NO_DATA
                        deriving (Eq, Read, Show)

data TPM_KEY_PARMS = TPM_KEY_PARMS {
      tpmKeyParamAlg  :: TPM_ALGORITHM_ID
    , tpmKeyParamEnc  :: TPM_ENC_SCHEME
    , tpmKeyParamSig  :: TPM_SIG_SCHEME
    , tpmKeyParamData :: TPM_KEY_PARMS_DATA
    } deriving (Eq, Read, Show)

{-
instance Show TPM_KEY_PARMS_DATA where
    show NO_DATA = "\nKey Data:    none"
    show (RSA_DATA rsa) = "\nKey Length:  " ++ show (tpmRsaKeyLength rsa) ++
                          "\nNum Primes:  " ++ show (tpmRsaKeyPrimes rsa) ++
                          "\nExponent:    " ++ bshex (tpmRsaKeyExp rsa)
    show (AES_DATA aes) = "\nKey Length:  " ++ show (tpmSymKeyLength aes) ++
                          "\nBlock Size:  " ++ show (tpmSymKeyBlockSize aes) ++
                          "\nInit Vector: " ++ bshex (tpmSymKeyIV aes)
-}

{-
instance Show TPM_KEY_PARMS where
    show (TPM_KEY_PARMS alg enc sig dat) =
        "Algorithm:   " ++ tpm_alg_getname alg ++
        "\nEnc. Scheme: " ++ tpm_es_getname enc ++
        "\nSig. Scheme: " ++ tpm_ss_getname sig ++
        (show dat)
-}

instance Binary TPM_KEY_PARMS where
    put(TPM_KEY_PARMS alg enc sig dat) = do
        put alg
        put enc
        put sig
        case dat of
            RSA_DATA rsa -> do
                let bs = encode rsa
                put ((fromIntegral $ length bs) :: UINT32)
                putLazyByteString bs
            AES_DATA aes -> do
                let bs = encode aes
                put ((fromIntegral $ length bs) :: UINT32)
                putLazyByteString bs
            NO_DATA -> do
                put (0 :: UINT32)
    get = do
        alg  <- get
        enc  <- get
        sig  <- get
        case lookup alg tbl of
            Just finish -> do
                size <- (get :: Get UINT32)
                dat  <- getLazyByteString (fromIntegral size)
                return $ finish dat alg enc sig
            Nothing -> do size <- (get :: Get UINT32)
                          return $ TPM_KEY_PARMS alg enc sig NO_DATA
        where tbl = [(tpm_alg_rsa,mkrsa),(tpm_alg_aes128,mkaes)
                ,(tpm_alg_aes192,mkaes),(tpm_alg_aes256,mkaes)]
              mkrsa dat a e s = TPM_KEY_PARMS a e s (RSA_DATA (decode dat))
              mkaes dat a e s = TPM_KEY_PARMS a e s (AES_DATA (decode dat))

-------------------------------------------------------------------------------
-- TPM RSA parameters structure as defined by section 10.1.1 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_RSA_KEY_PARMS = TPM_RSA_KEY_PARMS {
      tpmRsaKeyLength  :: UINT32
    , tpmRsaKeyPrimes  :: UINT32
    , tpmRsaKeyExp     :: ByteString
    } deriving (Show,Eq, Read)

instance Binary TPM_RSA_KEY_PARMS where
    put (TPM_RSA_KEY_PARMS len prim exp) = do
        put len
        put prim
        put ((fromIntegral $ length exp) :: UINT32)
        putLazyByteString exp
    get = do
        len <- get
        prim <- get
        size <- (get :: Get UINT32)
        bs <- getLazyByteString (fromIntegral size)
        return $ TPM_RSA_KEY_PARMS len prim bs

-------------------------------------------------------------------------------
-- TPM sym parameters structure as defined by section 10.1.2 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_SYMMETRIC_KEY_PARMS = TPM_SYMMETRIC_KEY_PARMS {
      tpmSymKeyLength    :: UINT32
    , tpmSymKeyBlockSize :: UINT32
    , tpmSymKeyIV        :: ByteString
    } deriving (Show,Eq, Read)

instance Binary TPM_SYMMETRIC_KEY_PARMS where
    put (TPM_SYMMETRIC_KEY_PARMS kl bs iv) = do
        put kl
        put bs
        put ((fromIntegral $ length iv) :: UINT32)
        putLazyByteString iv
    get = do
        kl <- get
        bs <- get
        size <- (get :: Get UINT32)
        iv <- getLazyByteString (fromIntegral size)
        return $ TPM_SYMMETRIC_KEY_PARMS kl bs iv


-------------------------------------------------------------------------------
-- TPM key structure as defined by section 10.2 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_KEY = TPM_KEY {
      tpmKeyUsage   :: TPM_KEY_USAGE
    , tpmKeyFlags   :: TPM_KEY_FLAGS
    , tpmKeyAuth    :: TPM_AUTH_DATA_USAGE
    , tpmKeyParams  :: TPM_KEY_PARMS
    , tpmKeyPcrInfo :: ByteString
    , tpmKeyPublic  :: TPM_STORE_PUBKEY
    , tpmKeyEncData :: ByteString
    } deriving (Eq)

instance Show TPM_KEY where
    show (TPM_KEY use flg auth prm pcr pub enc) =
        "TPM Key:\n" ++
        "-----------------------------------------------------------------" ++
        "\nUsage:       " ++ tpm_key_getname use ++
        "\nFlags:       " ++ tpm_kf_getname flg ++
        "\nAuth:        " ++ tpm_auth_getname auth ++
        "\nPCR Info:    " ++ (bshex pcr) ++
        "\nEnc. Data:   " ++ (blkwrap hdr 60 $ bshex enc)  ++
        "\n" ++ (show prm) ++
        "\n" ++ (show pub)
        where hdr = "             "

instance Binary TPM_KEY where
    put (TPM_KEY use flg ath prm pcr pub enc) = do
        put tpm_struct_ver_default
        put use
        put flg
        put ath
        put prm
        put ((fromIntegral $ length pcr) :: UINT32)
        putLazyByteString pcr
        put pub
        put ((fromIntegral $ length enc) :: UINT32)
        putLazyByteString enc
        where ver = TPM_STRUCT_VER
    get = do
        ver <- (get :: Get TPM_STRUCT_VER)
        when (ver /= tpm_struct_ver_default) $ do
            error "Unexpected structure version."
        use <- get
        flg <- get
        ath <- get
        prm <- get
        psz <- (get :: Get UINT32)
        pcr <- getLazyByteString (fromIntegral psz)
        pub <- get
        esz <- (get :: Get UINT32)
        enc <- getLazyByteString (fromIntegral esz)
        return $ TPM_KEY use flg ath prm pcr pub enc

-------------------------------------------------------------------------------
-- TPM key v1.2 structure as defined by section 10.3 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_KEY12 = TPM_KEY12 {
      tpmKey12Usage   :: TPM_KEY_USAGE
    , tpmKey12Flags   :: TPM_KEY_FLAGS
    , tpmKey12Auth    :: TPM_AUTH_DATA_USAGE
    , tpmKey12Params  :: TPM_KEY_PARMS
    , tpmKey12PcrInfo :: ByteString
    , tpmKey12Public  :: TPM_STORE_PUBKEY
    , tpmKey12EncData :: ByteString
    } deriving (Show,Eq)

instance Binary TPM_KEY12 where
    put (TPM_KEY12 use flg ath prm pcr pub enc) = do
        put tpm_tag_key12
        put (0x0000 :: UINT16)
        put use
        put flg
        put ath
        put prm
        put ((fromIntegral $ length pcr) :: UINT32)
        putLazyByteString pcr
        put pub
        put ((fromIntegral $ length enc) :: UINT32)
        putLazyByteString enc
    get = do
        tag <- (get :: Get TPM_STRUCTURE_TAG)
        when (tag /= tpm_tag_key12) $ do
            error "Unexpected structure tag."
        fill <- (get :: Get UINT16)
        when (fill /= 0x0000) $ do
            error "Unexpected fill value."
        use <- get
        flg <- get
        ath <- get
        prm <- get
        psz <- (get :: Get UINT32)
        pcr <- getLazyByteString (fromIntegral psz)
        pub <- get
        esz <- (get :: Get UINT32)
        enc <- getLazyByteString (fromIntegral esz)
        return $ TPM_KEY12 use flg ath prm pcr pub enc

-------------------------------------------------------------------------------
-- TPM store public key structure as defined by section 10.4 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
newtype TPM_STORE_PUBKEY = TPM_STORE_PUBKEY ByteString deriving (Eq, Read, Show)

{-
instance Show TPM_STORE_PUBKEY where
    show (TPM_STORE_PUBKEY dat) = "Key:         " ++ blkwrap hdr 60 (bshex dat)
        where hdr = "             "
-}

instance Binary TPM_STORE_PUBKEY where
    put (TPM_STORE_PUBKEY dat) = do
        put ((fromIntegral $ length dat) :: UINT32)
        putLazyByteString dat
    get = do
        len <- (get :: Get UINT32)
        dat <- getLazyByteString (fromIntegral len)
        return $ TPM_STORE_PUBKEY dat

-------------------------------------------------------------------------------
-- TPM public key structure as defined by section 10.5 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_PUBKEY = TPM_PUBKEY {
      tpmPubKeyParams :: TPM_KEY_PARMS
    , tpmPubKeyData   :: TPM_STORE_PUBKEY
    } deriving (Eq, Read, Show)

{-
instance Show TPM_PUBKEY where
    show (TPM_PUBKEY prms key) =
        (show prms) ++ "\n" ++
        (show key)
-}

instance Binary TPM_PUBKEY where
    put (TPM_PUBKEY parms dat) = do
        put parms
        put dat
    get = do
        parms <- get
        dat <- get
        return $ TPM_PUBKEY parms dat

-------------------------------------------------------------------------------
-- TPM store asymkey structure as defined by section 10.6 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_STORE_ASYMKEY = TPM_STORE_ASYMKEY {
      tpmStoreAsymType    :: TPM_PAYLOAD_TYPE
    , tpmStoreAsymUsage   :: TPM_SECRET
    , tpmStoreAsymMigrate :: TPM_SECRET
    , tpmStoreAsymDigest  :: TPM_DIGEST
    , tpmStoreAsymKey     :: TPM_STORE_PRIVKEY
    } deriving (Show,Eq)

instance Binary TPM_STORE_ASYMKEY where
    put (TPM_STORE_ASYMKEY t use mig dig key) = do
        put t
        put use
        put mig
        put dig
        put key
    get = do
        t <- get
        use <- get
        mig <- get
        dig <- get
        key <- get
        return $ TPM_STORE_ASYMKEY t use mig dig key

-------------------------------------------------------------------------------
-- TPM store asymkey structure as defined by section 10.7 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_STORE_PRIVKEY = TPM_STORE_PRIVKEY ByteString deriving (Eq)

instance Show TPM_STORE_PRIVKEY where
    show (TPM_STORE_PRIVKEY dat) = bshex dat

instance Binary TPM_STORE_PRIVKEY where
    put (TPM_STORE_PRIVKEY dat) = do
        put ((fromIntegral $ length dat) :: UINT32)
        putLazyByteString dat
    get = do
        len <- (get :: Get UINT32)
        dat <- getLazyByteString (fromIntegral len)
        return $ TPM_STORE_PRIVKEY dat

-------------------------------------------------------------------------------
-- TPM store asymkey structure as defined by section 10.6 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_MIGRATE_ASYMKEY = TPM_MIGRATE_ASYMKEY {
      tpmMigrateAsymType   :: TPM_PAYLOAD_TYPE
    , tpmMigrateAsymUsage  :: TPM_SECRET
    , tpmMigrateAsymDigest :: TPM_DIGEST
    , tpmMigrateAsymKey    :: ByteString
    } deriving (Show,Eq)

instance Binary TPM_MIGRATE_ASYMKEY where
    put (TPM_MIGRATE_ASYMKEY t u d k) = do
        put t
        put u
        put d
        put ((fromIntegral $ length k) :: UINT32)
        putLazyByteString k
    get = do
        t <- get
        u <- get
        d <- get
        l <- (get :: Get UINT32)
        k <- getLazyByteString (fromIntegral l)
        return $ TPM_MIGRATE_ASYMKEY t u d k

-------------------------------------------------------------------------------
-- TPM current ticks structure as defined by section 15.1 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_CURRENT_TICKS = TPM_CURRENT_TICKS {
      tpmCurrentTicksTag   :: TPM_STRUCTURE_TAG
    , tpmCurrentTicksValue :: UINT64
    , tpmCurrentTicksRate  :: UINT16
    , tpmCurrentTicksNonce :: TPM_NONCE
    } deriving (Show,Eq)

-------------------------------------------------------------------------------
-- TPM delegations structure as defined by section 20.2 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_DELEGATIONS = TPM_DELEGATIONS {
      tpmDelegationsTag   :: TPM_STRUCTURE_TAG
    , tpmDelegationsType  :: UINT32
    , tpmDelegationsPerm1 :: UINT32
    , tpmDelegationsPerm2 :: UINT32
    } deriving (Show,Eq)

-------------------------------------------------------------------------------
-- TPM family table entry structure as defined by section 20.5 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_FAMILY_TABLE_ENTRY = TPM_FAMILY_TABLE_ENTRY {
      tpmFamilyTableEntryTag   :: TPM_STRUCTURE_TAG
    , tpmFamilyTableEntryLabel :: TPM_FAMILY_LABEL
    , tpmFamilyTableEntryId    :: TPM_FAMILY_ID
    , tpmFamilyTableEntryVerif :: TPM_FAMILY_VERIFICATION
    , tpmFamilyTableEntryFlags :: TPM_FAMILY_FLAGS
    } deriving (Show,Eq)

-------------------------------------------------------------------------------
-- TPM family table structure as defined by section 20.6 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_FAMILY_TABLE = TPM_FAMILY_TABLE {
      tpmFamilyTable :: [TPM_FAMILY_TABLE_ENTRY]
    } deriving (Show,Eq)

-------------------------------------------------------------------------------
-- TPM delegate public structure as defined by section 20.8 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_DELEGATE_PUBLIC = TPM_DELEGATE_PUBLIC {
      tpmDelegatePublicTag   :: TPM_STRUCTURE_TAG
    , tpmDelegatePublicLabel :: TPM_DELEGATE_LABEL
    , tpmDelegatePublicInfo  :: TPM_PCR_INFO_SHORT
    , tpmDelegatePublicPerms :: TPM_DELEGATIONS
    , tpmDelegatePublicId    :: TPM_FAMILY_ID
    , tpmDelegatePublicVerif :: TPM_FAMILY_VERIFICATION
    } deriving (Show,Eq)

-------------------------------------------------------------------------------
-- TPM delegate table row structure as defined by section 20.9 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_DELEGATE_TABLE_ROW = TPM_DELEGATE_TABLE_ROW {
      tpmDelegateTableRowTag  :: TPM_STRUCTURE_TAG
    , tpmDelegateTableRowPub  :: TPM_DELEGATE_PUBLIC
    , tpmDelegateTableRowAuth :: TPM_SECRET
    } deriving (Show,Eq)

-------------------------------------------------------------------------------
-- TPM delegate table structure as defined by section 20.10 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_DELEGATE_TABLE = TPM_DELEGATE_TABLE {
      tpmDelegateTable :: [TPM_DELEGATE_TABLE_ROW]
    } deriving (Show,Eq)

-------------------------------------------------------------------------------
-- TPM capability version structure as defined by section 21.6 of the document:
--  TPM Main: Part 2 - TPM Structures
-------------------------------------------------------------------------------
data TPM_CAP_VERSION_INFO = TPM_CAP_VERSION {
      tpmCapVersionTag    :: TPM_STRUCTURE_TAG
    , tpmCapVersionVer    :: TPM_VERSION
    , tpmCapVersionSpec   :: UINT16
    , tpmCapVersionRev    :: BYTE
    , tpmCapVersionVendor :: UINT32
    , tpmCapVersionVSize  :: UINT16
    , tpmCapVersionVSpec  :: ByteString
    } deriving (Show,Eq)


{-
----------------------------------------------------------------------
-- JSON INSTANCES-----------------------------------------------------
----------------------------------------------------------------------

testpubkey = TPM_STORE_PUBKEY $ fromStrict $ Char8.pack "3434"

-- JSON stuff!

--Request Things first
   --toJSON
jsonEncode :: (ToJSON a) => a -> ByteString
jsonEncode = DA.encode

jsonEitherDecode :: (FromJSON a) => ByteString -> Either String a
jsonEitherDecode = DA.eitherDecode

jsonDecode :: (FromJSON a) => ByteString -> Maybe a
jsonDecode= DA.decode

instance ToJSON TPM_IDENTITY_CONTENTS where
	toJSON (TPM_IDENTITY_CONTENTS {..}) = object [ "labelPrivCADigest" .= toJSON labelPrivCADigest --this is just TPM_Digest again
						     , "identityPubKey" .= toJSON identityPubKey   --did this one too.
						     ]
instance FromJSON TPM_IDENTITY_CONTENTS where
	parseJSON (DA.Object o) = TPM_IDENTITY_CONTENTS <$> o .: "labelPrivCADigest"
							<*> o .: "identityPubKey"

instance ToJSON TPM_PUBKEY where
	toJSON (TPM_PUBKEY {..}) = object [ "TPM_KEY_PARMS" .= toJSON tpmPubKeyParams
					  , "TPM_STORE_PUBKEY" .= toJSON tpmPubKeyData
					  ]
instance FromJSON TPM_PUBKEY where
	parseJSON (DA.Object o) = TPM_PUBKEY <$> o .: "TPM_KEY_PARMS"
					     <*> o .: "TPM_STORE_PUBKEY"
instance ToJSON TPM_KEY_PARMS where
	toJSON TPM_KEY_PARMS {..} = object [ "TPM_ALGORITHM_ID" .= toJSON tpmKeyParamAlg --word32
					   , "TPM_ENC_SCHEME" .= toJSON tpmKeyParamEnc --word16
					   , "TPM_SIG_SCHEME" .= toJSON tpmKeyParamSig  --word16
					   , "TPM_KEY_PARMS_DATA" .= toJSON tpmKeyParamData
					   ]
instance FromJSON TPM_KEY_PARMS where
	parseJSON (DA.Object o) = TPM_KEY_PARMS <$> o .: "TPM_ALGORITHM_ID"
						<*> o .: "TPM_ENC_SCHEME"
						<*> o .: "TPM_SIG_SCHEME"
						<*> o .: "TPM_KEY_PARMS_DATA"
{-
data TPM_KEY_PARMS_DATA = RSA_DATA TPM_RSA_KEY_PARMS
                        | AES_DATA TPM_SYMMETRIC_KEY_PARMS
                        | NO_DATA
                        deriving (Eq, Read, Show)					    -}

instance ToJSON TPM_KEY_PARMS_DATA where
	toJSON (RSA_DATA tpm_RSA_KEY_PARMS) = object [ "RSA_DATA" .= toJSON tpm_RSA_KEY_PARMS ]
	toJSON (AES_DATA tpm_SYMMETRIC_KEY_PARMS) = object [ "AES_DATA" .= toJSON tpm_SYMMETRIC_KEY_PARMS ]
	toJSON (NO_DATA) = DA.String "NO_DATA"
instance FromJSON TPM_KEY_PARMS_DATA where
	parseJSON (DA.Object o)	| HM.member "RSA_DATA" o = RSA_DATA  <$> o .: "RSA_DATA"
				| HM.member "AES_DATA" o = AES_DATA <$> o .: "AES_DATA"
				| HM.member "NO_DATA" o = pure NO_DATA

--DA.Object = HaskMap Text Value



instance ToJSON TPM_RSA_KEY_PARMS where
	toJSON (TPM_RSA_KEY_PARMS {..}) = object [ "tpmRsaKeyLength" .= toJSON tpmRsaKeyLength
						 , "tpmRsaKeyPrimes" .= toJSON tpmRsaKeyPrimes
						 , "tpmRsaKeyExp" .= encodeToText (toStrict tpmRsaKeyExp)
						 ]
instance FromJSON TPM_RSA_KEY_PARMS where
	parseJSON (DA.Object o) = TPM_RSA_KEY_PARMS <$> o .: "tpmRsaKeyLength"
						    <*> o .: "tpmRsaKeyPrimes"
						    <*> ((o .: "tpmRsaKeyExp") >>= decodeFromTextL)
instance ToJSON TPM_SYMMETRIC_KEY_PARMS where
	toJSON (TPM_SYMMETRIC_KEY_PARMS {..}) = object [ "tpmSymKeyLength" .= toJSON tpmSymKeyLength
					 	       , "tpmSymKeyBlockSize" .= toJSON tpmSymKeyBlockSize
					 	       , "tpmSymKeyIV" .= encodeToText (toStrict tpmSymKeyIV)
					 	       ]
instance FromJSON TPM_SYMMETRIC_KEY_PARMS where
	parseJSON (DA.Object o) = TPM_SYMMETRIC_KEY_PARMS <$>  o .: "tpmSymKeyLength"
							  <*> o .:  "tpmSymKeyBlockSize"
							  <*> ((o .: "tpmSymKeyIV") >>= decodeFromTextL)

	{-<$> o .: "DesiredEvidence"
  				 <*> o .: "TPM_PCR_SELECTION"
  				 <*> o .: "TPM_NONCE" -}
instance ToJSON TPM_STORE_PUBKEY where
	toJSON (TPM_STORE_PUBKEY bs) = object [ "TPM_STORE_PUBKEY" .= encodeToText (toStrict bs) ]

instance FromJSON TPM_STORE_PUBKEY where
	parseJSON (DA.Object o) = TPM_STORE_PUBKEY <$> ((o .: "TPM_STORE_PUBKEY") >>= decodeFromTextL)

instance ToJSON TPM_PCR_COMPOSITE where
	toJSON (TPM_PCR_COMPOSITE {..}) = object [ "TPM_PCR_SELECTION" .= toJSON tpmPcrCompositeSelection
						 , "TPM_PCRVALUEs" .= toJSON tpmPcrCompositePcrs
						 ]
instance FromJSON TPM_PCR_COMPOSITE where
	parseJSON (DA.Object o) = TPM_PCR_COMPOSITE <$> o .: "TPM_PCR_SELECTION"
						    <*> o .: "TPM_PCRVALUEs"

--instance ToJSON TPM_PCRVALUE where TPM_PCRVALUE is a synonym for TPM_DIGEST
instance ToJSON TPM_DIGEST where
	toJSON (TPM_DIGEST bs) = object [ "TPM_DIGEST" .= encodeToText (toStrict bs) ]
instance FromJSON TPM_DIGEST where
	parseJSON (DA.Object o) = TPM_DIGEST <$> ((o .: "TPM_DIGEST") >>= decodeFromTextL)

instance ToJSON TPM_PCR_SELECTION where
	toJSON (TPM_PCR_SELECTION bs) = object [ "TPM_PCR_SELECTION" .= encodeToText (toStrict bs) ]
instance FromJSON TPM_PCR_SELECTION where
	parseJSON (DA.Object o) = TPM_PCR_SELECTION <$> ((o .: "TPM_PCR_SELECTION") >>= decodeFromTextL)

instance ToJSON TPM_NONCE where
  toJSON (TPM_NONCE n) = object ["TPM_NONCE" .= encodeToText (toStrict n)]
instance FromJSON TPM_NONCE where
	parseJSON (DA.Object o) = TPM_NONCE <$> ((o .: "TPM_NONCE") >>= decodeFromTextL)
-}
