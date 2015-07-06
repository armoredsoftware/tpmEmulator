-------------------------------------------------------------------------------
-- This module provides functions which perform all of the commands
-- listed in section 22 of the document: TPM Main: Part 3 - Commands
-------------------------------------------------------------------------------
module TPM.Eviction where
import TPM.Const
import TPM.Driver
import TPM.Types
import Data.Binary
import Data.ByteString.Lazy
import Prelude hiding (concat)

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
tpm_flushspecific :: TPM tpm => tpm -> TPM_HANDLE -> TPM_RESOURCE_TYPE -> IO ()
tpm_flushspecific tpm hand rtype = tpm_transmit tpm 0 tag cod dat >> return ()
    where tag = tpm_tag_rqu_command
          cod = tpm_ord_flushspecific
          dat = concat [encode hand, encode rtype]
