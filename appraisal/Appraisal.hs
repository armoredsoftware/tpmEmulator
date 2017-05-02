module Appraisal where --AppMain where

import CAProtoMain (caEntity_App)
import ProtoMonad
import ArmoredTypes
import ProtoActions
import VChanUtil
import TPM
import TPMUtil
import Keys
import Provisioning(readGoldenComp)


import Prelude
import Data.ByteString.Lazy hiding (putStrLn, map)
import qualified Data.Map as M
import System.IO
import Codec.Crypto.RSA
import System.Random
import Data.Digest.Pure.SHA (bytestringDigest, sha1)
import Data.Binary
import Control.Applicative hiding (empty)

import AbstractedCommunication


