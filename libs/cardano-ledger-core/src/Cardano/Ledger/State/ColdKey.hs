{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Experimental permanent pool authorities. Pool identifiers remain unchanged.
module Cardano.Ledger.State.ColdKey (
  ColdKeyRotation (..),
  ColdKeyAuthority (..),
  PendingColdKey (..),
  initialColdKeyAuthority,
  activateColdKeyAuthority,
  scheduleColdKeyRotation,
) where

import Cardano.Ledger.BaseTypes (StrictMaybe (..))
import Cardano.Ledger.Binary (DecCBOR (..), EncCBOR (..), decodeRecordNamed, encodeListLen)
import Cardano.Ledger.Keys (KeyHash, KeyRole (StakePool))
import Cardano.Ledger.Slot (EpochNo (..))
import Control.DeepSeq (NFData)
import Data.Aeson (ToJSON)
import Data.Word (Word64)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)

-- | Both keys witness the transaction body containing this request.
data ColdKeyRotation = ColdKeyRotation
  { ckrExpectedGeneration :: !Word64
  , ckrNewKey :: !(KeyHash StakePool)
  }
  deriving (Eq, Ord, Show, Generic, NFData, NoThunks, ToJSON)

data PendingColdKey = PendingColdKey
  { pckActivation :: !EpochNo
  , pckKey :: !(KeyHash StakePool)
  }
  deriving (Eq, Ord, Show, Generic, NFData, NoThunks, ToJSON)

data ColdKeyAuthority = ColdKeyAuthority
  { ckaKey :: !(KeyHash StakePool)
  , ckaGeneration :: !Word64
  , ckaPending :: !(StrictMaybe PendingColdKey)
  }
  deriving (Eq, Ord, Show, Generic, NFData, NoThunks, ToJSON)

initialColdKeyAuthority :: KeyHash StakePool -> ColdKeyAuthority
initialColdKeyAuthority poolId = ColdKeyAuthority poolId 0 SNothing

activateColdKeyAuthority :: EpochNo -> ColdKeyAuthority -> ColdKeyAuthority
activateColdKeyAuthority epoch authority@ColdKeyAuthority {ckaGeneration, ckaPending} =
  case ckaPending of
    SJust (PendingColdKey activation key)
      | epoch >= activation -> ColdKeyAuthority key (ckaGeneration + 1) SNothing
    _ -> authority

-- | One immutable pending request. The POOL rule also checks that a full epoch
-- exceeds the consensus forecast window before accepting this two-epoch delay.
-- Returning Nothing rejects stale generations, concurrent requests and overflow.
scheduleColdKeyRotation ::
  EpochNo -> ColdKeyRotation -> ColdKeyAuthority -> Maybe ColdKeyAuthority
scheduleColdKeyRotation epoch@(EpochNo e) ColdKeyRotation {ckrExpectedGeneration, ckrNewKey} previous
  | e > maxBound - 2 = Nothing
  | ckaGeneration active == maxBound = Nothing
  | ckrExpectedGeneration /= ckaGeneration active = Nothing
  | ckrNewKey == ckaKey active = Nothing
  | SJust _ <- ckaPending active = Nothing
  | otherwise = Just active {ckaPending = SJust (PendingColdKey (EpochNo (e + 2)) ckrNewKey)}
  where
    active = activateColdKeyAuthority epoch previous

instance EncCBOR ColdKeyRotation where
  encCBOR (ColdKeyRotation generation key) = encodeListLen 2 <> encCBOR generation <> encCBOR key

instance DecCBOR ColdKeyRotation where
  decCBOR = decodeRecordNamed "ColdKeyRotation" (const 2) $ ColdKeyRotation <$> decCBOR <*> decCBOR

instance EncCBOR PendingColdKey where
  encCBOR (PendingColdKey epoch key) = encodeListLen 2 <> encCBOR epoch <> encCBOR key

instance DecCBOR PendingColdKey where
  decCBOR = decodeRecordNamed "PendingColdKey" (const 2) $ PendingColdKey <$> decCBOR <*> decCBOR

instance EncCBOR ColdKeyAuthority where
  encCBOR (ColdKeyAuthority key generation pending) =
    encodeListLen 3 <> encCBOR key <> encCBOR generation <> encCBOR pending

instance DecCBOR ColdKeyAuthority where
  decCBOR = decodeRecordNamed "ColdKeyAuthority" (const 3) $ ColdKeyAuthority <$> decCBOR <*> decCBOR <*> decCBOR
