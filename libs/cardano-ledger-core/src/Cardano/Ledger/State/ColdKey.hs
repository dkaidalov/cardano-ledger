{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Experimental permanent pool authorities. Pool identifiers remain unchanged.
module Cardano.Ledger.State.ColdKey (
  ColdScheme (..),
  ColdWitness (..),
  coldWitnessKeyHash,
  verifyColdWitness,
  coldKeyHash,
  ColdKeyRotation (..),
  ColdKeyAuthority (..),
  PendingColdKey (..),
  initialColdKeyAuthority,
  activateColdKeyAuthority,
  scheduleColdKeyRotation,
) where

import Cardano.Ledger.BaseTypes (StrictMaybe (..))
import Cardano.Ledger.Binary (DecCBOR (..), EncCBOR (..), decodeRecordNamed, decodeListLen, encodeListLen)
import Cardano.Ledger.Keys (KeyHash (..), KeyRole (StakePool))
import qualified Cardano.Crypto.DSIGN as D
import qualified Cardano.Crypto.Hash as H
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Cardano.Ledger.BaseTypes (natVersion)
import Cardano.Ledger.Binary (serialize', FixedSizeCodec (..))
import Cardano.Ledger.Slot (EpochNo (..))
import Control.DeepSeq (NFData)
import Data.Aeson (ToJSON)
import Data.Word (Word64)
import GHC.Generics (Generic)
import NoThunks.Class (NoThunks)

-- Experimental scheme registry, scoped to pool cold authority.
data ColdScheme = ColdEd25519 | ColdMLDSA44
  deriving (Eq, Ord, Show, Generic, NFData, NoThunks, ToJSON)

instance EncCBOR ColdScheme where
  encCBOR ColdEd25519 = encCBOR (0 :: Word64)
  encCBOR ColdMLDSA44 = encCBOR (1 :: Word64)
instance DecCBOR ColdScheme where
  decCBOR = do
    tag <- decCBOR @Word64
    case tag of
      0 -> pure ColdEd25519
      1 -> pure ColdMLDSA44
      _ -> fail "Unsupported pool cold-key scheme"

-- Only ML-DSA uses the new witness field. Ed25519 keeps ordinary witnesses.
data ColdWitness = ColdWitness !ByteString !ByteString
  deriving (Eq, Ord, Show, Generic, NFData, NoThunks)

coldKeyHash :: ByteString -> KeyHash StakePool
coldKeyHash key = KeyHash $ H.castHash $ H.hashWith id $
  "Cardano.PoolColdKey.v1" <> serialize' (natVersion @9) (ColdMLDSA44, key)

coldWitnessKeyHash :: ColdWitness -> KeyHash StakePool
coldWitnessKeyHash (ColdWitness key _) = coldKeyHash key

verifyColdWitness :: ByteString -> ColdWitness -> Bool
verifyColdWitness message (ColdWitness key sig) =
  case (rawDecodeFixedSized @(D.VerKeyDSIGN D.MLDSA44DSIGN) key, rawDecodeFixedSized @(D.SigDSIGN D.MLDSA44DSIGN) sig) of
    (Just vk, Just signature) -> either (const False) (const True) $ D.verifyDSIGN () vk message signature
    _ -> False

instance EncCBOR ColdWitness where
  encCBOR (ColdWitness key sig) = encodeListLen 3 <> encCBOR ColdMLDSA44 <> encCBOR key <> encCBOR sig
instance DecCBOR ColdWitness where
  decCBOR = decodeRecordNamed "ColdWitness" (const 3) $ do
    scheme <- decCBOR
    key <- decCBOR
    sig <- decCBOR
    if scheme == ColdMLDSA44 && BS.length key == 1312 && BS.length sig == 2420
      then pure (ColdWitness key sig)
      else fail "Invalid ML-DSA-44 cold witness"

-- | Both keys witness the transaction body containing this request.
data ColdKeyRotation = ColdKeyRotation
  { ckrExpectedGeneration :: !Word64
  , ckrScheme :: !ColdScheme
  , ckrNewKey :: !(KeyHash StakePool)
  }
  deriving (Eq, Ord, Show, Generic, NFData, NoThunks, ToJSON)

data PendingColdKey = PendingColdKey
  { pckActivation :: !EpochNo
  , pckScheme :: !ColdScheme
  , pckKey :: !(KeyHash StakePool)
  }
  deriving (Eq, Ord, Show, Generic, NFData, NoThunks, ToJSON)

data ColdKeyAuthority = ColdKeyAuthority
  { ckaKey :: !(KeyHash StakePool)
  , ckaScheme :: !ColdScheme
  , ckaGeneration :: !Word64
  , ckaPending :: !(StrictMaybe PendingColdKey)
  }
  deriving (Eq, Ord, Show, Generic, NFData, NoThunks, ToJSON)

initialColdKeyAuthority :: KeyHash StakePool -> ColdKeyAuthority
initialColdKeyAuthority poolId = ColdKeyAuthority poolId ColdEd25519 0 SNothing

activateColdKeyAuthority :: EpochNo -> ColdKeyAuthority -> ColdKeyAuthority
activateColdKeyAuthority epoch authority@ColdKeyAuthority {ckaGeneration, ckaPending} =
  case ckaPending of
    SJust (PendingColdKey activation scheme key)
      | epoch >= activation -> ColdKeyAuthority key scheme (ckaGeneration + 1) SNothing
    _ -> authority

-- | One immutable pending request. The POOL rule also checks that a full epoch
-- exceeds the consensus forecast window before accepting this two-epoch delay.
-- Returning Nothing rejects stale generations, concurrent requests and overflow.
scheduleColdKeyRotation ::
  EpochNo -> ColdKeyRotation -> ColdKeyAuthority -> Maybe ColdKeyAuthority
scheduleColdKeyRotation epoch@(EpochNo e) ColdKeyRotation {ckrExpectedGeneration, ckrScheme, ckrNewKey} previous
  | e > maxBound - 2 = Nothing
  | ckaGeneration active == maxBound = Nothing
  | ckrExpectedGeneration /= ckaGeneration active = Nothing
  | ckrScheme == ckaScheme active && ckrNewKey == ckaKey active = Nothing
  | SJust _ <- ckaPending active = Nothing
  | otherwise = Just active {ckaPending = SJust (PendingColdKey (EpochNo (e + 2)) ckrScheme ckrNewKey)}
  where
    active = activateColdKeyAuthority epoch previous

instance EncCBOR ColdKeyRotation where
  encCBOR (ColdKeyRotation generation scheme key) = encodeListLen 3 <> encCBOR generation <> encCBOR scheme <> encCBOR key
instance DecCBOR ColdKeyRotation where
  decCBOR = do
    len <- decodeListLen
    case len of
      2 -> ColdKeyRotation <$> decCBOR <*> pure ColdEd25519 <*> decCBOR
      3 -> ColdKeyRotation <$> decCBOR <*> decCBOR <*> decCBOR
      _ -> fail "Invalid cold rotation"
instance EncCBOR PendingColdKey where
  encCBOR (PendingColdKey epoch scheme key) = encodeListLen 3 <> encCBOR epoch <> encCBOR scheme <> encCBOR key
instance DecCBOR PendingColdKey where
  decCBOR = do
    len <- decodeListLen
    case len of
      2 -> PendingColdKey <$> decCBOR <*> pure ColdEd25519 <*> decCBOR
      3 -> PendingColdKey <$> decCBOR <*> decCBOR <*> decCBOR
      _ -> fail "Invalid pending cold key"
instance EncCBOR ColdKeyAuthority where
  encCBOR (ColdKeyAuthority key scheme generation pending) =
    encodeListLen 4 <> encCBOR key <> encCBOR scheme <> encCBOR generation <> encCBOR pending
instance DecCBOR ColdKeyAuthority where
  decCBOR = do
    len <- decodeListLen
    case len of
      3 -> ColdKeyAuthority <$> decCBOR <*> pure ColdEd25519 <*> decCBOR <*> decCBOR
      4 -> ColdKeyAuthority <$> decCBOR <*> decCBOR <*> decCBOR <*> decCBOR
      _ -> fail "Invalid cold authority"
