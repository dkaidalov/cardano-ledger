{-# OPTIONS_GHC -Wno-partial-fields #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ViewPatterns #-}

-- | Block header associated with Praos.
--
-- The choice of whether to associate the header with the ledger era or the
-- protocol is a little arbitrary. Functionally the header contains things which
-- are associated with both ledger and protocol, and which are used by both.
--
-- We choose to associate the header with the protocol, since it more strongly
-- binds in that direction, and to assist with the mental picture that the
-- protocol is concerned with the block header, while the ledger is concerned
-- with the block body. However, in order to more cleanly illustrate which parts
-- of the header are _strictly_ protocol concerns, we also provide a view of the
-- header (in @Ouroboros.Consensus.Protocol.Praos.Views@, in ouroboros-consensus) which extracts just
-- the fields needed for the Praos protocol. This also allows us to hide the
-- more detailed construction of the header.
module Cardano.Protocol.Praos.BlockHeader (
  Header (Header, headerBody, headerSig),
  HeaderBody (..),
  HeaderOCert (..),
  OCertAuth (..),
  mkHeaderOCert,
  headerHash,
  headerSize,
) where

import Cardano.Ledger.State.ColdKey (ColdWitness)
import qualified Cardano.Crypto.DSIGN as DSIGN
import qualified Cardano.Crypto.Hash as Hash
import qualified Cardano.Crypto.KES as KES
import Cardano.Crypto.Util (
  SignableRepresentation (getSignableRepresentation),
 )
import qualified Cardano.Crypto.VRF as VRF
import Cardano.Ledger.BaseTypes (ProtVer (pvMajor), StrictMaybe (..))
import Cardano.Ledger.Binary (
  Annotator (..),
  DecCBOR (decCBOR),
  EncCBOR (..),
  decodeFixedSized,
  decodeListLen,
  encodeListLen,
  encodeFixedSized,
  serialize',
 )
import Cardano.Ledger.Binary.Coders
import qualified Cardano.Ledger.Binary.Plain as Plain
import Cardano.Ledger.Block (Block (..), EraBlockHeader (..))
import Cardano.Ledger.Core (Era)
import Cardano.Ledger.Hashes (
  EraIndependentBlockBody,
  EraIndependentBlockHeader,
  HASH,
  HashAnnotated (..),
  SafeToHash,
  extractHash,
  originalBytesSize,
 )
import Cardano.Ledger.Keys (DSIGN, KeyHash, KeyRole (BlockIssuer), VKey)
import Cardano.Ledger.MemoBytes (
  Mem,
  MemoBytes,
  MemoHashIndex,
  Memoized (..),
  getMemoRawType,
  getMemoSafeHash,
  mkMemoized,
 )
import Cardano.Protocol.Crypto (Crypto, KES, VRF)
import Cardano.Protocol.Praos.VRF (InputVRF)
import Cardano.Protocol.TPraos.BlockHeader (PrevHash)
import Cardano.Protocol.TPraos.OCert (KESPeriod, OCert (..), OCertSignable)
import Cardano.Slotting.Block (BlockNo)
import Cardano.Slotting.Slot (SlotNo)
import Data.Word (Word32, Word64)
import GHC.Generics (Generic)
import Lens.Micro (lens, to)
import NoThunks.Class (NoThunks (..))

-- | Cold-key authentication of the operational certificate fields. Omitted
-- when those fields are already authenticated in the chain-dependent state.
data OCertAuth crypto = OCertAuth
  { oaColdKey :: !(VKey BlockIssuer)
  , oaColdSig :: !(DSIGN.SignedDSIGN DSIGN (OCertSignable crypto))
  }
  | OCertAuthMLDSA44 !ColdWitness
  deriving (Generic)

deriving instance Crypto crypto => Show (OCertAuth crypto)

deriving instance Crypto crypto => Eq (OCertAuth crypto)

instance Crypto crypto => NoThunks (OCertAuth crypto)

instance Crypto crypto => EncCBOR (OCertAuth crypto) where
  encCBOR OCertAuth {oaColdKey, oaColdSig} =
    encode $ Rec OCertAuth !> To oaColdKey !> E encodeFixedSized oaColdSig

  encCBOR (OCertAuthMLDSA44 witness) = encodeListLen 1 <> encCBOR witness

instance Crypto crypto => DecCBOR (OCertAuth crypto) where
  decCBOR = do
    len <- decodeListLen
    case len of
      2 -> OCertAuth <$> decCBOR <*> decodeFixedSized
      1 -> OCertAuthMLDSA44 <$> decCBOR
      _ -> fail "Invalid cold authentication"

-- | Header representation of an operational certificate. The hot KES key,
-- counter and start period are always present, so the header's KES signature
-- can be checked without chain state. Full validation also authenticates these
-- fields using either 'hocAuth' or the certificate remembered on this chain.
-- The on-disk 'OCert' used by operators remains a complete signed certificate.
data HeaderOCert crypto = HeaderOCert
  { hocHotKey :: !(KES.VerKeyKES (KES crypto))
  , hocIssueNo :: !Word64
  , hocStartPeriod :: !KESPeriod
  , hocAuth :: !(StrictMaybe (OCertAuth crypto))
  }
  deriving (Generic)

deriving instance Crypto crypto => Show (HeaderOCert crypto)

deriving instance Crypto crypto => Eq (HeaderOCert crypto)

instance Crypto crypto => NoThunks (HeaderOCert crypto)

instance Crypto crypto => EncCBOR (HeaderOCert crypto) where
  encCBOR HeaderOCert {hocHotKey, hocIssueNo, hocStartPeriod, hocAuth} =
    encode $
      Rec HeaderOCert
        !> E encodeFixedSized hocHotKey
        !> To hocIssueNo
        !> To hocStartPeriod
        !> To hocAuth

instance Crypto crypto => DecCBOR (HeaderOCert crypto) where
  decCBOR = decode $ RecD HeaderOCert <! D decodeFixedSized <! From <! From <! From

-- | Include the cold key and signature when introducing a certificate.
mkHeaderOCert :: VKey BlockIssuer -> OCert crypto -> HeaderOCert crypto
mkHeaderOCert vk (OCert hotKey counter startPeriod sig) =
  HeaderOCert hotKey counter startPeriod (SJust (OCertAuth vk sig))
mkHeaderOCert _ (OCertMLDSA44 hotKey counter startPeriod witness) =
  HeaderOCert hotKey counter startPeriod (SJust (OCertAuthMLDSA44 witness))

-- | The body of the header is the part signed by the KES key.
data HeaderBody crypto = HeaderBody
  { hbBlockNo :: !BlockNo
  -- ^ block number
  , hbSlotNo :: !SlotNo
  -- ^ block slot
  , hbPrev :: !PrevHash
  -- ^ Hash of the previous block header
  , hbIssuer :: !(KeyHash BlockIssuer)
  -- ^ hash of the block issuer's cold verification key
  , hbVrfVk :: !(VRF.VerKeyVRF (VRF crypto))
  -- ^ VRF verification key for block issuer
  , hbVrfRes :: !(VRF.CertifiedVRF (VRF crypto) InputVRF)
  -- ^ Certified VRF value
  , hbBodySize :: !Word32
  -- ^ Size of the block body
  , hbBodyHash :: !(Hash.Hash HASH EraIndependentBlockBody)
  -- ^ Hash of block body
  , hbOCert :: !(HeaderOCert crypto)
  -- ^ operational certificate fields with optional cold-key authentication
  , hbProtVer :: !ProtVer
  -- ^ protocol version
  }
  deriving (Generic)

deriving instance Crypto crypto => Show (HeaderBody crypto)

deriving instance Crypto crypto => Eq (HeaderBody crypto)

instance
  Crypto crypto =>
  SignableRepresentation (HeaderBody crypto)
  where
  getSignableRepresentation hb = serialize' (pvMajor (hbProtVer hb)) hb

instance
  Crypto crypto =>
  NoThunks (HeaderBody crypto)

data HeaderRaw crypto = HeaderRaw
  { headerRawBody :: !(HeaderBody crypto)
  , headerRawSig :: !(KES.SignedKES (KES crypto) (HeaderBody crypto))
  }
  deriving (Show, Generic)

instance Crypto c => Eq (HeaderRaw c) where
  h1 == h2 =
    headerRawSig h1 == headerRawSig h2
      && headerRawBody h1 == headerRawBody h2

instance
  Crypto crypto =>
  NoThunks (HeaderRaw crypto)

-- | Full header type, carrying its own memoised bytes.
newtype Header crypto = HeaderConstr (MemoBytes (HeaderRaw crypto))
  deriving (Generic)
  deriving newtype (Eq, Show, NoThunks, Plain.ToCBOR, SafeToHash)

instance Memoized (Header crypto) where
  type RawType (Header crypto) = HeaderRaw crypto

type instance MemoHashIndex (HeaderRaw crypto) = EraIndependentBlockHeader

instance HashAnnotated (Header crypto) EraIndependentBlockHeader where
  hashAnnotated = getMemoSafeHash

pattern Header ::
  Crypto crypto =>
  HeaderBody crypto ->
  KES.SignedKES (KES crypto) (HeaderBody crypto) ->
  Header crypto
pattern Header {headerBody, headerSig} <- (getMemoRawType -> HeaderRaw headerBody headerSig)
  where
    Header body sig = mkMemoized (pvMajor (hbProtVer body)) $ HeaderRaw body sig

{-# COMPLETE Header #-}

-- | Compute the size of the header
headerSize :: Header crypto -> Int
headerSize = originalBytesSize

-- | Hash a header
headerHash ::
  Header crypto ->
  Hash.Hash HASH EraIndependentBlockHeader
headerHash = extractHash . hashAnnotated

--------------------------------------------------------------------------------
-- Serialisation
--------------------------------------------------------------------------------

instance Crypto crypto => EncCBOR (HeaderBody crypto) where
  encCBOR
    HeaderBody
      { hbBlockNo
      , hbSlotNo
      , hbPrev
      , hbIssuer
      , hbVrfVk
      , hbVrfRes
      , hbBodySize
      , hbBodyHash
      , hbOCert
      , hbProtVer
      } =
      encode $
        Rec HeaderBody
          !> To hbBlockNo
          !> To hbSlotNo
          !> To hbPrev
          !> To hbIssuer
          !> E encodeFixedSized hbVrfVk
          !> To hbVrfRes
          !> To hbBodySize
          !> To hbBodyHash
          !> To hbOCert
          !> To hbProtVer

instance Crypto crypto => DecCBOR (HeaderBody crypto) where
  decCBOR =
    decode $
      RecD HeaderBody
        <! From
        <! From
        <! From
        <! From
        <! D decodeFixedSized
        <! From
        <! From
        <! From
        <! From
        <! From

encodeHeaderRaw ::
  Crypto crypto =>
  HeaderRaw crypto ->
  Encode (Closed Dense) (HeaderRaw crypto)
encodeHeaderRaw (HeaderRaw body sig) =
  Rec HeaderRaw !> To body !> E encodeFixedSized sig

instance Crypto crypto => EncCBOR (HeaderRaw crypto) where
  encCBOR = encode . encodeHeaderRaw

instance Crypto crypto => DecCBOR (HeaderRaw crypto) where
  decCBOR = decode $ RecD HeaderRaw <! From <! D decodeFixedSized

instance Crypto crypto => DecCBOR (Annotator (HeaderRaw crypto)) where
  decCBOR = pure <$> decCBOR

instance Crypto c => EncCBOR (Header c)

deriving via
  Mem (HeaderRaw crypto)
  instance
    Crypto crypto => DecCBOR (Annotator (Header crypto))

instance (Crypto c, Era era) => EraBlockHeader (Header c) era where
  blockIssuerBlockHeaderG =
    to (\(Block (Header hb _) _) -> hbIssuer hb)
  blockHeaderSizeBlockHeaderG =
    to (\(Block hdr _) -> originalBytesSize hdr)
  blockBodySizeBlockHeaderL =
    lens
      (\(Block (Header hb _) _) -> hbBodySize hb)
      ( \(Block (Header hb sig) body) sz ->
          Block (Header hb {hbBodySize = sz} sig) body
      )
  blockBodyHashBlockHeaderL =
    lens
      (\(Block (Header hb _) _) -> hbBodyHash hb)
      ( \(Block (Header hb sig) body) h ->
          Block (Header hb {hbBodyHash = h} sig) body
      )
  slotNoBlockHeaderL =
    lens
      (\(Block (Header hb _) _) -> hbSlotNo hb)
      ( \(Block (Header hb sig) body) s ->
          Block (Header hb {hbSlotNo = s} sig) body
      )
  protVerBlockHeaderL =
    lens
      (\(Block (Header hb _) _) -> hbProtVer hb)
      ( \(Block (Header hb sig) body) pv ->
          Block (Header hb {hbProtVer = pv} sig) body
      )
