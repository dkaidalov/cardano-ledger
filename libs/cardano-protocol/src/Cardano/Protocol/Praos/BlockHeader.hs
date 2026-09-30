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
  IssuerCert (..),
  headerHash,
  headerSize,
) where

import qualified Cardano.Crypto.Hash as Hash
import qualified Cardano.Crypto.KES as KES
import Cardano.Crypto.Util (
  SignableRepresentation (getSignableRepresentation),
 )
import qualified Cardano.Crypto.VRF as VRF
import Cardano.Ledger.BaseTypes (ProtVer (pvMajor))
import Cardano.Ledger.Binary (
  Annotator (..),
  DecCBOR (decCBOR),
  EncCBOR (..),
  decodeFixedSized,
  encodeFixedSized,
  serialize',
  unCBORGroup,
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
import Cardano.Ledger.BaseTypes (StrictMaybe)
import Cardano.Ledger.Keys (KeyHash, KeyRole (BlockIssuer), VKey)
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
import Cardano.Protocol.TPraos.OCert (OCert)
import Cardano.Slotting.Block (BlockNo)
import Cardano.Slotting.Slot (SlotNo)
import Data.Word (Word32, Word64)
import GHC.Generics (Generic)
import Lens.Micro (lens, to)
import NoThunks.Class (NoThunks (..))

-- | The body of the header is the part which gets hashed to form the hash
-- chain.
-- | The block issuer's cold verification key together with its operational
-- certificate. Carried in a header only when the issuer's certificate is not
-- yet known to the chain, that is on the first block after a KES key
-- rotation (or the issuer's first block ever). Every other header identifies
-- the issuer by key hash and counter alone, and verifiers look the current
-- certificate up in the chain-dependent state.
--
-- Experimental header format for the post-quantum header experiments: with
-- post-quantum cold keys and KES keys the certificate is several kilobytes,
-- and it changes only every few weeks.
data IssuerCert crypto = IssuerCert
  { icVk :: !(VKey BlockIssuer)
  -- ^ verification key of block issuer
  , icOCert :: !(OCert crypto)
  -- ^ operational certificate
  }
  deriving (Generic)

deriving instance Crypto crypto => Show (IssuerCert crypto)
deriving instance Crypto crypto => Eq (IssuerCert crypto)

instance Crypto crypto => NoThunks (IssuerCert crypto)

instance Crypto crypto => EncCBOR (IssuerCert crypto) where
  encCBOR IssuerCert {icVk, icOCert} =
    encode $ Rec IssuerCert !> To icVk !> To icOCert

instance Crypto crypto => DecCBOR (IssuerCert crypto) where
  decCBOR = decode $ RecD IssuerCert <! From <! mapCoder unCBORGroup From

data HeaderBody crypto = HeaderBody
  { hbBlockNo :: !BlockNo
  -- ^ block number
  , hbSlotNo :: !SlotNo
  -- ^ block slot
  , hbPrev :: !PrevHash
  -- ^ Hash of the previous block header
  , hbIssuer :: !(KeyHash BlockIssuer)
  -- ^ hash of the block issuer's cold verification key
  , hbIssueNo :: !Word64
  -- ^ counter of the operational certificate in force for this header; equal
  -- to the certificate's counter when 'hbOCert' is present
  , hbVrfVk :: !(VRF.VerKeyVRF (VRF crypto))
  -- ^ VRF verification key for block issuer
  , hbVrfRes :: !(VRF.CertifiedVRF (VRF crypto) InputVRF)
  -- ^ Certified VRF value
  , hbBodySize :: !Word32
  -- ^ Size of the block body
  , hbBodyHash :: !(Hash.Hash HASH EraIndependentBlockBody)
  -- ^ Hash of block body
  , hbOCert :: !(StrictMaybe (IssuerCert crypto))
  -- ^ cold key and operational certificate, only when the KES key rotated
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
      , hbIssueNo
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
          !> To hbIssueNo
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
