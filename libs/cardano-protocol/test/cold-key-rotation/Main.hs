{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Main (main) where

import qualified Cardano.Crypto.DSIGN as DSIGN
import qualified Cardano.Crypto.Hash as Hash
import Cardano.Crypto.Init (cryptoInit)
import qualified Cardano.Crypto.KES as KES
import Cardano.Crypto.Seed (mkSeedFromBytes)
import Cardano.Crypto.Util (getSignableRepresentation)
import qualified Cardano.Crypto.VRF as VRF
import Cardano.Ledger.BaseTypes (Nonce (..), ProtVer (..), StrictMaybe (..), natVersion)
import Cardano.Ledger.Binary (FixedSizeCodec (..), decCBOR, decodeFull', decodeFullAnnotator, serialize')
import Cardano.Ledger.Keys (DSIGN, VKey (..), coerceKeyRole, hashKey, signedDSIGN)
import qualified Cardano.Ledger.State as SL
import Cardano.Protocol.Crypto (KES, StandardCrypto)
import Cardano.Protocol.Praos.BlockHeader
import Cardano.Protocol.Praos.VRF (mkInputVRF)
import Cardano.Protocol.TPraos.BlockHeader (PrevHash (..))
import Cardano.Protocol.TPraos.OCert (KESPeriod (..), OCert (..), OCertSignable (..))
import Cardano.Slotting.Slot (SlotNo (..))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Test.Tasty (TestTree, defaultMain, testGroup)
import Test.Tasty.HUnit (assertBool, testCase, (@?=))

main :: IO ()
main = cryptoInit >> defaultMain tests

tests :: TestTree
tests = testGroup "Cold-key rotation encoding"
  [ testCase "header codec round trips with and without authentication" $ do
      roundtrip first @?= Right first
      roundtrip ordinary @?= Right ordinary
  , testCase "ordinary header omits cold authentication bytes" $
      assertBool "cached header is smaller" (headerSize ordinary < headerSize first)
  , testCase "ML-DSA OpCert CBOR roundtrip" $
      decodeFull' (natVersion @9) (serialize' (natVersion @9) pqOCert) @?= Right pqOCert
  ]
  where
    seed n = mkSeedFromBytes $ BS.replicate 32 n
    cold = DSIGN.genKeyDSIGN @DSIGN $ seed 1
    coldKey = VKey $ DSIGN.deriveVerKeyDSIGN cold
    issuer = hashKey coldKey
    hot = KES.unsoundPureGenKeyKES @(KES StandardCrypto) $ seed 2
    hotKey = KES.unsoundPureDeriveVerKeyKES hot
    oc = OCert hotKey 0 (KESPeriod 10) (signedDSIGN cold $ OCertSignable hotKey 0 (KESPeriod 10))
    vrf = VRF.genKeyVRF $ seed 4
    body = HeaderBody
      { hbBlockNo = 1
      , hbSlotNo = SlotNo 100
      , hbPrev = GenesisHash
      , hbIssuer = issuer
      , hbVrfVk = VRF.deriveVerKeyVRF vrf
      , hbVrfRes = VRF.evalCertified () (mkInputVRF (SlotNo 100) NeutralNonce) vrf
      , hbBodySize = 0
      , hbBodyHash = Hash.castHash (Hash.hashWith id BS.empty)
      , hbOCert = mkHeaderOCert coldKey oc
      , hbProtVer = ProtVer (natVersion @9) 0
      }
    sign b = Header b (KES.SignedKES $ KES.unsoundPureSignKES () 0 b hot)
    first = sign body
    ordinary = sign body{hbBlockNo = 2, hbSlotNo = SlotNo 101, hbOCert = (hbOCert body){hocAuth = SNothing}}
    roundtrip hdr = decodeFullAnnotator @(Header StandardCrypto)
      (natVersion @9) "Header" decCBOR (LBS.fromStrict $ serialize' (natVersion @9) hdr)
    pqKey = DSIGN.genKeyDSIGN @DSIGN.MLDSA44DSIGN $ seed 18
    pqPublic = rawEncodeFixedSized $ DSIGN.deriveVerKeyDSIGN pqKey
    pqMessage = getSignableRepresentation
      (OCertSignableForScheme SL.ColdMLDSA44 (coerceKeyRole issuer) 1 hotKey 0 (KESPeriod 10) :: OCertSignable StandardCrypto)
    pqWitness = SL.ColdWitness pqPublic (rawEncodeFixedSized $ DSIGN.signDSIGN () pqMessage pqKey)
    pqOCert :: OCert StandardCrypto
    pqOCert = OCertMLDSA44 hotKey 0 (KESPeriod 10) pqWitness
