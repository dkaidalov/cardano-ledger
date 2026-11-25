{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module Main (main) where

import qualified Cardano.Crypto.DSIGN as DSIGN
import Cardano.Crypto.Init (cryptoInit)
import Cardano.Crypto.Seed (mkSeedFromBytes)
import Cardano.Ledger.BaseTypes
import Cardano.Ledger.Binary (decodeFull', serialize', DecoderError, FixedSizeCodec (..))
import qualified Cardano.Crypto.Hash as H
import Cardano.Ledger.Alonzo.TxWits (coldAlonzoTxWitsL)
import Cardano.Ledger.Conway.Rules (validateColdWitnesses)
import Validation (Validation (..))
import Cardano.Ledger.Conway (ConwayEra)
import Cardano.Ledger.Conway.Governance (Voter (..), VotingProcedures (..))
import Cardano.Ledger.Conway.Core
import Cardano.Ledger.Conway.State
import Cardano.Ledger.Conway.TxCert (ConwayTxCert (..))
import Cardano.Ledger.Conway.UTxO (getConwayWitsVKeyNeeded, getConwayColdWitsNeeded)
import Cardano.Ledger.MemoBytes (EqRaw (..))
import Cardano.Ledger.Credential (Credential (..))
import Cardano.Ledger.Keys (DSIGN, VKey (..), asWitness, coerceKeyRole)
import Cardano.Ledger.Shelley.API.Forecast (EraForecast (..), futureForecast)
import Cardano.Ledger.Shelley.LedgerState
import Cardano.Ledger.Shelley.Rules (PoolEnv (..), ShelleyPoolreapState (..))
import Cardano.Slotting.EpochInfo (EpochInfo (..), fixedEpochInfo)
import Cardano.Slotting.Time (SystemStart (..), mkSlotLength)
import Test.Hspec (Spec, describe, hspec, it, runIO, shouldBe)
import Control.Monad.Reader (runReader)
import Control.State.Transition.Extended (TRC (..), applySTS)
import qualified Data.ByteString as BS
import Data.Default (def)
import Data.Either (isLeft, isRight)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromJust)
import qualified Data.Sequence.Strict as SSeq
import qualified Data.Set as Set
import Data.Word (Word64)
import Data.Time.Clock.POSIX (posixSecondsToUTCTime)
import Lens.Micro ((&), (.~), (^.))

main :: IO ()
main = do
  cryptoInit
  hspec $ describe "Cold-key rotation" scenario

scenario :: Spec
scenario = do
  let key n = hashKey . VKey . DSIGN.deriveVerKeyDSIGN @DSIGN . DSIGN.genKeyDSIGN @DSIGN $
        mkSeedFromBytes (BS.replicate 32 n)
      poolId = key 1
      b = key 2
      c = key 3
      owner = coerceKeyRole (key 4)
      params = def {sppId = poolId, sppOwners = Set.singleton owner,
                    sppAccountAddress = AccountAddress Testnet (AccountId (KeyHashObj owner))}
      pp = emptyPParams @ConwayEra & ppProtocolVersionL .~ ProtVer (natVersion @9) 0
            & ppEMaxL .~ EpochInterval 18
      runPool epoch st cert = runReader
        (applySTS @(EraRule "POOL" ConwayEra) (TRC (PoolEnv (EpochNo epoch) pp, st, cert))) globals
      request = ColdKeyRotation 0 ColdEd25519 b
      rotation = RegPoolWithRotation params request
  registered <- expectRight "pool registration" $ runPool 10 def (RegPool params)
  pending <- expectRight "rotation re-registration" $ runPool 10 registered rotation
  assert "pool identity, delegators and deposit unchanged" $ psStakePools pending == psStakePools registered
  assert "ordinary re-registration fields still queued" $ Map.lookup poolId (psFutureStakePoolParams pending) == Just params
  let authority = psColdKeys pending Map.! poolId
      active = activateColdKeyAuthority (EpochNo 12) authority
      activeState = pending{psColdKeys = Map.singleton poolId active}
  assert "old key active until boundary" $ ckaKey (activateColdKeyAuthority (EpochNo 11) authority) == poolId
  assert "new key active at boundary" $ ckaKey active == b && ckaGeneration active == 1
  assert "concurrent pending rotation rejected" $ isLeft $ runPool 10 pending rotation
  assert "unregistered rotation rejected" $ isLeft $ runPool 10 def rotation
  assert "stale generation rejected" $ isLeft $ runPool 12 activeState rotation
  second <- expectRight "second rotation accepted" $
    runPool 12 activeState (RegPoolWithRotation params (ColdKeyRotation 1 ColdEd25519 c))
  let twice = activateColdKeyAuthority (EpochNo 14) (psColdKeys second Map.! poolId)
  assert "second activation retains pool identity" $ ckaKey twice == c && ckaGeneration twice == 2
  assert "no-op rotation rejected" $ isLeft $
    runPool 12 activeState (RegPoolWithRotation params (ColdKeyRotation 1 ColdEd25519 b))
  assert "generation overflow rejected" $
    scheduleColdKeyRotation (EpochNo 12) (ColdKeyRotation maxBound ColdEd25519 c) active{ckaGeneration = maxBound} == Nothing
  assert "epoch overflow rejected" $
    scheduleColdKeyRotation (EpochNo maxBound) (ColdKeyRotation 1 ColdEd25519 c) active == Nothing
  assert "short epoch rejected for forecast safety" $ isLeft $ runReader
    (applySTS @(EraRule "POOL" ConwayEra) (TRC (PoolEnv (EpochNo 10) pp, registered, rotation)))
    globals{stabilityWindow = 100}
  let boundedInfo = (epochInfo globals){epochInfoSize_ = \epoch ->
        if epoch > EpochNo 10 then Left "past forecast horizon" else Right (EpochSize 100)}
  assert "rotation does not query beyond the forecast horizon" $ isRight $ runReader
    (applySTS @(EraRule "POOL" ConwayEra) (TRC (PoolEnv (EpochNo 10) pp, registered, rotation)))
    globals{epochInfo = boundedInfo}

  let certState = def & certPStateL .~ activeState :: CertState ConwayEra
      body cert = mkBasicTxBody @ConwayEra @TopTx & certsTxBodyL .~ SSeq.singleton cert
      needed txb = getConwayWitsVKeyNeeded certState (UTxO Map.empty) txb
      rotationBody = body $ ConwayTxCertPool (RegPoolWithRotation params (ColdKeyRotation 1 ColdEd25519 c))
  assert "rotation requires active key, replacement key and supplied owners" $
    needed rotationBody == Set.fromList [asWitness b, asWitness c, asWitness owner]
  assert "ordinary re-registration uses active authority" $
    needed (body (RegPoolTxCert params)) == Set.fromList [asWitness b, asWitness owner]
  assert "retirement uses active authority" $
    needed (body (RetirePoolTxCert poolId (EpochNo 15))) == Set.singleton (asWitness b)
  let voteBody = mkBasicTxBody @ConwayEra @TopTx & votingProceduresTxBodyL .~
        VotingProcedures (Map.singleton (StakePoolVoter poolId) Map.empty)
  assert "pool vote uses active authority" $ needed voteBody == Set.singleton (asWitness b)
  assert "explicit old-key requirement is preserved" $
    Set.member (asWitness poolId) $ needed (voteBody & reqSignerHashesTxBodyL .~ Set.singleton (coerceKeyRole poolId))

  let nes = def{nesEL = EpochNo 11} & nesEsL . esLStateL . lsCertStateL . certPStateL .~ pending
            & nesEsL . curPParamsEpochStateL .~ pp :: NewEpochState ConwayEra
      before = coldKeysForecast @ConwayEra (futureForecast globals (SlotNo 1199) nes)
      after = coldKeysForecast @ConwayEra (futureForecast globals (SlotNo 1200) nes)
  assert "forecast before activation preserves legacy authority" $ Map.null before
  assert "forecast at activation exposes replacement" $
    fmap ckaKey (Map.lookup poolId after) == Just b
  assert "forecast contains no mutable pending request" $
    all ((== SNothing) . ckaPending) after
  assert "forecast does not mutate original ledger state" $
    ckaKey (psColdKeys pending Map.! poolId) == poolId

  let cert = ConwayTxCertPool rotation :: ConwayTxCert ConwayEra
  assert "rotation certificate CBOR roundtrip" $
    decodeFull' (natVersion @9) (serialize' (natVersion @9) cert) == Right cert
  assert "ledger authority CBOR roundtrip" $
    decodeFull' (natVersion @9) (serialize' (natVersion @9) pending) == Right pending
  let reap epoch st = runReader
        (applySTS @(EraRule "POOLREAP" ConwayEra)
          (TRC ((), PoolreapState def def (def & certPStateL .~ st), EpochNo epoch))) globals
  activated <- expectRight "epoch processing activates authority" $ reap 12 pending
  assert "POOLREAP installs the replacement authority" $
    fmap ckaKey (Map.lookup poolId (psColdKeys (prCertState activated ^. certPStateL))) == Just b
  retiring <- expectRight "retirement request" $ runPool 12 activeState (RetirePool poolId (EpochNo 13))
  retired <- expectRight "pool retirement processing" $ reap 13 retiring
  let retiredState = prCertState retired ^. certPStateL
  assert "retirement preserves authority tombstone" $
    Map.notMember poolId (psStakePools retiredState) && Map.lookup poolId (psColdKeys retiredState) == Just active
  assert "re-registration after retirement requires replacement authority" $
    getConwayWitsVKeyNeeded (prCertState retired) (UTxO Map.empty) (body (RegPoolTxCert params))
      == Set.fromList [asWitness b, asWitness owner]
  assert "retired pool can re-register without resetting authority" $ isRight $ runPool 13 retiredState (RegPool params)

  let pqKey = DSIGN.genKeyDSIGN @DSIGN.MLDSA44DSIGN (mkSeedFromBytes (BS.replicate 32 17))
      pqPublic = rawEncodeFixedSized $ DSIGN.deriveVerKeyDSIGN pqKey
      pqHash = coldKeyHash pqPublic
      pqRequest = ColdKeyRotation 1 ColdMLDSA44 pqHash
      pqBody = body (ConwayTxCertPool (RegPoolWithRotation params pqRequest))
      pqTx = mkBasicTx pqBody
      message = H.hashToBytes $ extractHash $ hashAnnotated @_ @EraIndependentTxBody pqBody
      witness = ColdWitness pqPublic (rawEncodeFixedSized $ DSIGN.signDSIGN () message pqKey)
      signedTx = pqTx & witsTxL . coldAlonzoTxWitsL .~ Set.singleton witness
      valid tx = case validateColdWitnesses certState tx of
        Success () -> True
        Failure _ -> False
  assert "mixed rotation keeps Ed25519 incumbent and owner witnesses" $
    needed pqBody == Set.fromList [asWitness b, asWitness owner]
  assert "mixed rotation requires replacement ML-DSA witness" $
    getConwayColdWitsNeeded certState pqBody == Set.singleton pqHash
  assert "valid ML-DSA proof of possession accepted" $ valid signedTx
  assert "missing ML-DSA proof rejected" $ not $ valid pqTx
  assert "ML-DSA witness bound to transaction body" $ not $ valid $
    signedTx & bodyTxL . reqSignerHashesTxBodyL .~ Set.singleton (coerceKeyRole poolId)
  assert "invalid ML-DSA signature rejected" $ not $ valid $
    pqTx & witsTxL . coldAlonzoTxWitsL .~ Set.singleton (ColdWitness pqPublic (BS.replicate 2420 0))
  assert "cold witness cannot authorize unrelated transaction" $ not $ valid $
    signedTx & bodyTxL .~ body (RegPoolTxCert params)
  assert "ML-DSA witness CBOR roundtrip" $
    decodeFull' (natVersion @9) (serialize' (natVersion @9) witness) == Right witness
  assert "unknown cold scheme rejected" $
    isLeft (decodeFull' (natVersion @9) (BS.pack [2]) :: Either DecoderError ColdScheme)
  assert "ML-DSA witness lengths checked during decoding" $
    isLeft (decodeFull' (natVersion @9) (serialize' (natVersion @9) (ColdWitness BS.empty BS.empty)) :: Either DecoderError ColdWitness)
  pqPending <- expectRight "mixed rotation accepted by POOL" $
    runPool 12 activeState (RegPoolWithRotation params pqRequest)
  let pqActive = activateColdKeyAuthority (EpochNo 14) (psColdKeys pqPending Map.! poolId)
      pqState = certState & certPStateL .~ pqPending{psColdKeys = Map.singleton poolId pqActive}
      management = body (RegPoolTxCert params)
      retirement = body (RetirePoolTxCert poolId (EpochNo 16))
  let coldOnly = mkBasicTxWits @ConwayEra & coldAlonzoTxWitsL .~ Set.singleton witness
      combined = coldOnly <> mkBasicTxWits @ConwayEra
      pqNes = nes{nesEL = EpochNo 13} & nesEsL . esLStateL . lsCertStateL . certPStateL .~ pqPending
      pqForecast = coldKeysForecast @ConwayEra (futureForecast globals (SlotNo 1400) pqNes)
  assert "witness merging preserves ML-DSA authentication" $ combined ^. coldTxWitsG == Set.singleton witness
  assert "raw witness equality includes ML-DSA authentication" $ not $ eqRaw coldOnly (mkBasicTxWits @ConwayEra)
  assert "forecast activates ML-DSA scheme and key together" $
    fmap (\a -> (ckaScheme a, ckaKey a)) (Map.lookup poolId pqForecast) == Just (ColdMLDSA44, pqHash)
  assert "legacy authority decoder supplies Ed25519 scheme" $
    decodeFull' (natVersion @9) (serialize' (natVersion @9) (b, 1 :: Word64, SNothing :: StrictMaybe PendingColdKey))
      == Right (ColdKeyAuthority b ColdEd25519 1 SNothing)
  assert "legacy rotation decoder supplies Ed25519 scheme" $
    decodeFull' (natVersion @9) (serialize' (natVersion @9) (1 :: Word64, b)) == Right (ColdKeyRotation 1 ColdEd25519 b)
  assert "ML-DSA scheme activates with its key" $ ckaScheme pqActive == ColdMLDSA44 && ckaGeneration pqActive == 2
  assert "ML-DSA management retains ordinary owner requirement" $
    getConwayWitsVKeyNeeded pqState (UTxO Map.empty) management == Set.singleton (asWitness owner)
  assert "ML-DSA pool management requires active PQ key" $ getConwayColdWitsNeeded pqState management == Set.singleton pqHash
  assert "ML-DSA retirement requires active PQ key" $ getConwayColdWitsNeeded pqState retirement == Set.singleton pqHash
  assert "ML-DSA pool voting requires active PQ key" $ getConwayColdWitsNeeded pqState voteBody == Set.singleton pqHash
  assert "explicit signer remains an ordinary witness even with matching PQ hash" $
    Set.member (asWitness pqHash) $ getConwayWitsVKeyNeeded pqState (UTxO Map.empty)
      (management & reqSignerHashesTxBodyL .~ Set.singleton (coerceKeyRole pqHash))
  assert "ML-DSA authority state roundtrip" $
    decodeFull' (natVersion @9) (serialize' (natVersion @9) pqActive) == Right pqActive
  where
    assert label ok = it label $ ok `shouldBe` True
    expectRight label result = runIO $ either (fail . ((label ++ ": ") ++) . show) pure result

globals :: Globals
globals = Globals
  { epochInfo = fixedEpochInfo (EpochSize 100) (mkSlotLength 1)
  , slotsPerKESPeriod = 20
  , stabilityWindow = 33
  , randomnessStabilisationWindow = 33
  , securityParameter = knownNonZeroBounded @10
  , maxKESEvo = 10
  , quorum = 5
  , maxLovelaceSupply = 45000000000000000
  , activeSlotCoeff = mkActiveSlotCoeff (fromJust $ boundRational 0.9)
  , networkId = Testnet
  , systemStart = SystemStart $ posixSecondsToUTCTime 0
  }
