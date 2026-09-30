{-# LANGUAGE CPP #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

-- | Package all the crypto constraints into one place.
module Cardano.Protocol.Crypto (
  Crypto (..),
  StandardCrypto,
  VRFVerKeyHash (..),
  KeyRoleVRF (..),
  hashVerKeyVRF,
) where

import Cardano.Crypto.DSIGN
import Cardano.Crypto.Hash as Hash
import qualified Cardano.Crypto.KES as KES
import qualified Cardano.Crypto.VRF as VRF
import qualified Cardano.Crypto.VRF.Praos as VRF
import Cardano.Ledger.Hashes
import Data.Kind (Type)
import Data.Typeable (Typeable)

hashVerKeyVRF :: Crypto c => VRF.VerKeyVRF (VRF c) -> VRFVerKeyHash (r :: KeyRoleVRF)
hashVerKeyVRF = VRFVerKeyHash . Hash.castHash . VRF.hashVerKeyVRF

class
  ( KES.UnsoundPureKESAlgorithm (KES c)
  , VRF.VRFAlgorithm (VRF c)
  , KES.ContextKES (KES c) ~ ()
  , VRF.ContextVRF (VRF c) ~ ()
  , Typeable c
  ) =>
  Crypto c
  where
  type KES c :: Type
  type VRF c :: Type

-- ================================

-- | The same crypto used on the net
data StandardCrypto

-- Experimental scheme selection for the post-quantum header experiments.
-- The schemes are chosen at compile time with CPP defines, normally set from a
-- @cabal.project.local@ stanza such as
--
-- > package cardano-protocol
-- >   ghc-options: -DPQ_KES_MLDSA44 -DPQ_VRF_PAD=1000
--
-- * @PQ_KES_MLDSA44@: use @HashedCompactSum6KES MLDSA44DSIGN Blake2b_256@
--   (3924-byte signatures) instead of mainnet's @Sum6KES Ed25519DSIGN@.
-- * @PQ_VRF_PAD@: zero bytes appended to every VRF proof (default 0), to
--   give headers the proof size a post-quantum VRF would have. The VRF is
--   otherwise mainnet's @PraosVRF@.
--
-- The cold key and every other ledger signature are selected separately in
-- "Cardano.Ledger.Keys" with @PQ_DSIGN_MLDSA44@.
#ifndef PQ_VRF_PAD
#define PQ_VRF_PAD 0
#endif

#if defined(PQ_KES_MLDSA44)
type StandardKES = KES.HashedCompactSum6KES MLDSA44DSIGN Blake2b_256
#else
type StandardKES = KES.Sum6KES Ed25519DSIGN Blake2b_256
#endif

instance Crypto StandardCrypto where
  type KES StandardCrypto = StandardKES
  type VRF StandardCrypto = VRF.PaddedVRF PQ_VRF_PAD VRF.PraosVRF
