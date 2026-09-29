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

-- Experimental KES selection for the post-quantum header experiments.
-- The scheme is chosen at compile time with CPP defines, normally set from a
-- @cabal.project@ stanza such as
--
-- > package cardano-protocol
-- >   ghc-options: -DPQ_KES_MLDSA44 -DPQ_KES_PAD=3636 -DPQ_KES_SPIN=0
--
-- * @PQ_KES_MLDSA44@: use @HashedCompactSum6KES MLDSA44DSIGN Blake2b_256@
--   (3924-byte signatures) instead of mainnet's @Sum6KES Ed25519DSIGN@.
-- * @PQ_KES_PAD@: zero bytes appended to every KES signature (default 0).
-- * @PQ_KES_SPIN@: microseconds of busy waiting after each successful KES
--   verification (default 0).
--
-- Every variant, including the default, goes through 'KES.PaddedKES', so all
-- experiment runs exercise the same code path. With no defines the scheme is
-- byte-for-byte mainnet's; only its algorithm name differs.
#ifndef PQ_KES_PAD
#define PQ_KES_PAD 0
#endif
#ifndef PQ_KES_SPIN
#define PQ_KES_SPIN 0
#endif

#if defined(PQ_KES_MLDSA44)
type StandardKESInner = KES.HashedCompactSum6KES MLDSA44DSIGN Blake2b_256
#else
type StandardKESInner = KES.Sum6KES Ed25519DSIGN Blake2b_256
#endif

instance Crypto StandardCrypto where
  type KES StandardCrypto = KES.PaddedKES PQ_KES_PAD PQ_KES_SPIN StandardKESInner
  type VRF StandardCrypto = VRF.PraosVRF
