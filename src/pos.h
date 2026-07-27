// Copyright (c) 2026 The RuxCrypto Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef RUXCRYPTO_POS_H
#define RUXCRYPTO_POS_H

#include "consensus/params.h"

class CBlock;

/**
 * Proof-of-Stake transition.
 *
 * RuxCrypto started as pure proof-of-work. The transition happens in two steps,
 * both keyed on block height so that the ENTIRE historical chain keeps
 * validating under the rules it was mined with:
 *
 *   below nPoSForkHeight      pure PoW, exactly as before
 *   nPoSForkHeight..          hybrid: blocks may be PoW or PoS
 *   nPoWDisableHeight..       PoS only, mining is over
 *
 * See doc/RXC-PoS-design.md. These predicates are the seams the later steps
 * hook into; on their own they change nothing.
 */

/** True once staking is allowed, i.e. inside the hybrid window or past it. */
bool IsPoSEnabled(int nHeight, const Consensus::Params& params);

/** True once proof-of-work blocks must be rejected. */
bool IsPoWDisabled(int nHeight, const Consensus::Params& params);

/**
 * A block is proof-of-stake when its second transaction is a coinstake.
 * (The first stays a coinbase, empty on PoS blocks, so that existing code which
 * assumes vtx[0] is the coinbase keeps working.)
 */
bool BlockIsProofOfStake(const CBlock& block);

#endif // RUXCRYPTO_POS_H
