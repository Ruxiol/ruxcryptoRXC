// Copyright (c) 2026 The RuxCrypto Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef RUXCRYPTO_POS_H
#define RUXCRYPTO_POS_H

#include "amount.h"
#include "consensus/params.h"
#include "uint256.h"

class CBlock;
class CBlockIndex;
class COutPoint;

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

/** Same, against the active chain's parameters. For callers like the block index
 *  serializer that have a height but no params in hand. */
bool IsPoSEnabled(int nHeight);

/** True once proof-of-work blocks must be rejected. */
bool IsPoWDisabled(int nHeight, const Consensus::Params& params);

/**
 * A block is proof-of-stake when its second transaction is a coinstake.
 * (The first stays a coinbase, empty on PoS blocks, so that existing code which
 * assumes vtx[0] is the coinbase keeps working.)
 *
 * Thin wrapper over CBlock::IsProofOfStake(), which is where the rule actually
 * lives -- the serializer in primitives/block.h needs it too, and the two must
 * never drift apart.
 */
bool BlockIsProofOfStake(const CBlock& block);

/**
 * The same question asked of a block index entry, which has no transactions.
 *
 * It leans on the nNonce marker rather than a new field: above the fork,
 * ContextualCheckBlock refuses any block whose marker and coinstake disagree, so
 * by the time an entry exists the marker is trustworthy. Below the fork it is
 * not consulted at all and every block is proof-of-work, which is the truth.
 */
bool BlockIndexIsProofOfStake(const CBlockIndex* pindex, const Consensus::Params& params);

/**
 * Verify the signature a staker attaches to their block.
 *
 * Proof-of-work needs no signature: the work itself is the claim. Proof-of-stake
 * has nothing equivalent, so the staker signs the block hash with the key that
 * controls the output being staked, and CBlock::vchBlockSig carries it. Without
 * this check anyone could take someone else's coinstake and reuse it.
 *
 * A proof-of-work block must carry an EMPTY signature. That is not pedantry:
 * vchBlockSig is only serialized for PoS blocks, so a PoW block arriving with a
 * non-empty one could only have been built in memory, never parsed off the wire.
 */
bool CheckBlockSignature(const CBlock& block);

/**
 * The stake modifier: the one input to the kernel a staker cannot choose.
 *
 * A proof-of-work miner grinds nNonce until the hash comes out small. A staker
 * has no nonce -- the coins are fixed, the outpoint is fixed, and the only knob
 * left is time. So without further mixing, a staker holding a given coin could
 * sit down today and compute every block they will be entitled to for months
 * ahead, then arrange their transactions around it.
 *
 * The modifier closes that off. Each block folds something it cannot know in
 * advance into the previous block's modifier, so the chain of modifiers only
 * becomes determined as the chain itself is built. Grinding future kernels means
 * first predicting every block in between.
 *
 * @param pindexPrev  previous block, or nullptr at genesis
 * @param kernel      the per-block entropy: for a PoS block the outpoint hash of
 *                    the coin being staked, for a PoW block the block hash
 */
uint256 ComputeStakeModifier(const CBlockIndex* pindexPrev, const uint256& kernel);

/** The entropy ComputeStakeModifier() should be given for this block. */
uint256 StakeModifierKernelFor(const CBlock& block);

/**
 * The kernel check -- the proof-of-stake analogue of "does the hash meet nBits".
 *
 *     hash(modifier, prevout, nTime) / weight  <=  target
 *
 * Weight is the staked amount in whole coins, so ten times the stake means ten
 * times the chance, exactly as ten times the hashrate would. Note the division:
 * the textbook form is hash <= target * weight, but with a large stake that
 * product can run past 256 bits and silently wrap, handing an attacker a target
 * of nearly zero difficulty. Dividing the hash instead cannot overflow.
 *
 * @param hashProofOfStake  out: the kernel hash, recorded in the block index
 */
bool CheckStakeKernelHash(unsigned int nBits,
                          const uint256& nStakeModifier,
                          const COutPoint& prevout,
                          CAmount nValueIn,
                          unsigned int nTimeTx,
                          const Consensus::Params& params,
                          uint256& hashProofOfStake);

#endif // RUXCRYPTO_POS_H
