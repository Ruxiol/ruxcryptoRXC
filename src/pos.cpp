// Copyright (c) 2026 The RuxCrypto Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pos.h"

#include "arith_uint256.h"
#include "chain.h"
#include "chainparams.h"
#include "hash.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/standard.h"

bool IsPoSEnabled(int nHeight, const Consensus::Params& params)
{
    // A height of 0 would mean "always on", which is never what we want on a
    // chain that has PoW history, so treat only a positive value as configured.
    return params.nPoSForkHeight > 0 && nHeight >= params.nPoSForkHeight;
}

bool IsPoSEnabled(int nHeight)
{
    return IsPoSEnabled(nHeight, Params().GetConsensus());
}

bool IsPoWDisabled(int nHeight, const Consensus::Params& params)
{
    return params.nPoWDisableHeight > 0 && nHeight >= params.nPoWDisableHeight;
}

bool BlockIsProofOfStake(const CBlock& block)
{
    return block.IsProofOfStake();
}

bool CheckBlockSignature(const CBlock& block)
{
    if (!block.IsProofOfStake())
        return block.vchBlockSig.empty();

    if (block.vchBlockSig.empty())
        return false;

    if (block.vtx[1]->vout.size() < 2 || block.vtx[1]->vin.empty())
        return false;

    // The signing key comes from the coinstake's INPUT, not from its output.
    //
    // Reading it from the output forced the stake to be paid back to the same
    // address it came from -- that was the only way the verifier could find the
    // key. The cost was privacy: a staker's address appeared in every block they
    // ever won, and every output they held was threaded onto that one public
    // name for anyone reading the chain. Proof-of-work has nothing like it.
    //
    // The input proves ownership just as well, and is the thing that actually
    // does. A P2PKH scriptSig is <sig> <pubkey>, and ConnectBlock's script
    // validation already establishes that this key may spend the staked coin --
    // so a signature made by it is exactly the proof this check is looking for,
    // and the output is then free to be a fresh address every time.
    //
    // Old blocks are unaffected: they paid the stake back to the same key, so
    // input and output name the same signer and both readings agree.
    const CScript& scriptSig = block.vtx[1]->vin[0].scriptSig;
    std::vector<unsigned char> vchPubKey;
    {
        CScript::const_iterator pc = scriptSig.begin();
        opcodetype opcode;
        std::vector<unsigned char> vchPush;
        while (scriptSig.GetOp(pc, opcode, vchPush)) {
            if (opcode > OP_16)
                return false;  // a staking scriptSig is pushes only
            vchPubKey = vchPush;  // keep the last push: the pubkey
        }
    }

    CPubKey pubKey(vchPubKey);
    if (pubKey.IsValid())
        return pubKey.Verify(block.GetHash(), block.vchBlockSig);

    // A pay-to-pubkey input carries no key in its scriptSig, only a signature,
    // so for those the output still has to name the signer -- and the wallet
    // pays such a stake back to the same script for exactly that reason.
    txnouttype whichType;
    std::vector<std::vector<unsigned char> > vSolutions;
    if (!Solver(block.vtx[1]->vout[1].scriptPubKey, whichType, vSolutions))
        return false;
    if (whichType != TX_PUBKEY)
        return false;

    return CPubKey(vSolutions[0]).Verify(block.GetHash(), block.vchBlockSig);
}

bool IsQuorumTypeActive(Consensus::LLMQType type, int nHeight, const Consensus::Params& params)
{
    if (params.llmqsFromPoSFork.count(type))
        return IsPoSEnabled(nHeight, params);

    return true;
}

bool BlockIndexIsProofOfStake(const CBlockIndex* pindex, const Consensus::Params& params)
{
    return pindex && IsPoSEnabled(pindex->nHeight, params) && pindex->nNonce == 0;
}

uint256 ComputeStakeModifier(const CBlockIndex* pindexPrev, const uint256& kernel)
{
    if (!pindexPrev)
        return uint256();  // genesis has nothing behind it to mix in

    CHashWriter ss(SER_GETHASH, 0);
    ss << kernel << pindexPrev->nStakeModifier;
    return ss.GetHash();
}

uint256 StakeModifierKernelFor(const CBlock& block)
{
    // A PoS block contributes the coin it spent: chosen by the staker, but only
    // once, and public from that point on. A PoW block contributes its own hash,
    // which the miner had to burn work to move. Either way the next modifier
    // depends on something that could not be known before this block existed.
    if (block.IsProofOfStake())
        return block.vtx[1]->vin[0].prevout.hash;

    return block.GetHash();
}

bool CheckStakeKernelHash(unsigned int nBits,
                          const uint256& nStakeModifier,
                          const COutPoint& prevout,
                          CAmount nValueIn,
                          unsigned int nTimeTx,
                          const Consensus::Params& params,
                          uint256& hashProofOfStake)
{
    if (nValueIn < params.nStakeMinAmount)
        return false;

    // Time is the staker's only free variable, so it is pinned to a grid.
    if ((nTimeTx & params.nStakeTimestampMask) != 0)
        return false;

    CHashWriter ss(SER_GETHASH, 0);
    ss << nStakeModifier << prevout.hash << prevout.n << nTimeTx;
    hashProofOfStake = ss.GetHash();

    arith_uint256 bnTarget;
    bool fNegative, fOverflow;
    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0)
        return false;

    // Weight in whole coins, never zero: nStakeMinAmount already guarantees at
    // least one, but the guard costs nothing and a division by zero would be
    // a consensus fault rather than a crash on one node.
    arith_uint256 bnWeight = arith_uint256(nValueIn / COIN);
    if (bnWeight == 0)
        return false;

    return (UintToArith256(hashProofOfStake) / bnWeight) <= bnTarget;
}
