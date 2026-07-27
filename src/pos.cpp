// Copyright (c) 2026 The RuxCrypto Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pos.h"

#include "primitives/block.h"
#include "primitives/transaction.h"

bool IsPoSEnabled(int nHeight, const Consensus::Params& params)
{
    // A height of 0 would mean "always on", which is never what we want on a
    // chain that has PoW history, so treat only a positive value as configured.
    return params.nPoSForkHeight > 0 && nHeight >= params.nPoSForkHeight;
}

bool IsPoWDisabled(int nHeight, const Consensus::Params& params)
{
    return params.nPoWDisableHeight > 0 && nHeight >= params.nPoWDisableHeight;
}

bool BlockIsProofOfStake(const CBlock& block)
{
    return block.vtx.size() > 1 && block.vtx[1] && block.vtx[1]->IsCoinStake();
}
