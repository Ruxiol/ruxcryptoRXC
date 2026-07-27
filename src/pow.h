// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include "consensus/params.h"

#include <stdint.h>

class CBlockHeader;
class CBlockIndex;
class uint256;

/**
 * Target seconds between blocks at a given height.
 *
 * The spacing changes at the fork, so it cannot simply be read out of the
 * parameters: the difficulty algorithm recomputes nBits for historical blocks
 * too, and feeding it the new spacing everywhere would make the node reject the
 * chain it already has.
 */
int64_t GetTargetSpacing(int nHeight, const Consensus::Params& params);

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&, bool fProofOfStake = false);
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params&);


/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&);

#endif // BITCOIN_POW_H
