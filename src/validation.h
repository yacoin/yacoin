// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2024 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YACOIN_CONSENSUS_VALIDATION_H
#define YACOIN_CONSENSUS_VALIDATION_H

#include <string>
#include <unordered_map>

#include "uint256.h"

/** Headers download timeout expressed in microseconds
 *  Timeout = base + per_header * (expected number of headers) */
extern int64_t HEADERS_DOWNLOAD_TIMEOUT_BASE; // 15 minutes
extern int64_t BLOCK_DOWNLOAD_TIMEOUT_BASE; // 15 minutes
// For YACoin, we don't use this constant because we will reset the timeout at the time we receive the header
//static const int64_t HEADERS_DOWNLOAD_TIMEOUT_PER_HEADER = 1000; // 1ms/header
/** Additional block download timeout per parallel downloading peer (i.e. 5 min) */
static const int64_t BLOCK_DOWNLOAD_TIMEOUT_PER_PEER = 500000;
/** Timeout in seconds during which a peer must stall block download progress before being disconnected. */
static const unsigned int BLOCK_STALLING_TIMEOUT = 2;
/** Number of headers sent in one getheaders result. We rely on the assumption that if a peer sends
 *  less than this number, we reached their tip. Changing this value is a protocol upgrade. */
static unsigned int MAX_HEADERS_RESULTS = 2000;
/** Number of blocks that can be requested at any given time from a single peer. */
extern int MAX_BLOCKS_IN_TRANSIT_PER_PEER;
/** Size of the "block download window": how far ahead of our current height do we fetch?
 *  Larger windows tolerate larger download speed differences between peer, but increase the potential
 *  degree of disordering of blocks on disk (which make reindexing and in the future perhaps pruning
 *  harder). We'll probably want to make this a per-peer adaptive value at some point. */
extern unsigned int BLOCK_DOWNLOAD_WINDOW; //32000
extern unsigned int FETCH_BLOCK_DOWNLOAD; //4000
// Trigger sending getblocks from other peers when header > block + HEADER_BLOCK_DIFFERENCES_TRIGGER_GETDATA
extern unsigned int HEADER_BLOCK_DIFFERENCES_TRIGGER_GETBLOCKS; //default = 10000
extern int64_t nMaxTipAge;

/** Maximum depth of blocks we're willing to serve as compact blocks to peers
 *  when requested. For older blocks, a regular BLOCK response will be sent. */
static const int MAX_CMPCTBLOCK_DEPTH = 5;

/** Maximum number of headers to announce when relaying blocks with headers message.*/
static const unsigned int MAX_BLOCKS_TO_ANNOUNCE = 8;

/** Maximum number of unconnecting headers announcements before DoS score */
static const int MAX_UNCONNECTING_HEADERS = 10;
/** Maximum length of reject messages. */

static const unsigned int MAX_REJECT_MESSAGE_LENGTH = 111;
/** Reject codes greater or equal to this can be returned by AcceptToMemPool
 * for transactions, to signal internal conditions. They cannot and should not
 * be sent over the P2P network.
 */
static const unsigned int REJECT_INTERNAL = 0x100;
/** Too high fee. Can not be triggered by P2P transactions */
static const unsigned int REJECT_HIGHFEE = 0x100;

/** Default for DEFAULT_WHITELISTRELAY. */
static const bool DEFAULT_WHITELISTRELAY = true;
/** Default for DEFAULT_WHITELISTFORCERELAY. */
static const bool DEFAULT_WHITELISTFORCERELAY = true;

/** Average delay between local address broadcasts in seconds. */
static const unsigned int AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL = 24 * 60 * 60;
/** Average delay between peer address broadcasts in seconds. */
static const unsigned int AVG_ADDRESS_BROADCAST_INTERVAL = 30;

/** Average delay between trickled inventory transmissions in seconds.
 *  Blocks and whitelisted receivers bypass this, outbound peers get half this delay. */
static const unsigned int INVENTORY_BROADCAST_INTERVAL = 5;
/** Maximum number of inventory items to send per transmission.
 *  Limits the impact of low-fee transaction floods. */
static const unsigned int INVENTORY_BROADCAST_MAX = 7 * INVENTORY_BROADCAST_INTERVAL;

static const int64_t DEFAULT_MAX_TIP_AGE = 24 * 60 * 60;

class CBlockIndex;
/** "reject" message codes */
static const unsigned char REJECT_MALFORMED = 0x01;
static const unsigned char REJECT_INVALID = 0x10;
static const unsigned char REJECT_OBSOLETE = 0x11;
static const unsigned char REJECT_DUPLICATE = 0x12;
static const unsigned char REJECT_NONSTANDARD = 0x40;
// static const unsigned char REJECT_DUST = 0x41; // part of BIP 61
static const unsigned char REJECT_INSUFFICIENTFEE = 0x42;
static const unsigned char REJECT_CHECKPOINT = 0x43;

class CValidationState;

/** Convert CValidationState to a human-readable message for logging */
std::string FormatStateMessage(const CValidationState &state);
bool AbortNode(const std::string &msg);

/** Capture information about block/transaction validation */
class CValidationState {
private:
    enum mode_state {
        MODE_VALID,   // everything ok
        MODE_INVALID, // network rule violation (DoS value may be set)
        MODE_ERROR,   // run-time error
    } mode;
    int nDoS;
    std::string strRejectReason;
    unsigned int chRejectCode;
    bool corruptionPossible;
    std::string strDebugMessage;
    uint256 failedTransaction;
public:
    CValidationState() : mode(MODE_VALID), nDoS(0), chRejectCode(0), corruptionPossible(false) {}
    bool DoS(int level, bool ret = false,
             unsigned char chRejectCodeIn=0, const std::string &strRejectReasonIn="",
             bool corruptionIn=false,
             const std::string &strDebugMessageIn="") {
        chRejectCode = chRejectCodeIn;
        strRejectReason = strRejectReasonIn;
        corruptionPossible = corruptionIn;
        strDebugMessage = strDebugMessageIn;
        if (mode == MODE_ERROR)
            return ret;
        nDoS += level;
        mode = MODE_INVALID;
        return ret;
    }
    bool Invalid(bool ret = false,
                 unsigned char _chRejectCode=0, std::string _strRejectReason="") {
        return DoS(0, ret, _chRejectCode, _strRejectReason);
    }
    bool Error() {
        mode = MODE_ERROR;
        return false;
    }
    bool Abort(const std::string &msg) {
        AbortNode(msg);
        return Error();
    }
    bool IsValid() const {
        return mode == MODE_VALID;
    }
    bool IsInvalid() const {
        return mode == MODE_INVALID;
    }
    bool IsError() const {
        return mode == MODE_ERROR;
    }
    bool IsInvalid(int &nDoSOut) const {
        if (IsInvalid()) {
            nDoSOut = nDoS;
            return true;
        }
        return false;
    }
    bool CorruptionPossible() const {
        return corruptionPossible;
    }
    void SetCorruptionPossible() {
        corruptionPossible = true;
    }
    void SetFailedTransaction(const uint256& txhash) {
        failedTransaction = txhash;
    }
    uint256 GetFailedTransaction() {
        return failedTransaction;
    }
    bool IsTransactionError() const  {
        return failedTransaction != uint256();
    }
    unsigned char GetRejectCode() const { return chRejectCode; }
    std::string GetRejectReason() const { return strRejectReason; }
    std::string GetDebugMessage() const { return strDebugMessage; }
};

struct BlockHasher
{
    size_t operator()(const uint256& hash) const { return hash.GetCheapHash(); }
};

typedef std::unordered_map<uint256, CBlockIndex*, BlockHasher> BlockMap;

#endif // YACOIN_CONSENSUS_VALIDATION_H
