#include "primitives/transaction.h"
#include "primitives/block.h"
#include <map>
#include <vector>

#ifndef BITCOIN_TXMEMPOOL_H
#define BITCOIN_TXMEMPOOL_H

class CTxDB;
class CTxMemPool
{
public:
    mutable CCriticalSection cs;
    std::map<uint256, CTransaction> mapTx;
    std::map<COutPoint, CInPoint> mapNextTx;
    std::map<std::string, uint256> mapTokenToHash;
    std::map<uint256, std::string> mapHashToToken;

    bool accept(CValidationState &state, CTxDB& txdb, const CTransaction &tx,
                bool fCheckInputs, bool* pfMissingInputs);
    bool addUnchecked(const uint256& hash, const CTransaction &tx);
    void remove(const CTransaction& tx);
    void remove(const std::vector<CTransaction>& vtx);
    void remove(const std::vector<CTransaction>& vtx, ConnectedBlockTokenData& connectedBlockData);
    void removeUnchecked(const CTransaction& tx, const uint256& hash);
    void clear();
    void queryHashes(std::vector<uint256>& vtxid);

    size_t size()
    {
        LOCK(cs);
        return mapTx.size();
    }

    bool exists(uint256 hash)
    {
        return (mapTx.count(hash) != 0);
    }

    CTransaction& lookup(uint256 hash)
    {
        return mapTx[hash];
    }
};
#endif // BITCOIN_TXMEMPOOL_H

