#ifndef COINCONTROL_H
#define COINCONTROL_H

#include "script/standard.h"

/** Coin Control Features. */
class CCoinControl
{
public:
    //! Custom change destination, if not set an address is generated
    CTxDestination destChange;
    //! If set, all token change will be sent to this address, if not destChange will be used
    CTxDestination tokenDestChange;
    //! If false, allows unselected inputs, but requires all selected inputs be used
    bool fAllowOtherInputs;
    //! Includes watch only addresses which match the ISMINE_WATCH_SOLVABLE criteria
    bool fAllowWatchOnly;
    //! Override automatic min/max checks on fee, m_feerate must be set if true
    bool fOverrideFeeRate;
    //! Override the default payTxFee if set
    boost::optional<CFeeRate> m_feerate;

    /** YAC_TOKEN START */
    //! Name of the token that is selected, used when sending tokens with coincontrol
    std::string strTokenSelected;
    /** YAC_TOKEN END */

    CCoinControl()
    {
        SetNull();
    }

    void SetNull()
    {
        destChange = CNoDestination();
        tokenDestChange = CNoDestination();
        fAllowOtherInputs = false;
        fAllowWatchOnly = false;
        fOverrideFeeRate = false;
        m_feerate.reset();
        strTokenSelected = "";
        setSelected.clear();
        setTokensSelected.clear();
    }

    bool HasSelected() const
    {
        return (setSelected.size() > 0);
    }

    bool HasTokenSelected() const
    {
        return (setTokensSelected.size() > 0);
    }

    bool IsSelected(const COutPoint& output) const
    {
        return (setSelected.count(output) > 0);
    }

    bool IsSelected(const uint256& hash, unsigned int n) const
    {
        COutPoint outpt(hash, n);
        return (setSelected.count(outpt) > 0);
    }

    bool IsTokenSelected(const COutPoint& output) const
    {
        return (setTokensSelected.count(output) > 0);
    }

    void Select(const COutPoint& output)
    {
        setSelected.insert(output);
    }

    void SelectToken(const COutPoint& output)
    {
        setTokensSelected.insert(output);
    }

    void UnSelect(const COutPoint& output)
    {
        setSelected.erase(output);
        if (!setSelected.size())
            strTokenSelected = "";
    }

    void UnSelectToken(const COutPoint& output)
    {
        setTokensSelected.erase(output);
        if (!setSelected.size())
            strTokenSelected = "";
    }

    void UnSelectAll()
    {
        setSelected.clear();
        strTokenSelected = "";
        setTokensSelected.clear();
    }

    void ListSelected(std::vector<COutPoint>& vOutpoints) const
    {
        vOutpoints.assign(setSelected.begin(), setSelected.end());
    }

    void ListSelectedTokens(std::vector<COutPoint>& vOutpoints) const
    {
        vOutpoints.assign(setTokensSelected.begin(), setTokensSelected.end());
    }

private:
    std::set<COutPoint> setSelected;
    std::set<COutPoint> setTokensSelected;

};

#endif // COINCONTROL_H
