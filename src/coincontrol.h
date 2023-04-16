#ifndef COINCONTROL_H
#define COINCONTROL_H

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

    bool IsSelected(const uint256& hash, unsigned int n) const
    {
        COutPoint outpt(hash, n);
        return (setSelected.count(outpt) > 0);
    }

    bool IsTokenSelected(const COutPoint& output) const
    {
        return (setTokensSelected.count(output) > 0);
    }

    void Select(COutPoint& output)
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
