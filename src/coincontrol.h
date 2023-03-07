#ifndef COINCONTROL_H
#define COINCONTROL_H

/** Coin Control Features. */
class CCoinControl
{
public:
    //! Custom change destination, if not set an address is generated
    CTxDestination destChange;
    //! If set, all asset change will be sent to this address, if not destChange will be used
    CTxDestination assetDestChange;
    //! If false, allows unselected inputs, but requires all selected inputs be used
    bool fAllowOtherInputs;
    //! Includes watch only addresses which match the ISMINE_WATCH_SOLVABLE criteria
    bool fAllowWatchOnly;

    /** YAC_ASSET START */
    //! Name of the asset that is selected, used when sending assets with coincontrol
    std::string strAssetSelected;
    /** YAC_ASSET END */

    CCoinControl()
    {
        SetNull();
    }

    void SetNull()
    {
        destChange = CNoDestination();
        assetDestChange = CNoDestination();
        fAllowOtherInputs = false;
        fAllowWatchOnly = false;
        strAssetSelected = "";
        setSelected.clear();
        setAssetsSelected.clear();
    }

    bool HasSelected() const
    {
        return (setSelected.size() > 0);
    }

    bool HasAssetSelected() const
    {
        return (setAssetsSelected.size() > 0);
    }

    bool IsSelected(const uint256& hash, unsigned int n) const
    {
        COutPoint outpt(hash, n);
        return (setSelected.count(outpt) > 0);
    }

    bool IsAssetSelected(const COutPoint& output) const
    {
        return (setAssetsSelected.count(output) > 0);
    }

    void Select(COutPoint& output)
    {
        setSelected.insert(output);
    }

    void SelectAsset(const COutPoint& output)
    {
        setAssetsSelected.insert(output);
    }

    void UnSelect(const COutPoint& output)
    {
        setSelected.erase(output);
        if (!setSelected.size())
            strAssetSelected = "";
    }

    void UnSelectAsset(const COutPoint& output)
    {
        setAssetsSelected.erase(output);
        if (!setSelected.size())
            strAssetSelected = "";
    }

    void UnSelectAll()
    {
        setSelected.clear();
        strAssetSelected = "";
        setAssetsSelected.clear();
    }

    void ListSelected(std::vector<COutPoint>& vOutpoints) const
    {
        vOutpoints.assign(setSelected.begin(), setSelected.end());
    }

    void ListSelectedAssets(std::vector<COutPoint>& vOutpoints) const
    {
        vOutpoints.assign(setAssetsSelected.begin(), setAssetsSelected.end());
    }

private:
    std::set<COutPoint> setSelected;
    std::set<COutPoint> setAssetsSelected;

};

#endif // COINCONTROL_H
