#ifndef EXPLORER_H
#define EXPLORER_H
    // this insures that explorer.h is included only once
#include "uint256.h"

//extern Object blockToJSON(const CBlock& block, const CBlockIndex* blockindex, bool fPrintTransactionDetail)

#include <QDialog>
#include <QTableView>
#include <QTextBrowser>

#include <QDateTime>
#include <QLabel>
#include <QList>
#include <QVector>
#include <QString>

const int
    nARBITRARY_LARGE_NUMBER_OF_ROWS = 150,
    nONE_ROW = 1;

//QT_BEGIN_NAMESPACE
class QModelIndex;
//QT_END_NAMESPACE
class BlockExplorerPage;
class TransactionExplorerPage;

namespace Ui {
    class ExplorerPage;
}
namespace Ui {
    class BlockExplorerPage;
}
namespace Ui {
    class TransactionExplorerPage;
}

class QStandardItemModel;
class ClientModel;
class CTransaction;
//_____________________________________________________________________________
//_____________________________________________________________________________

class ExplorerPage 
    : public QDialog
{
    Q_OBJECT

    enum{
        HEIGHT              = 0,
        AGE                 = 1,    //(HEIGHT + 1),
        TRANSACTIONS        = 2,    //(AGE + 1),
        TOTAL_SENT          = 3,    //(TRANSACTIONS + 1),
        //RELAYED_BY = 4,
        SIZE_kB             = 4,    //(TOTAL_SENT +1), 
        TIME                = 5,    //(SIZE_kB + 1),
                /********************************
        BLOCK_TEST_AREA     = 6,    //(TIME + 1)
            BLOCK_VIEW_SIZE = 7     //(BLOCK_TEST_AREA + 1) 
                ********************************/
            BLOCK_VIEW_SIZE = 6     //(TIME + 1) 
        };
    enum{
        TX_ID               = 0,
        TX_AGE              = 1,
        TX_AMOUNT           = 2,
        TX_TIME             = 3,
                /********************************
        TX_nm               = 4,
            TX_VIEW_SIZE    = 5 
                ********************************/
            TX_VIEW_SIZE    = 4 
        };
    int
        nROWS_OF_DISPLAYED_BLOCKS,
        nROWS_OF_DISPLAYED_TRANSACTIONS;

public:
    explicit ExplorerPage(QWidget *parent = 0);
    //ExplorerPage(QWidget *parent = 0);
    //virtual ~ExplorerPage();
    ~ExplorerPage();

    // the table and transaction views, that like to be fed by "models"
    QTableView
        *pQTVblocks;
    QTableView
        *pQTVtransactions;

    QLineEdit 
        *pTxIDLineEdit,
        *pBlockHashLineEdit,
        *pBlockNumberLineEdit;
    QLabel
        *pQLpriceText, 
        *pQLprice, 
        *pQLaverage;
    double
        dLastPrice; 
    bool
        fBlockEditConnected,
        fBlockHashEditConnected,
        fBlkConnected,
        fTxHashEditConnected,
        fTxConnected;
    // for modal-less?
    void setClientModel(ClientModel *model);
    void setModel(ClientModel *model);

public slots:
    /** Set number of blocks shown in the UI */
    void setNumBlocks( int count );
    void setTransactions( uint256 txhash );

signals:
    //void transactionClicked(const QModelIndex &index);
    //void blockClicked(const QModelIndex &index);

    void doubleClicked( const QModelIndex );     // block #
    //void doubleClicked( const QModelIndex );    // tx ID

//void QAbstractItemView::doubleClicked ( const QModelIndex & index ) [signal]
//This signal is emitted when a mouse button is double-clicked. The item the mouse was double-clicked on is specified by index. The signal is only emitted when the index is valid.

private:
    Ui::ExplorerPage *ui;

    // for non modal (modaless?) window do this?
    ClientModel     
        *pclientModel;
    // for modal popup dialog box

    BlockExplorerPage 
        *pExplorerBlockDialog;
    TransactionExplorerPage 
        *pExplorerTransactionDialog;

    // pointers to models to hold the block data, transaction data, ...
    QStandardItemModel                              
        *pQSIMblocks;       
    QStandardItemModel                              
        *pQSIMtransactions;

    // the actual data that is placed into the model 
    QList< QVector< QString > > 
        qlistOfTxRows,
        qlistOfBlockRows;

    QVector< int >
        vBlockPeriods;

    int
        nLastBestHeight;

    std::string
        sCOIN_SYMBOL;

    bool
        fDontReenterMe,
        fDoneIt;

private slots:
    void on_closeButton_clicked();
    void showBkDetails( QModelIndex );  // clicked on a block #
    void showTxDetails( QModelIndex );  // clicked on a Tx ID

    void showTxInfoDetails( QModelIndex );  // clicked on a Tx ID
    void showBlockLineDetails();
    void showBlockHashLineDetails();
    void showTxIdLineDetails();
    void showBkInfoDetails( QModelIndex QMI );
};
//_____________________________________________________________________________
//_____________________________________________________________________________
class BlockExplorerPage : public QDialog
{
    Q_OBJECT

public:
    explicit BlockExplorerPage(QWidget *parent = 0);
    ~BlockExplorerPage();

    enum{
        BLOCK_INFO_ITEM   = 0,
        BLOCK_INFO_VALUE  = 1,          //(BLOCK_INFO_ITEM + 1),
            BLOCK_INFO_VIEW_SIZE = 2    //(BLOCK_INFO_VALUE + 1) 
        };

    void setClientModel(ClientModel *model);
    void setModel(ClientModel *model);

    QTableView
        *pQTVblockinfo;
    QItemSelectionModel
        *pQISM;

//    QTextBrowser
//        *pQTBblock;
    bool
        fBlkInfoConnected;

    void fillBlockInfoPage( int currentHeight
                            //, ExplorerPage * const 
                          );
    void showBkItem();
    //void followLink( const QUrl & link );
    QStandardItemModel                              
        *pQSIMblockinfo;       

public slots:
//    void showBkHashDetails( QModelIndex );

signals:

private:
    Ui::BlockExplorerPage *ui;

    //ExplorerPage 
    //    *pExplorerPage;

    ClientModel     
        *pclientModel;

    QList< QVector< QString > > 
        qlistOfBlockinfoRows;

private slots:
    void on_closeButton_clicked();
};
//_____________________________________________________________________________
//_____________________________________________________________________________
               
class TransactionExplorerPage : public QDialog
{
    Q_OBJECT
public:
    explicit TransactionExplorerPage(QWidget *parent = 0 );
    ~TransactionExplorerPage();

    enum{
        TRANSACTION_INFO_ITEM   = 0,
        TRANSACTION_INFO_VALUE  = 1,          //(TRANSACTION_INFO_ITEM + 1),
            TRANSACTION_INFO_VIEW_SIZE = 2    //(TRANSACTION_INFO_VALUE + 1) 
        };

    void setClientModel(ClientModel *model);
    void setModel(ClientModel *model);

    QTableView
        *pQTVtxinfo;

    QStandardItemModel
        *pQSIMtxinfo;

//    QTextBrowser
//        *pQTBtransaction;
    bool
        fTxInfoConnected;

    //void fillTxInfoPage( int currentHeight );
    //void showTxItem();
    //void followLink( const QUrl & link );

public slots:

signals:

private:
    Ui::TransactionExplorerPage *ui;

    //ExplorerPage 
    //    *pExplorerPage;

    ClientModel     
        *pclientModel;

    QList< QVector< QString > > 
        qlistOfTxinfoRows;

private slots:
    void on_closeButton_clicked();
};
//_____________________________________________________________________________
//_____________________________________________________________________________
class CLastTxHash
{
public:
    CLastTxHash();
    void storeLasthash( uint256 &hash );
    uint256 retrieveLastHash( void );
private:
    uint256 lastHash;
};
//_____________________________________________________________________________

extern CLastTxHash lastTxHash;

#endif // EXPLORER_H
