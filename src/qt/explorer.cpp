#ifndef EXPLORER_H
    #include "explorer.h"
#endif
#include "ui_explorer.h"
    #include "ui_explorerBlockPage.h"
    #include "ui_explorerTransactionPage.h"

#ifndef CLIENTMODEL_H
    #include "clientmodel.h"
#endif

#ifndef _BITCOINRPC_H_
    #include "bitcoinrpc.h"
#endif

#ifndef GUIUTIL_H
    #include "guiutil.h"
#endif

#ifndef BITCOIN_MAIN_H
    #include "main.h"
#endif
//#include "guiconstants.h"

//#include <QAbstractItemDelegate>

//#include <QTime>
//#include <QTimer>
//#include <QThread>
//#include <QTextEdit>
#include <QTextBrowser>
#include <QMessageBox>
#include <QKeyEvent>
//#include <QUrl>
//#include <QScrollBar>

    CLastTxHash lastTxHash;
    #include <QDateTime>

#include <QStandardItemModel>

#include <openssl/crypto.h>

// for tx details
#include <map>
#include <boost/foreach.hpp>

// TODO: make it possible to filter out categories (esp debug messages when implemented)
// TODO: receive errors and debug messages through ClientModel

const QSize ICON_SIZE(24, 24);

using namespace json_spirit;
extern Object blockToJSON(const CBlock& block, const CBlockIndex* blockindex, bool fPrintTransactionDetail);
//#include <QtScript/QScriptEngine>
//#include <QtScript/QScriptValue>
//#include <QtScript/QScriptValueIterator>

    //#include "explorer.moc"
std::string BuildBlockinfoDetailsFrom( 
                                      CBlock &block                         // in
                                      , CBlockIndex* pblockindex            // in
                                      , QStandardItemModel *pQSIMblockinfo  // out
                                      , QTableView *pQTVblockinfo           // out
                                     );
std::string BuildTxDetailsFrom( 
                                uint256 &hashOfSelectedTransaction          // in
                                , CTransaction &tx                          // in
                                , uint256 &hashBlock                        // in
                                , QStandardItemModel *pQSIMtxinfo           // out
                                , QTableView *pQTVtxinfo                    // out
                              );
void pop_a_message_box( std::string s );

// definition of the statics
/* static */ bool ExplorerPage::fDontReenterMe = false;      
/* static */ bool ExplorerPage::fResizeBlocksFields = false;
/* static */ bool ExplorerPage::fResizeTxsFields = false;

// this is the Using a Pointer Member Variable approach ctor
//_____________________________________________________________________________
//_____________________________________________________________________________
// explorer area constructor
// initializes the headers for the blocks and transactions table views
//_____________________________________________________________________________
ExplorerPage::ExplorerPage(QDialog * parent, bool fNoCloseButton ) :
//ExplorerPage::ExplorerPage(QDialog * const parent) :
    QDialog(parent)
    //QWidget(parent)
    , ui(new Ui::ExplorerPage)
    , pExplorerBlockDialog( 0 )
    , pExplorerTransactionDialog( 0 )
  //, model(0)
{
    ui->setupUi(this);

    pclientModel = NULL;

    fBlkConnected = false;
    fTxConnected = false;
    fBlockEditConnected = false;
    fBlockHashEditConnected = false;
    fTxHashEditConnected = false;
    fCloseButton = !fNoCloseButton;
    if( fNoCloseButton )
        ui->closeButton->hide();

    const int
        nGOOD_impossible_value = -1;

    nLastBestHeight = nGOOD_impossible_value;

    pQTVblocks = ui->tableViewForBlocks;
    pQTVblocks->setShowGrid( false );
    nROWS_OF_DISPLAYED_BLOCKS = 20;
    //nROWS_OF_DISPLAYED_BLOCKS = 10;

    pQTVtransactions = ui->tableViewForTransactions;
    pQTVtransactions->setShowGrid( false );
    nROWS_OF_DISPLAYED_TRANSACTIONS = 10;

    vBlockPeriods.resize( nROWS_OF_DISPLAYED_BLOCKS );  
    pQLaverage = ui->AveBkPeriodField;
    pQLpriceText = ui->labelPrice;
    pQLprice = ui->label_ThePrice;
    dLastPrice = 0.0;

    pBlockNumberLineEdit = ui->BlockNumberLineEdit;
    pBlockHashLineEdit = ui->BlockHashLineEdit;
    pTxIDLineEdit = ui->TxIDlineEdit;

    //QList< QVector< QString > > qlistOfBlockRows;

    ppcArrayOfBlockHeaders = new char*[ BLOCK_VIEW_SIZE ];

    ppcArrayOfBlockHeaders[ HEIGHT       ] = "Height";
    ppcArrayOfBlockHeaders[ TIME         ] = "Time (local)";
    ppcArrayOfBlockHeaders[ AGE          ] = "Age";
    ppcArrayOfBlockHeaders[ TRANSACTIONS ] = "Txs";
    ppcArrayOfBlockHeaders[ TOTAL_SENT   ] = "Total Sent";
                           //RELAYED_BY  //"Relayed By";
    ppcArrayOfBlockHeaders[ SIZE_kB      ] = "Size (kB)"; 

    pExplorerBlockDialog = new BlockExplorerPage( this );
    pExplorerTransactionDialog = new TransactionExplorerPage( this );

    // by analogy, 
    // clicking on a transaction in the block detail view should invoke 
    // the pExplorerTransactionDialog and
    // clicking on a block hash in the transaction detail view should invoke 
    // the pExplorerBlockDialog.
    // Also,
    // clicking on a Tx in the Tx detail view should re-invoke the 
    // pExplorerTransactionDialog and
    // clicking on a block hash in the Block detail view should re-invoke the
    // pExplorerBlockDialog.

    // When an item is clicked (double clicked) in the block info dialog, 
    // we signal a slot in pExplorerDialog (this), and it can
    // then launch pExplorerTransactionDialog or pExplorerBlockDialog as needed
    // and similarly for a selection in pExplorerTransactionDialog
    bool
        fOK = connect(
                pExplorerBlockDialog->pQTVblockinfo,
                SIGNAL(clicked( QModelIndex )), //SIGNAL(doubleClicked( QModelIndex )),
                this,
                SLOT(showBkInfoDetails( QModelIndex ))
                     );
    if ( fOK )
        pExplorerBlockDialog->fBlkInfoConnected = true;

    fOK = connect(
                pExplorerTransactionDialog->pQTVtxinfo, 
                SIGNAL(clicked( QModelIndex )),   //SIGNAL(doubleClicked( QModelIndex )), 
                this,   //pExplorerTransactionDialog, 
                SLOT(showTxInfoDetails( QModelIndex ))
                 );
    if ( fOK )
        pExplorerTransactionDialog->fTxInfoConnected = true;

    // Generate block view headers
    pQSIMblocks = new QStandardItemModel( nROWS_OF_DISPLAYED_BLOCKS, BLOCK_VIEW_SIZE, this );
    for (int column = 0; column < BLOCK_VIEW_SIZE; ++column)
    {
        pQSIMblocks->setHorizontalHeaderItem( 
                                            column, 
                                            new QStandardItem( 
                                                              QString( 
                                                              ppcArrayOfBlockHeaders[ column ] 
                                                                     ) 
                                                             ) 
                                            );
        pQTVblocks->resizeColumnToContents( column );
    }
    // this puts the model into the view
    pQTVblocks->setModel( pQSIMblocks );
    pQTVblocks->setEditTriggers( QAbstractItemView::NoEditTriggers );

    //_________________________________________________________________________
    //_________________________________________________________________________
    // build the transactions model 

    //_________________________________________________________________________
    // Generate transaction headers
    ppcArrayOfTransactionHeaders = new char*[ TX_VIEW_SIZE ];

    ppcArrayOfTransactionHeaders[ TX_ID     ] = "                       Tx ID                       ";
    ppcArrayOfTransactionHeaders[ TX_TIME   ] = "Time (local)";
    ppcArrayOfTransactionHeaders[ TX_AGE    ] = "Age";
    ppcArrayOfTransactionHeaders[ TX_AMOUNT ] = "Amount";
                /********************************
    ppcArrayOfTransactionHeaders[ TX_nm ] = "Test Area";
                ********************************/
    pQSIMtransactions = new QStandardItemModel( nROWS_OF_DISPLAYED_TRANSACTIONS, TX_VIEW_SIZE, this );
    for (int column = 0; column < TX_VIEW_SIZE; ++column)
    {
        QString
            QS = QString( ppcArrayOfTransactionHeaders[ column ] );

        QStandardItem
            *pQSI = new QStandardItem( QS );
        /*********************************
        if( TX_ID == column )
        {
            int
                nTxPixelSize = 300;
            const QSize 
                *pQSh = new QSize( nTxPixelSize, 13 );
            const QSize
                &CrQSize = *pQSh;
            
            pQSI->setSizeHint( CrQSize );   // well, that didn't do it :(
        }
        *********************************/
        pQSIMtransactions->setHorizontalHeaderItem( column, pQSI );
    }    
    //_________________________________________________________________________

    // this puts the model into the view
    pQTVtransactions->setModel( pQSIMtransactions );
    pQTVtransactions->setEditTriggers( QAbstractItemView::NoEditTriggers );
    sCOIN_SYMBOL = "YAC";                   // put your favorite coin name here!
}
//_____________________________________________________________________________
// just a POF to pop a message box, maiinly for testing
//_____________________________________________________________________________

void pop_a_message_box( std::string s )
{
    QMessageBox 
        msgBox;

    msgBox.setTextFormat( Qt::RichText );
    msgBox.setText( s.c_str() );
    msgBox.exec();
}
//_____________________________________________________________________________
// SLOT receiver object for clicking on a block in the block list view
//_____________________________________________________________________________
void ExplorerPage::showBkDetails( QModelIndex QMI )
{
    if ( !pQTVblocks->selectionModel() )
        return;

    int
        nColumn = QMI.column(),
        nRow = QMI.row();

    if ( 
        ( nRow < qlistOfBlockRows.size() ) &&       // only existing rows
        ( HEIGHT == nColumn )                       // only 'height' column
       )
    {   // clicked somewhere in the height column
        bool
            fOK;
        QString
            QSblockNumber = pQSIMblocks->item( nRow, HEIGHT )->text();
        int
            nHeight = QSblockNumber.toInt( &fOK );

        if ( !fBlockEditConnected )
        {
            pop_a_message_box( "Something's wrong in slotland!" );
        }
        if( fOK )
        {                   // copy nHeight to block # input line edit field
            pBlockNumberLineEdit->setText( QSblockNumber );
            pExplorerBlockDialog->fillBlockInfoPage( nHeight );   // shows OK
        }
    }
    pQTVblocks->selectionModel()->select( QMI, QItemSelectionModel::Deselect );
}
//_____________________________________________________________________________
// SLOT receiver for the Block # line edit field
//_____________________________________________________________________________
void ExplorerPage::showBlockLineDetails( )
{
    bool
        fOK;
    int
        nNewBlockNumber = pBlockNumberLineEdit->text().toInt( &fOK );

    if ( fOK )
    {
        if ( 
            ( 0 <= nNewBlockNumber ) &&
            ( nNewBlockNumber <= nBestHeight )
           )
        {
            if ( nNewBlockNumber != nLastBestHeight )
            {
                nLastBestHeight = nNewBlockNumber;
            }
            pExplorerBlockDialog->fillBlockInfoPage( nNewBlockNumber );  // shows OK
            pBlockNumberLineEdit->clearFocus();
            pBlockNumberLineEdit->deselect();
        }
        else    // not a legal entry
        {
            pBlockNumberLineEdit->setText( "" );
        }
    }
    else    // not a number
        pBlockNumberLineEdit->setText( "" );

}
//_____________________________________________________________________________
// SLOT receiver for the Tx ID  line edit field
//_____________________________________________________________________________
void ExplorerPage::showTxIdLineDetails()
{
    QString
        QShash = pTxIDLineEdit->text();

    std::string
        sTemp = QShash.toStdString();

    uint256
        hashOfSelectedTransaction( sTemp );

    CTransaction 
        tx;

    uint256 
        hashBlock = 0;

    if (GetTransaction(hashOfSelectedTransaction, tx, hashBlock))
    {
        sTemp = BuildTxDetailsFrom( 
                                    hashOfSelectedTransaction
                                    , tx 
                                    , hashBlock 
                                    , pExplorerTransactionDialog->pQSIMtxinfo
                                    , pExplorerTransactionDialog->pQTVtxinfo
                                  );
        // it seems one must move the focus in Qt or this selection lingers!?
        pTxIDLineEdit->clearFocus();
        pTxIDLineEdit->deselect();

        pExplorerTransactionDialog->show();
        //pExplorerTransactionDialog->raise( );
        pExplorerTransactionDialog->setVisible( true );
        pExplorerTransactionDialog->activateWindow( );
    }
    else    // hash is no good
        pTxIDLineEdit->setText( "" );
}
//_____________________________________________________________________________
// SLOT receiver object for clicking or double clicking on a Block hash in the 
// explorer page Block hash line input
//_____________________________________________________________________________

void ExplorerPage::showBlockHashLineDetails()
{
    QString
        QShash = pBlockHashLineEdit->text();

    std::string
        sTemp = QShash.toStdString();

    uint256
        hashOfSelectedItem( sTemp );

    CBlockIndex
        *pblockindex = mapBlockIndex[ hashOfSelectedItem ];

    CBlock 
        block;

    /********************************************
    uint256                                        // if I add this it crashes??????????
        hash = pblockindex->GetHash();

    if ( hash != hashOfSelectedItem )
    {
        pop_a_message_box( "curious?" );  
    }
    ********************************************/
    if ( pblockindex )
    {
        block.ReadFromDisk( pblockindex, true );

        CMerkleTx 
            txGen( block.vtx[ 0 ] );

        if( 0 == txGen.SetMerkleBranch( &block ) )  
            pop_a_message_box( "curious?" );  

        std::string
            sX = BuildBlockinfoDetailsFrom( 
                                        block, 
                                        pblockindex, 
                                        pExplorerBlockDialog->pQSIMblockinfo, 
                                        pExplorerBlockDialog->pQTVblockinfo
                                          );
        pBlockHashLineEdit->clearFocus();
        pBlockHashLineEdit->deselect();
        pExplorerBlockDialog->show();
        //this->raise( );                    // doesn't seem to do anything??
        pExplorerBlockDialog->setVisible( true );
        pExplorerBlockDialog->activateWindow( );

        //pBlockHashLineEdit->selectionModel()->select( QMI, QItemSelectionModel::Deselect );
    }
    else    // a bad block hash was entered?
    {
        pBlockHashLineEdit->setText( "" );
    }
}
//_____________________________________________________________________________
// SLOT receiver object for clicking or double clicking on a Tx in the table view
//_____________________________________________________________________________

void ExplorerPage::showTxDetails( QModelIndex QMI )
{
    //pclientModel
    if ( !pQTVtransactions->selectionModel() )
        return;
    int
        nColumn = QMI.column(),
        nRow = QMI.row();

    if ( 
        ( nRow < qlistOfTxRows.size() ) &&
        ( TX_ID == nColumn )
       )                                
    {   // clicked somewhere in the ID column, where there is data
        QString
            QShash = pQSIMtransactions->item( nRow, TX_ID )->text();

        std::string
            sTemp = QShash.toStdString();

        uint256
            hashOfSelectedTransaction( sTemp );

        CTransaction 
            tx;

        uint256 
            hashBlock = 0;

        if (GetTransaction(hashOfSelectedTransaction, tx, hashBlock))
        {
            // copy Tx IDt to Tx ID input line edit field
            pTxIDLineEdit->setText( QShash );

            sTemp = BuildTxDetailsFrom( 
                                        hashOfSelectedTransaction
                                        , tx
                                        , hashBlock 
                                        , pExplorerTransactionDialog->pQSIMtxinfo
                                        , pExplorerTransactionDialog->pQTVtxinfo
                                      );
            //pop_a_message_box( sTemp );
        }
        else
            sTemp += strprintf( "%s", " No information available about transaction" );

        pExplorerTransactionDialog->show();
        //pExplorerTransactionDialog->raise( );
        pExplorerTransactionDialog->setVisible( true );
        pExplorerTransactionDialog->activateWindow( );
    }
    pQTVtransactions->selectionModel()->select( QMI, QItemSelectionModel::Deselect );
}
//_____________________________________________________________________________
// slot receiver for a selection an item in the transaction info detail dialog
//_____________________________________________________________________________

void ExplorerPage::showTxInfoDetails( QModelIndex QMI )
{
    int
        row = QMI.row(),
        column = QMI.column();

    QString
        QSitem = pExplorerTransactionDialog->pQSIMtxinfo->item( 
                                                            row, 
                                                            pExplorerTransactionDialog->TRANSACTION_INFO_ITEM 
                                                              )->text(),
        QSvalue = pExplorerTransactionDialog->pQSIMtxinfo->item( 
                                                            row, 
                                                            pExplorerTransactionDialog->TRANSACTION_INFO_VALUE 
                                                               )->text();
    // what was clicked?
    if  (
         ( "Tx ID" == QSitem.toStdString() ) ||
         ( "Coinbase hash" == QSitem.toStdString() )
        )
    {
        //pop_a_message_box( "A tx hash " + QSitem.toStdString() );
    }
    if  (
         ( "Tx's block hash" == QSitem.toStdString() )
        )
    {
        //pop_a_message_box( "A block hash " + QSitem.toStdString() );
        uint256
            hashOfSelectedItem( QSvalue.toStdString() );

        CBlockIndex
            *pblockindex = mapBlockIndex[ hashOfSelectedItem ];

        CBlock 
             block;

        if ( pblockindex )
        {
            block.ReadFromDisk( pblockindex, true );

            CMerkleTx 
                txGen( block.vtx[ 0 ] );    // fixed it!!! Code that is inside read JSON!!!!!

            if( 0 == txGen.SetMerkleBranch( &block ) )  
            {
                pop_a_message_box( "curious?" );  
            }

            std::string
                sX = BuildBlockinfoDetailsFrom( 
                                        block, 
                                        pblockindex, 
                                        pExplorerBlockDialog->pQSIMblockinfo, 
                                        pExplorerBlockDialog->pQTVblockinfo
                                              );
            pExplorerBlockDialog->show();
            //this->raise( );                    // doesn't seem to do anything??
            pExplorerBlockDialog->setVisible( true );
            pExplorerBlockDialog->activateWindow( );
        }
        //else
        //      // it isn't a good block hash?  For whatever reason??
    }
    pExplorerTransactionDialog->pQTVtxinfo->selectionModel()->select( QMI, QItemSelectionModel::Deselect );
}
//_____________________________________________________________________________
// slot receiver for a selection in the block info detail dialog
//_____________________________________________________________________________

void ExplorerPage::showBkInfoDetails( QModelIndex QMI )
{
    int
        row = QMI.row(),
        column = QMI.column();

    QString
        QSitem = pExplorerBlockDialog->pQSIMblockinfo->item( 
                                                            row, 
                                                            pExplorerBlockDialog->BLOCK_INFO_ITEM 
                                                           )->text(),
        QSvalue = pExplorerBlockDialog->pQSIMblockinfo->item( 
                                                            row, 
                                                            pExplorerBlockDialog->BLOCK_INFO_VALUE 
                                                            )->text();
        //pExplorerBlockDialog->pQISM->reset();
        //pExplorerBlockDialog->pQISM->clear(); // this crashes!!!

        //pExplorerBlockDialog->pQISM->clearSelection();
        //pExplorerBlockDialog->pQISM->select( QMI, QItemSelectionModel::Deselect );
        //pExplorerBlockDialog->pQISM->select( QMI, QItemSelectionModel::Clear );
        //pExplorerBlockDialog->pQISM->select( QMI, QItemSelectionModel::Toggle );

        //nothing seems to work!?

    QString
        QShash = QSvalue.toStdString().c_str();

    std::string
        sTemp = QShash.toStdString();

    uint256
        hashOfSelectedValue( sTemp );

    CTransaction 
        tx;

    uint256 
        hashBlock = 0;

    if  (
         ( "previous block" == QSitem.toStdString() ) ||
         ( "hashPrevBlock" == QSitem.toStdString() ) ||
         ( "next block" == QSitem.toStdString() )
        )
    {
        QShash = QSvalue.toStdString().c_str();

        CBlockIndex
            *pblockindex = mapBlockIndex[ hashOfSelectedValue ];

        CBlock 
            block;

        block.ReadFromDisk(pblockindex, true);

        CMerkleTx 
            txGen( block.vtx[ 0 ] );    // fixed it!!! Code that is inside read JSON!!!!!

        if( 0 == txGen.SetMerkleBranch( &block ) )  
        {
            pop_a_message_box( "curious?" );  
        }

        std::string
            sX = BuildBlockinfoDetailsFrom( 
                                        block, 
                                        pblockindex, 
                                        pExplorerBlockDialog->pQSIMblockinfo, 
                                        pExplorerBlockDialog->pQTVblockinfo
                                          );
        pExplorerBlockDialog->show();
        //this->raise( );
        pExplorerBlockDialog->setVisible( true );
        pExplorerBlockDialog->activateWindow( );
    }
    // we need the tx count and vMerkle sizes for this block,
    const int
        nBLOCK_HASH_ROW = 0;

    QString
        QSblockhash = pExplorerBlockDialog->pQSIMblockinfo->item( 
                                                            nBLOCK_HASH_ROW, 
                                                            pExplorerBlockDialog->BLOCK_INFO_VALUE 
                                                                )->text();
    uint256
        hashOfBlock( QSblockhash.toStdString() );

    CBlockIndex
        *pthisblockindex = mapBlockIndex[ hashOfBlock ];

    CBlock 
        thisblock;

    thisblock.ReadFromDisk( pthisblockindex, true );

    int 
        nThisVTxSize = (int)thisblock.vtx.size(),
        nThisVMerkleSize = (int)thisblock.vMerkleTree.size();

    QString
        QStxhash = "";

    if ( 1 == nThisVTxSize )
    {
        if (
             ( "merkle root hash" == QSitem.toStdString() ) ||
             ( "hashMerkleRoot" == QSitem.toStdString() )
           )
        {
            QStxhash = QSvalue.toStdString().c_str();
        }
    }
    if ( "vMerkleTree:" == QSitem.toStdString() )
    {
        QStxhash = QSvalue.toStdString().c_str();
    }
    for ( int i = 1; i < nThisVTxSize; ++i )    // I think this is the right way to do this?
    {
        if  (
             ( strprintf( "vMerkleTree[ %d ]", i ).c_str() == QSitem.toStdString() )
            )
        {
            QStxhash = QSvalue.toStdString().c_str();
        }
    }
    if( "" != QStxhash.toStdString() )
    {
        std::string
            sTemp = QStxhash.toStdString();

        uint256
            hashOfSelectedItem( sTemp );

        CTransaction 
            tx;

        uint256 
            hashBlock = 0;

        if ( GetTransaction( hashOfSelectedItem, tx, hashBlock ) )
        {
            std::string
                sTemp = BuildTxDetailsFrom( 
                                    hashOfSelectedItem
                                    , tx 
                                    , hashBlock 
                                    , pExplorerTransactionDialog->pQSIMtxinfo
                                    , pExplorerTransactionDialog->pQTVtxinfo
                                          );
            // it seems one must move the focus in Qt or this selection lingers!?
            pExplorerTransactionDialog->show();
            //pExplorerTransactionDialog->raise( );
            pExplorerTransactionDialog->setVisible( true );
            pExplorerTransactionDialog->activateWindow( );
        }
    }
    pExplorerBlockDialog->pQTVblockinfo->selectionModel()->select( QMI, QItemSelectionModel::Deselect );
}
//_____________________________________________________________________________
// a POF to display YAC price & direction
//_____________________________________________________________________________
std::string doPrettyPrice( double & dlastPrice, double & dPrice )
{
    enum{
        PRICE_INCREASING = 1,
        PRICE_DECREASING = -1,
        PRICE_NOCHANGE = 0
        };

    std::string
        sColorText = "<font color = '",
        sTemp = strprintf( "%0.8lf", dPrice );
    
    int 
        nPriceSignal;

    if ( dPrice > dlastPrice )
    {
        nPriceSignal = (int)PRICE_INCREASING;
    }
    else
        if ( dPrice < dlastPrice )
        {
            nPriceSignal = (int)PRICE_DECREASING;
        }
        else // they are equal
        {
            nPriceSignal = (int)PRICE_NOCHANGE;
        }
    dlastPrice = dPrice;

    switch( nPriceSignal )
    {
        case (int)PRICE_INCREASING:
            sColorText += "green' >";
            break;
        case (int)PRICE_DECREASING:
            sColorText += "red' >";
            break;
        case (int)PRICE_NOCHANGE:
            sColorText += "black' >";
            break;
    }
    sTemp += "</font >";
    sColorText += sTemp;
    
    //pop_a_message_box( sColorText );    // test
    //    pP->setText( sColorText.c_str() );   // so we can put this label basically on any page
    return sColorText;
    // try to place this text on the overviewpage, somehow!??
    // signal( )
}

//_____________________________________________________________________________
// a POF to assist ExplorerPage::showTxInfoDetails()
//_____________________________________________________________________________

std::string BuildTxDetailsFrom( 
                                uint256 &hashOfSelectedTransaction
                                , CTransaction &tx
                                , uint256 &hashBlock
                                , QStandardItemModel *pQSIMtxinfo
                                , QTableView *pQTVtxinfo
                              )
{
    int
        nRowCount = 0,
        TX_INFO_ITEM = TransactionExplorerPage::TRANSACTION_INFO_ITEM,
        TX_INFO_VALUE = TransactionExplorerPage::TRANSACTION_INFO_VALUE;

    int
        nNumberOfRows = pQSIMtxinfo->rowCount();

    if ( nNumberOfRows > 0 )
    {
        pQSIMtxinfo->setRowCount( nARBITRARY_LARGE_NUMBER_OF_ROWS );
    }

    std::string
        sStandardItemModelElement,
        sTemp = "function BuildTxDetailsFrom()\n";

    sTemp = strprintf( 
                        "function BuildTxinfoDetailsFrom()\n"
                        "%s",
                        //"<br />"
                        "<h3 >"
                        "<b > (fillBlockInfoPage() call)</b >"
                        "</h3 >"
                        //"<br />"
                        ""
                     );
    --nRowCount;
    //_________________________________________________________________________
    sStandardItemModelElement = "Tx ID";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMtxinfo->setData( 
                        pQSIMtxinfo->index( nRowCount, TX_INFO_ITEM, QModelIndex() ),
                        sStandardItemModelElement.c_str()
                        );
    sStandardItemModelElement = strprintf( 
                        " %s"
                        , hashOfSelectedTransaction.GetHex().c_str() 
                                         );
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMtxinfo->setData( 
                        pQSIMtxinfo->index( nRowCount, TX_INFO_VALUE, QModelIndex() ),
                        sStandardItemModelElement.c_str()
                        );
    ++nRowCount;
    //_________________________________________________________________________
    if ( 0 == hashBlock )
    {
        sStandardItemModelElement = "confirmations";
        sTemp += "<b >" + sStandardItemModelElement + "</b >";
        pQSIMtxinfo->setData( 
                            pQSIMtxinfo->index( nRowCount, TX_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                            );
        sStandardItemModelElement = "0";
        sTemp += sStandardItemModelElement + "<br />\n";
        pQSIMtxinfo->setData( 
                            pQSIMtxinfo->index( nRowCount, TX_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                            );
        ++nRowCount;
        //_____________________________________________________________________
    }
    else
    {
        sStandardItemModelElement = "Tx's block hash";
        sTemp += "<b >" + sStandardItemModelElement + "</b >";
        pQSIMtxinfo->setData( 
                            pQSIMtxinfo->index( nRowCount, TX_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                            );
        sStandardItemModelElement = hashBlock.GetHex();
        sTemp += sStandardItemModelElement + "<br />\n";
        pQSIMtxinfo->setData( 
                            pQSIMtxinfo->index( nRowCount, TX_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                            );
        ++nRowCount;
        //_____________________________________________________________________

        std::map<uint256, CBlockIndex*>::iterator 
            mi = mapBlockIndex.find(hashBlock);

        if (mi != mapBlockIndex.end() && (*mi).second)
        {
            CBlockIndex
                *pindex = (*mi).second;
    
            sStandardItemModelElement = "confirmations";
            sTemp += "<b >" + sStandardItemModelElement + "</b >";
            pQSIMtxinfo->setData( 
                                pQSIMtxinfo->index( nRowCount, TX_INFO_ITEM, QModelIndex() ),
                                sStandardItemModelElement.c_str()
                                );

            if ( pindex->IsInMainChain() )
            {
                sStandardItemModelElement = strprintf( 
                                                    "%d"
                                                    , 1 + nBestHeight - pindex->nHeight 
                                                     );
                sTemp += sStandardItemModelElement + "<br />\n";
                pQSIMtxinfo->setData( 
                                    pQSIMtxinfo->index( nRowCount, TX_INFO_VALUE, QModelIndex() ),
                                    sStandardItemModelElement.c_str()
                                    );
                ++nRowCount;
                //_____________________________________________________________

                sStandardItemModelElement = "tx time";
                sTemp += "<b >" + sStandardItemModelElement + "</b >";
                pQSIMtxinfo->setData( 
                                    pQSIMtxinfo->index( nRowCount, TX_INFO_ITEM, QModelIndex() ),
                                    sStandardItemModelElement.c_str()
                                    );
                sStandardItemModelElement = strprintf( 
                                                  //" %lld"
                                                    " %" PRI64d ""
                                                    , (boost::int64_t)tx.nTime
                                                     );
                sTemp += sStandardItemModelElement + "<br />\n";
                pQSIMtxinfo->setData( 
                                    pQSIMtxinfo->index( nRowCount, TX_INFO_VALUE, QModelIndex() ),
                                    sStandardItemModelElement.c_str()
                                    );
                ++nRowCount;
                //_____________________________________________________________

                sStandardItemModelElement = "block time";
                sTemp += "<b >" + sStandardItemModelElement + "</b >";
                pQSIMtxinfo->setData( 
                                    pQSIMtxinfo->index( nRowCount, TX_INFO_ITEM, QModelIndex() ),
                                    sStandardItemModelElement.c_str()
                                    );
                sStandardItemModelElement = strprintf( 
                                                  //" %lld"
                                                    " %" PRI64d ""
                                                    , (boost::int64_t)pindex->nTime
                                                     );
                sTemp += sStandardItemModelElement + "<br />\n";
                pQSIMtxinfo->setData( 
                                    pQSIMtxinfo->index( nRowCount, TX_INFO_VALUE, QModelIndex() ),
                                    sStandardItemModelElement.c_str()
                                    );
                ++nRowCount;
                //_____________________________________________________________
            }
            else
            {
                sStandardItemModelElement = " 0";
                sTemp += sStandardItemModelElement + "<br />\n";
                pQSIMtxinfo->setData( 
                                    pQSIMtxinfo->index( nRowCount, TX_INFO_VALUE, QModelIndex() ),
                                    sStandardItemModelElement.c_str()
                                    );
                ++nRowCount;
                //_____________________________________________________________
            }
        }
    }
    std::string
        sTime = QDateTime::fromTime_t(  tx.nTime ).
                          toString("hh:mm:ss MM/dd/yyyy").
                          toStdString();
    
    sStandardItemModelElement = tx.IsCoinBase()? 
                                "Coinbase" : 
                                (tx.IsCoinStake()? "Coinstake" : "CTransaction");
    sStandardItemModelElement += " hash";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMtxinfo->setData( 
                        pQSIMtxinfo->index( nRowCount, TX_INFO_ITEM, QModelIndex() ),
                        sStandardItemModelElement.c_str()
                        );
    sStandardItemModelElement = tx.GetHash().ToString();
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMtxinfo->setData( 
                        pQSIMtxinfo->index( nRowCount, TX_INFO_VALUE, QModelIndex() ),
                        sStandardItemModelElement.c_str()
                        );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "nTime";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMtxinfo->setData( 
                        pQSIMtxinfo->index( nRowCount, TX_INFO_ITEM, QModelIndex() ),
                        sStandardItemModelElement.c_str()
                        );
    sStandardItemModelElement = strprintf( 
                                        " %d (local %s)"
                                        , tx.nTime, sTime.c_str()
                                         );
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMtxinfo->setData( 
                        pQSIMtxinfo->index( nRowCount, TX_INFO_VALUE, QModelIndex() ),
                        sStandardItemModelElement.c_str()
                        );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "version";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMtxinfo->setData( 
                        pQSIMtxinfo->index( nRowCount, TX_INFO_ITEM, QModelIndex() ),
                        sStandardItemModelElement.c_str()
                        );
    sStandardItemModelElement = strprintf( 
                                        " %d"
                                        , tx.nVersion
                                         );
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMtxinfo->setData( 
                        pQSIMtxinfo->index( nRowCount, TX_INFO_VALUE, QModelIndex() ),
                        sStandardItemModelElement.c_str()
                        );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "vin.size";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMtxinfo->setData( 
                        pQSIMtxinfo->index( nRowCount, TX_INFO_ITEM, QModelIndex() ),
                        sStandardItemModelElement.c_str()
                        );
    int
        nVIsize = int( tx.vin.size() );

    sStandardItemModelElement = strprintf( 
                                        " %"PRIszu""
                                        , tx.vin.size()
                                         );
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMtxinfo->setData( 
                        pQSIMtxinfo->index( nRowCount, TX_INFO_VALUE, QModelIndex() ),
                        sStandardItemModelElement.c_str()
                        );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "vout.size";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMtxinfo->setData( 
                        pQSIMtxinfo->index( nRowCount, TX_INFO_ITEM, QModelIndex() ),
                        sStandardItemModelElement.c_str()
                        );
    int
        nVOsize = int( tx.vout.size() );
    sStandardItemModelElement = strprintf( 
                                        " %"PRIszu""
                                        , tx.vout.size()
                                         );
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMtxinfo->setData( 
                        pQSIMtxinfo->index( nRowCount, TX_INFO_VALUE, QModelIndex() ),
                        sStandardItemModelElement.c_str()
                        );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "nLockTime";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMtxinfo->setData( 
                        pQSIMtxinfo->index( nRowCount, TX_INFO_ITEM, QModelIndex() ),
                        sStandardItemModelElement.c_str()
                        );
    sStandardItemModelElement = strprintf( 
                                        " %d"
                                        , tx.nLockTime
                                         );
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMtxinfo->setData( 
                        pQSIMtxinfo->index( nRowCount, TX_INFO_VALUE, QModelIndex() ),
                        sStandardItemModelElement.c_str()
                        );
    ++nRowCount;
    //_________________________________________________________________________

    for (int i = 0; i < nVIsize; ++i)
    {
        sStandardItemModelElement = strprintf( "tx.vin[ %d ]", i );
        sTemp += "<b >" + sStandardItemModelElement + "</b >";
        pQSIMtxinfo->setData( 
                            pQSIMtxinfo->index( nRowCount, TX_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                            );
        sStandardItemModelElement = tx.vin[ i ].ToString();
        sTemp += sStandardItemModelElement + "<br />\n";
        pQSIMtxinfo->setData( 
                            pQSIMtxinfo->index( nRowCount, TX_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                            );
        ++nRowCount;
        //_____________________________________________________________________
    }
    for (int i = 0; i < nVOsize; ++i)
    {
        sStandardItemModelElement = strprintf( "tx.vout[ %d ]", i );
        sTemp += "<b >" + sStandardItemModelElement + "</b >";
        pQSIMtxinfo->setData( 
                            pQSIMtxinfo->index( nRowCount, TX_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                            );
        sStandardItemModelElement = tx.vout[ i ].ToString();
        sTemp += sStandardItemModelElement + "<br />\n";
        pQSIMtxinfo->setData( 
                            pQSIMtxinfo->index( nRowCount, TX_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                            );
        ++nRowCount;
        //_____________________________________________________________________
    }
    pQSIMtxinfo->setRowCount( nRowCount );

    pQTVtxinfo->setWordWrap( true ); // there seems to be a limit to cell width?? 
    pQTVtxinfo->setEditTriggers( QAbstractItemView::NoEditTriggers );
    pQTVtxinfo->setModel( pQSIMtxinfo );

    pQTVtxinfo->resizeColumnsToContents();
    pQTVtxinfo->resizeRowsToContents();
    //pQTVtxinfo->resizeColumnsToContents();
    //pQTVtxinfo->resizeRowsToContents();

    return sTemp;
}
//_____________________________________________________________________________
//
//_____________________________________________________________________________

void ExplorerPage::setClientModel(ClientModel *model)
{
    this->pclientModel = model;
    if(model)
    {

    }
}
//_____________________________________________________________________________
//
//_____________________________________________________________________________

void ExplorerPage::setModel(ClientModel *model)
{
    if(model)
    {
        ExplorerPage::setClientModel(model);
    }
}
//_____________________________________________________________________________
//
//_____________________________________________________________________________

// this is the Using a Pointer Member Variable approach
ExplorerPage::~ExplorerPage()
{
    // delete[] ppcArrayOfBlockHeaders;
    //delete pExplorerBlockDialog;
    //delete pExplorerTransactionDialog;
    //delete pQSIMblocks;

    // delete[] ppcArrayOfTransactionHeaders;
    //delete pQSIMtransactions;

    delete ui;          
}
//_____________________________________________________________________________
//
//_____________________________________________________________________________

void ExplorerPage::setTransactions( uint256 txhash )
{
    {
        QModelIndex                                 // an index into the transaction Model
            TransactionTableIndex;

        for(int column = 0; column < TX_VIEW_SIZE; ++column)
        {
        }
    }
}
//_____________________________________________________________________________
//
//_____________________________________________________________________________

void ExplorerPage::setNumBlocks( int currentHeight )  
{
    if( true == fDontReenterMe )
    {
        return;         // in case we were interrupted by ourself!
    }
    fDontReenterMe = true;

    //if(pclientModel)
    {
        QModelIndex     // an index into the block Model of the explorer page
            BlockTableIndex;
        static const int
            nNinetySeconds = 90,    // arbitrary moment to get YAC price
            nSECONDsPerMINUTE = 60, nMINUTEsPerHOUR = 60,
            nSECONDsPerHOUR = nSECONDsPerMINUTE * nMINUTEsPerHOUR;
            
        // really should get the block determined from height parameter currentHeight
        // but nBestHeight & hashBestChain refer to the best block, I think!?

        int
            nHeight = currentHeight;

        CBlockIndex
            * pblockindex = mapBlockIndex[ hashBestChain ]; // hash of best block

        while (pblockindex->nHeight > nHeight)              // in case we don't have the latest block
            pblockindex = pblockindex->pprev;               // I think??

        // now pblockindex points to nHeight, or at least pblockindex->nHeight <= nHeight
        uint256 
            theDefiningBlockHash = pblockindex->GetBlockHeader().GetHash();  
        // this hash should define the block
        // so the time should be this blocks time
        // the height this blocks, etc.

        pblockindex = mapBlockIndex[theDefiningBlockHash];
        nHeight = pblockindex->nHeight;

        bool
            fMostlyUpToDate = false;

        QDateTime
            Qnow = QDateTime::currentDateTime(),
            QdateOfBestBlock = QDateTime::fromTime_t( pblockindex->GetBlockTime() );
        int 
            nDeltaSecondsAgeOfBlock = QdateOfBestBlock.secsTo( Qnow );  // can be + or - some seconds from now

        if ( nDeltaSecondsAgeOfBlock < (int)nTwelveHoursInSeconds )   // OK to update explorer window
        {   
            // now at 1 minute/ block, 12 hours is ~720 blocks arbitrary point to start the display of data
            QVector< QString > 
                vStringBlockDataRow( BLOCK_VIEW_SIZE ); // our model behind the model

            CBlock 
                block;
        
            if( block.ReadFromDisk(pblockindex, true) ) // true means read Tx's, false means don't
            {
                // now we have the best "block" and its "pblockindex"
    
                // let's create a row of new block data to display
                //_____________________________________________________________
                //_____________________________________________________________
                std::string
                    strTemporary = strprintf( "%d", pblockindex->nHeight ); 
                vStringBlockDataRow[ HEIGHT ] = strTemporary.c_str();
    
                //_____________________________________________________________
                strTemporary = QdateOfBestBlock.toString("hh:mm:ss MM/dd/yyyy").toStdString();
                vStringBlockDataRow[ TIME ] = strTemporary.c_str();
    
                //_____________________________________________________________
                strTemporary = strprintf( "%d", block.vtx.size() );
                vStringBlockDataRow[ TRANSACTIONS ] = strTemporary.c_str();
    
                //_____________________________________________________________
                strTemporary = strprintf( "%.3f %s", pblockindex->nMint / 1000000.0, sCOIN_SYMBOL.c_str() );
                vStringBlockDataRow[ TOTAL_SENT ] = strTemporary.c_str();
    
                //_____________________________________________________________
                int
                    nS = (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION);
    
                if( nS > (1000) )
                    strTemporary = strprintf( "%.3f kB", nS / 1000.0 );
                else
                    strTemporary = strprintf( "%d bytes", nS );
                vStringBlockDataRow[ SIZE_kB ] = strTemporary.c_str();
    
                //_____________________________________________________________
                int
                    nDeltaSecondsAgeOfBlock =
                        (int)( (Qnow.toMSecsSinceEpoch() - QdateOfBestBlock.toMSecsSinceEpoch() ) / 1000 );
                                            // Qt doesn't like functional casts!!
                if( nDeltaSecondsAgeOfBlock > 0 )
                        strTemporary = QDateTime::fromTime_t( nDeltaSecondsAgeOfBlock ).
                                       toUTC().toString("hh:mm:ss").toStdString();
                else    // 0 or negative seconds
                    strTemporary = strprintf( "%d sec", nDeltaSecondsAgeOfBlock );
                vStringBlockDataRow[ AGE ] = strTemporary.c_str();
    
                //_________________________________________________________________
                // so we have a new vector of strings, vStringBlockDataRow, perfect
                // for out qlistOfBlockRows
                //_________________________________________________________________
    
                // massaging our Qlist
                bool
                    fMatched = false,   // represents the answer to the question
                                        // do we already have this block in our list, 
                                        // which is in our model, which is in our view (whew!).
                                        // We begin with a presumed false, since or model is empty.
                    fAddedRow = false;
                if( qlistOfBlockRows.isEmpty() )
                {
                    qlistOfBlockRows.prepend( vStringBlockDataRow );    // so we just add the row
                    fAddedRow = true;
                }
                else                                                // we have 1 or more rows already
                {                                                   // so let's delete if neccessary
                    int
                        nTestHeight,
                        nNumberOfRows = qlistOfBlockRows.size();            // how tall is it now?
    
                    bool fBool;
                    for ( int row = 0; row < nNumberOfRows; ++row )         // what do we have so far?
                    {
                        nTestHeight = pQSIMblocks->item( row, HEIGHT )->text().toInt( &fBool );
                        if( !fBool ) // something is amiss??
                            continue;// swallow hard and check the next row ! :)
                        if( nHeight == nTestHeight )    // we matched height, let's replace with the 
                        {                               // latest Age
                            fMatched = true;
                            break;
                        }
                    }
                    if ( !fMatched )                    // add the new block
                    {
                        if( nNumberOfRows >= nROWS_OF_DISPLAYED_BLOCKS ) // model is full, so delete first row in our Qlist
                            qlistOfBlockRows.removeLast();
    
                        qlistOfBlockRows.prepend( vStringBlockDataRow );
                        fAddedRow = true;
                    }
                    // else we matched so don't add the same block, i.e. do nothing to the array
                }
                // we have added our new block row of data
                //_________________________________________________________________
                if ( (!fMatched) || fAddedRow ) // we added a new row, so update the 'view'
                {                               // by putting the model into the view
                    // now, qlistOfBlockRows.size() is complete for display, so let's
                    // put qlistOfBlockRows into model, then the model into the view
                
                    int
                        nSize = qlistOfBlockRows.size();    // known to be <= nROWS_OF_DISPLAYED_BLOCKS
    
                    for ( int row = 0; row < nSize; ++row )
                    {
                        for ( int column = 0; column < BLOCK_VIEW_SIZE; ++column )
                        {   
                            BlockTableIndex = pQSIMblocks->index( 
                                                                row,
                                                                column,
                                                                QModelIndex() 
                                                                );
                            if (AGE == column ) // recalculate the age of the older blocks
                            {
                                bool fOK;
                                int
                                    nBn = qlistOfBlockRows[ row ][ HEIGHT ].toInt( &fOK );
                                if( fOK )
                                {
                                    while (pblockindex->nHeight > nBn)
                                        pblockindex = pblockindex->pprev;
                                    // now pblockindex is at the older block, or should be!
                                    // i.e. pblockindex->nHeight should be == nBn 
                                    uint256 
                                        hash = pblockindex->GetBlockHeader().GetHash();
    
                                    pblockindex = mapBlockIndex[ hash ];
                                    block.ReadFromDisk(pblockindex, false); // true means read Tx's
    
                                    int64_t
                                        nTimeOfBlock = pblockindex->GetBlockTime(),
                                        nQTimeNow = Qnow.toMSecsSinceEpoch() / 1000;
    
                                    int
                                        nBlockAge = (int)( nQTimeNow - nTimeOfBlock );
                                    
                                    // let's save these times for averageing purposes
                                    vBlockPeriods[ row ] = nBlockAge;
    
                                    if( nBlockAge > 0 )
                                    {
                                        const int
                                            nONE_HOUR_in_seconds = 60 * 60;
        
                                        if( nBlockAge >= nONE_HOUR_in_seconds )
                                        {
                                            if( nBlockAge >= (int)nSecondsPerDay )
                                            {
                                                strTemporary = "days...";
                                            }
                                            else
                                            {
                                                strTemporary = QDateTime::fromTime_t( nBlockAge ).
                                                               toUTC().toString("hh:mm:ss").toStdString();
                                            }
                                        }
                                        else
                                        {
                                            strTemporary = QDateTime::fromTime_t( nBlockAge ).
                                                           toUTC().toString("mm:ss").toStdString();
    
                                            if ( nBlockAge < nNinetySeconds )
                                                fMostlyUpToDate = true;
                                        }
                                    }
                                    else
                                    {
                                        strTemporary = strprintf( "%d sec", nBlockAge );
                                        if ( nBlockAge > -nNinetySeconds )
                                            fMostlyUpToDate = true;
                                    }
                                    //vStringBlockDataRow[ AGE ] = strTemporary.c_str();
    
                                    pQSIMblocks->setData( 
                                                BlockTableIndex,
                                                strTemporary.c_str()
                                                        );
                            
                                }
                                else        // couldn't read the block number??
                                    pQSIMblocks->setData( 
                                                BlockTableIndex,
                                                qlistOfBlockRows[ row ][ column ].toStdString().c_str()
                                                        );
                            }
                            else    // for all the other non Age columns
                                pQSIMblocks->setData( 
                                                BlockTableIndex,
                                                qlistOfBlockRows[ row ][ column ].toStdString().c_str()
                                                    );
                        }
                    }
                    pQTVblocks->setModel( pQSIMblocks );   // this puts the model into the view
                    pQTVblocks->setEditTriggers( QAbstractItemView::NoEditTriggers );
    
                    if( !fResizeBlocksFields )
                    {
                        fResizeBlocksFields = true;
                        if ( !pExplorerBlockDialog->fBlkInfoConnected )
                        {
                            pop_a_message_box( "connection failed for Block View signal" );
                        }
                        if ( !pExplorerTransactionDialog->fTxInfoConnected )
                        {
                            pop_a_message_box( "connection failed for Transaction View signal" );
                        }
                        for(int column = 0; column < BLOCK_VIEW_SIZE; ++column)
                            pQTVblocks->resizeColumnToContents( column );
                    }
                    else
                    {
                        pQTVblocks->resizeColumnToContents( AGE );
                    }
                    // lets's calculate our running average block period here since the times
                    // are all "fresh"
                    int 
                        nCounter = 0,
                        nTotalAges = 0;
                    
                    for ( int row = nSize - 1; row > 0; --row )
                    {
                        vBlockPeriods[ row ] = vBlockPeriods[ row ] - vBlockPeriods[ row - 1 ];
                        nTotalAges += vBlockPeriods[ row ];
                        ++nCounter;
                    }
                    if ( nCounter > 1 )      // let's average what we have, 1 seems bogus??
                    {
                        if( nTotalAges > 0 )
                        {
                            int 
                                nAverageBlockPeriod = nTotalAges / nCounter;    // since it's seconds, we
                                                                        // are happy with whole seconds
                            //const int
                            //    nONE_HOUR_in_seconds = 60 * 60;
        
                            if( nAverageBlockPeriod >= nSECONDsPerHOUR )
                                pQLaverage->setText( 
                                                   QDateTime::fromTime_t( nAverageBlockPeriod )
                                                   .toUTC()
                                                   .toString("hh:mm:ss")
                                                   );
                            else
                                pQLaverage->setText( 
                                                   QDateTime::fromTime_t( nAverageBlockPeriod )
                                                   .toUTC()
                                                   .toString("mm:ss")
                                                   );
                        }
                    }
                    if (fMostlyUpToDate)
                    {
                        if (!pQLprice->isVisible())
                        {
                            pQLpriceText->setVisible( true );
                            pQLprice->setVisible( true );

                            //pop_a_message_box( pQLpriceText->text().toStdString() );    // test
                        }
                        fMostlyUpToDate = false;
                        // add the price update here
                        double 
                            dPrice = 0.0;
                        //try
                        //{   
                            //temporarily blocked since it causes an exception in Qt somwehow-somewhere
                            //but not always???
                            dPrice = doGetYACprice();
                        //}
                        //catch (std::exception &e) 
                        //{
                        //    e;
                        //    dPrice = 0.0;
                        //}
                        //catch (...)
                        //{
                        //    dPrice = 0.0;
                        //}
                        if ( 0.0 != dPrice )
                        {
                            std::string
                                sP = doPrettyPrice( dLastPrice, dPrice );
    
                            // finally put the price into a QLabel!
                            pQLprice->setText( sP.c_str() );
                        }
                    }
                }
                else    // we received a block we already have, so sit quiet.  
                        // Maybe update Age times?
                        // Since blocks come ~1 minute apart, there seems to be no need!?
                {       
                }
            }
            else    // error reading disk
            {
            }
        }
        else        // in the catch up process, so stay quiet since blocks are too old
        {
            if (pQLprice->isVisible())
            {
                pQLprice->setVisible( false );                
            }
            pQLpriceText->setVisible( false );
        }
//_____________________________________________________________________________
//_____________________________________________________________________________
        // in a similar vein, let's do the transaction view
//_____________________________________________________________________________
//_____________________________________________________________________________
        // now check transactions similarly to blocks, but get the Tx hash from elsewhere
        QModelIndex
            TransactionTableIndex;

        //static uint256
        uint256
            lastHashKnown = 0;
            
        bool
            fMatched = true;

        uint256
            latestHashSeen = lastTxHash.retrieveLastHash(); // our hook from main.cpp's CTxMemPool::accept()

        if ( 
            (0 != latestHashSeen ) 
            &&
            (lastHashKnown != latestHashSeen)
           )    // work to do
        {
            fMatched = false;
            lastHashKnown = latestHashSeen;

            CTransaction
                CrefToTx;

            QVector< QString > vStringTransactionDataRow( TX_VIEW_SIZE );

            if( mempool.exists( latestHashSeen ) )
            {
                CrefToTx = mempool.lookup( latestHashSeen );

                std::string
                    strTemporary;

                // let's create a row of new tx data to display
                //_____________________________________________________________
                //_____________________________________________________________
                strTemporary = strprintf( "%s", CrefToTx.GetHash().ToString().c_str() );
                vStringTransactionDataRow[ TX_ID ] = strTemporary.c_str();  
                
                //_____________________________________________________________
                strTemporary = strprintf( "%.3f %s", CrefToTx.GetValueOut() / 1000000.0, sCOIN_SYMBOL.c_str() );
                vStringTransactionDataRow[ TX_AMOUNT  ] = strTemporary.c_str();

                //_____________________________________________________________
                int64_t
                    nTimeOfTx = CrefToTx.nTime;

                strTemporary = QDateTime::fromTime_t( nTimeOfTx ).toString("hh:mm:ss MM/dd/yyyy").toStdString();
                vStringTransactionDataRow[ TX_TIME  ] = strTemporary.c_str();

                //_____________________________________________________________
                int64_t
                    nQTimeNow = Qnow.toMSecsSinceEpoch() / 1000;    // this is now in seconds
                int
                    nTxAge = (int)( nQTimeNow - nTimeOfTx );

                if( nTxAge > 0 )
                    strTemporary = QDateTime::fromTime_t( nTxAge ).toUTC().toString("hh:mm:ss").toStdString();
                else
                    strTemporary = strprintf( "%d sec", nTxAge );
                vStringTransactionDataRow[ TX_AGE  ] = strTemporary.c_str();

                //_____________________________________________________________
                //_____________________________________________________________
                // we now have a new Tx row to add to the model

                if( qlistOfTxRows.isEmpty() )
                    qlistOfTxRows.append( vStringTransactionDataRow ); // same as for blocks above
                    //qlistOfTxRows.prepend( vStringTransactionDataRow );
                else    // there are rows
                {
                    int
                        nNumberOfRows = qlistOfTxRows.size();

                    // if the tx id doesn't match any tx we are already displaying, then add, i.e. prepend()
                    for ( int row = 0; row < nNumberOfRows; ++row )
                    {
                        uint256
                            hashTest( pQSIMtransactions->item( row, TX_ID )->text().toStdString() );

                        if( hashTest == latestHashSeen )    // we have this Tx already
                        {
                            fMatched = true;
                            break;
                        }
                        //else  //hash doesn't match
                    }
                    if ( !fMatched )
                    {
                        if( nNumberOfRows >= nROWS_OF_DISPLAYED_TRANSACTIONS )  
                            qlistOfTxRows.removeLast(); // model is full, so delete last row in our Qlist
                        qlistOfTxRows.prepend( vStringTransactionDataRow ); // so we have added a row
                    }
                  //else  //we matched so don't add the same Transaction, i.e. do nothing
                }

                if ( !fMatched )
                {   // this puts the model into the view
                    std::string
                        sHashToAvoid = CrefToTx.GetHash().ToString();
                    int
                        nNumberOfRows = qlistOfTxRows.size();
                    // really should recalculate times of all but the first row
                    for ( int row = 0; row < nNumberOfRows; ++row )
                    {
                        for ( int column = 0; column < TX_VIEW_SIZE; ++column )
                        {
                            TransactionTableIndex = pQSIMtransactions->index( 
                                                                        row,
                                                                        column,
                                                                        QModelIndex() 
                                                                            );
                            if (TX_AGE == column ) // recalculate the age displayed of the older transactions
                            {
                                bool
                                    fOK;

                                std::string
                                    sV = qlistOfTxRows[ row ][ TX_ID ].toStdString();

                                if ( sV != sHashToAvoid )  // we need to update the age
                                {   // first get the Tx from the hash
                                    CTransaction
                                        CrefToAnOldTx;
                                    uint256
                                        hashToMatch,
                                        hashOfBlock = 0;    // not sure why?

                                    hashToMatch.SetHex( sV );
                                    
                                    bool 
                                        fFoundTx = GetTransaction(
                                                                hashToMatch, 
                                                                CrefToAnOldTx, 
                                                                hashOfBlock
                                                                 );
                                    if( fFoundTx )
                                    {
                                        int64_t
                                            nTimeOfTx = CrefToAnOldTx.nTime;
                                        int
                                            nTxAge = (int)( nQTimeNow - nTimeOfTx );
                                        std::string
                                            strTemporary;

                                        if( nTxAge > 0 )
                                            strTemporary = QDateTime::fromTime_t( nTxAge ).toUTC().toString("hh:mm:ss").toStdString();
                                        else
                                            strTemporary = strprintf( "%d sec", nTxAge );
                                        pQSIMtransactions->setData( 
                                                            TransactionTableIndex,
                                                            strTemporary.c_str()
                                                                  );
                                    }
                                    else   // couldn't find the hash??
                                    {
                                        pQSIMtransactions->setData( 
                                                            TransactionTableIndex,
                                                            qlistOfTxRows[ row ]
                                                                         [ column ].toStdString().c_str()
                                                                  );
                                        //____________ just to see what is being done?
                                        /***********************************
                                        TransactionTableIndex = pQSIMtransactions->index( 
                                                                        row,
                                                                        TX_nm,
                                                                        QModelIndex() 
                                                                                        );
                                        pQSIMtransactions->setData( 
                                                            TransactionTableIndex,
                                                            sHashToAvoid.c_str()
                                                                  );
                                        //____________ just to see what is being done?
                                        pQTVtransactions->resizeColumnToContents( TX_nm );
                                        ***********************************/
                                    }
                                }
                                else        //this is the new one, so it's done already    
                                    pQSIMtransactions->setData( 
                                                            TransactionTableIndex,
                                                            qlistOfTxRows[ row ]
                                                                         [ column ].toStdString().c_str()
                                                              );
                            }
                            else    // for all the other columns
                                pQSIMtransactions->setData( 
                                                        TransactionTableIndex,
                                                        qlistOfTxRows[ row ]
                                                                     [ column ].toStdString().c_str()
                                                          );
                        }
                    }
                    pQTVtransactions->setModel( pQSIMtransactions );
                    pQTVtransactions->setEditTriggers( QAbstractItemView::NoEditTriggers );

                    // we should only resize once, I would think?
                    if( !fResizeTxsFields )
                    {
                        fResizeTxsFields = true;
                        for(int column = 0; column < TX_VIEW_SIZE; ++column)
                        {
                            //pQTVtransactions->resizeColumnToContents( column );
                            pQTVtransactions->resizeColumnToContents( TX_ID );
                            pQTVtransactions->resizeColumnToContents( TX_AGE );
                            pQTVtransactions->resizeColumnToContents( TX_TIME );
                            pQTVtransactions->resizeColumnToContents( TX_AMOUNT );
                            // test area 
                                        /***********************************
                            //pQTVtransactions->resizeColumnToContents( TX_nm );
                                        ***********************************/
                        }
                    }
                }
                else    // we received a Tx we already have
                {
                }
            }//else  // the hash doesn't exist (anymore?) so no  transaction info
        }
        else // we already have this hash (Tx) so no update
        {    // but let's freshen all the Ages, so this will happen ~1 minute since
            // it is the block time!
            if( !qlistOfTxRows.isEmpty() )  // there are rows whose times need updating
            {
                int
                    nNumberOfRows = qlistOfTxRows.size();
                // really should recalculate times of all the rows
                int64_t
                    nQTimeNow = Qnow.toMSecsSinceEpoch() / 1000;    // this is now in seconds
                for ( int row = 0; row < nNumberOfRows; ++row )
                {
                    int 
                        column = TX_AGE;

                    TransactionTableIndex = pQSIMtransactions->index( 
                                                                    row,
                                                                    column,
                                                                    QModelIndex() 
                                                                    );
                    std::string
                        sTxID = qlistOfTxRows[ row ][ TX_ID ].toStdString();

                    CTransaction
                        CrefToAnOldTx;
                    uint256
                        hashToMatch,
                        hashOfBlock = 0;    // not sure why?

                    hashToMatch.SetHex( sTxID );
                    
                    bool 
                        fFoundTx = GetTransaction(
                                                hashToMatch, 
                                                CrefToAnOldTx, 
                                                hashOfBlock
                                                 );
                    if( fFoundTx )
                    {
                        int64_t
                            nTimeOfTx = CrefToAnOldTx.nTime;
                        int
                            nTxAge = (int)( nQTimeNow - nTimeOfTx );
                        std::string
                            strTemporary;

                        if( nTxAge > 0 )
                            strTemporary = QDateTime::fromTime_t( nTxAge ).toUTC().toString("hh:mm:ss").toStdString();
                        else
                            strTemporary = strprintf( "%d sec", nTxAge );
                        pQSIMtransactions->setData( 
                                                    TransactionTableIndex,
                                                    strTemporary.c_str()
                                                  );
                    }
                }
                pQTVtransactions->setModel( pQSIMtransactions );
                pQTVtransactions->setEditTriggers( QAbstractItemView::NoEditTriggers );

                pQTVtransactions->resizeColumnToContents( TX_AGE );
            }
        }    
    }
    fDontReenterMe = false;
}
//_____________________________________________________________________________

void ExplorerPage::on_closeButton_clicked()
{
    if( true == fCloseButton )
        close();
}

//_____________________________________________________________________________
//_____________________________________________________________________________


















//_____________________________________________________________________________
//_____________________________________________________________________________
// block detail window constructor
// initialize the table view headers, etc.
//_____________________________________________________________________________
BlockExplorerPage::BlockExplorerPage(QDialog *parent ) :
    QDialog(parent)
    //QWidget(parent)
    , ui(new Ui::BlockExplorerPage)
    //, model(0)
{
    ui->setupUi(this);

    pclientModel = NULL;
    //this->pExplorerPage = NULL;

//    pQTBblock = ui->textBrowser;
//    pQTBblock->setOpenLinks( false );
    pQTVblockinfo = ui->tableView;

    pQISM = pQTVblockinfo->selectionModel();

    pQTVblockinfo->setShowGrid( false );
    

    fBlkInfoConnected = false;

    char 
        *pcArrayOfBlockinfoHeaders[ BLOCK_INFO_VIEW_SIZE ];

    pcArrayOfBlockinfoHeaders[ BLOCK_INFO_ITEM ] = "Name";
    pcArrayOfBlockinfoHeaders[ BLOCK_INFO_VALUE ] = "Value";
    
    pQSIMblockinfo = new QStandardItemModel( nARBITRARY_LARGE_NUMBER_OF_ROWS, BLOCK_INFO_VIEW_SIZE, this );

    for (int column = 0; column < BLOCK_INFO_VIEW_SIZE; ++column)
    {
        pQSIMblockinfo->setHorizontalHeaderItem( 
                                            column, 
                                            new QStandardItem( 
                                                              QString( 
                                                                    pcArrayOfBlockinfoHeaders[ column ] 
                                                                     ) 
                                                             ) 
                                               );
        //pQTVblockinfo->resizeColumnToContents( column );
    }
    pQTVblockinfo->setModel( pQSIMblockinfo );
    pQTVblockinfo->setEditTriggers( QAbstractItemView::NoEditTriggers );
}
//_____________________________________________________________________________
//_____________________________________________________________________________
// just a POF to assist BlockExplorerPage::fillBlockInfoPage
//_____________________________________________________________________________
std::string BuildBlockinfoDetailsFrom( 
                                        CBlock &block, 
                                        CBlockIndex* pblockindex,
                                        QStandardItemModel *pQSIMblockinfo,
                                        QTableView *pQTVblockinfo
                                     )
{
    int
        nRowCount = 0,
        nNumberOfRows = pQSIMblockinfo->rowCount();

    if ( nNumberOfRows > 0 )
    {
        pQSIMblockinfo->setRowCount( nARBITRARY_LARGE_NUMBER_OF_ROWS );
    }

    int
        BLOCK_INFO_ITEM = BlockExplorerPage::BLOCK_INFO_ITEM,
        BLOCK_INFO_VALUE = BlockExplorerPage::BLOCK_INFO_VALUE;

    std::string
        sTime = QDateTime::fromTime_t( block.nTime ).
                          toString("hh:mm:ss MM/dd/yyyy").
                          toStdString();

    CBigNum 
        bnTarget;

    bnTarget.SetCompact( block.nBits );

    uint256
        hTarget = bnTarget.getuint256();

    std::string
        sTarget = hTarget.GetHex();
    
    QModelIndex
        BlockinfoTableModelIndex;

    std::string
        sStandardItemModelElement,
        sTemp = strprintf( 
                        "function BuildBlockinfoDetailsFrom()\n"
                        "%s",
                        //"<br />"
                        "<h3 >"
                        "<b >CBlockIndex (fillBlockInfoPage() call)</b >"
                        "</h3 >"
                        //"<br />"
                        ""
                         );
    //_________________________________________________________________________
    sStandardItemModelElement = "Block hash";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()   //"<b >Block hash</b >"
                           );
    sStandardItemModelElement = pblockindex->GetBlockHash().ToString().c_str();
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()   //pblockindex->GetBlockHash().ToString().c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________

    if( pblockindex->pprev )
    {
        sStandardItemModelElement = "previous block";
        sTemp += "<b >" + sStandardItemModelElement + "</b > = ";
        pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                               );
        sStandardItemModelElement = strprintf(
                        "%s"
                        , pblockindex->pprev->GetBlockHash().ToString().c_str()
                                             );
        sTemp += "<font color = 'blue' ><a href = '' >" + sStandardItemModelElement + "</a ></font ><br />\n";
        pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                               );
        ++nRowCount;
    }
    //_________________________________________________________________________

    bool
        fTop = (NULL == pblockindex->pnext)? true: false;

    if( !fTop ) // there is a next block
    {
        sStandardItemModelElement = "next block";
        sTemp += "<b >" + sStandardItemModelElement + "</b >";
        pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                               );
        sStandardItemModelElement = pblockindex->pnext->GetBlockHash().ToString();
        sTemp += sStandardItemModelElement + "<br />\n";
        pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                               );
        ++nRowCount;
    //_________________________________________________________________________
    }
    sStandardItemModelElement = "nFile";
    sTemp += "(<b >" + sStandardItemModelElement + "</b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    sStandardItemModelElement = strprintf(
                        " %u "
                        , pblockindex->nFile
                                         );
    sTemp += sStandardItemModelElement + ")<br />\n";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "nBlockPos";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    sStandardItemModelElement = strprintf(
                        " (%-6d)"
                        , pblockindex->nBlockPos
                                         );
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "nHeight";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    sStandardItemModelElement = strprintf(
                        " %d "
                        , pblockindex->nHeight
                                         );
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "nMint";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    sStandardItemModelElement = strprintf(
                        " %s, "
                        , FormatMoney( pblockindex->nMint ).c_str()
                                         );
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "nMoneySupply";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    sStandardItemModelElement = strprintf(
                        " %s "
                        , FormatMoney( pblockindex->nMoneySupply ).c_str()
                                         );
    sTemp += sStandardItemModelElement + "<br />";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "nFlags";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );

    sStandardItemModelElement = strprintf(
                        " (%s)"
                        , pblockindex->GeneratedStakeModifier() ? "MOD" : "-"
                                         );
    sTemp += sStandardItemModelElement;
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "entropy";
    sTemp += "(<b >" + sStandardItemModelElement + "</b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    sStandardItemModelElement = strprintf(
                        " (%d)"
                        , pblockindex->GetStakeEntropyBit()
                                         );
    sTemp += sStandardItemModelElement;
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "Block type";
    sTemp += sStandardItemModelElement;
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    sStandardItemModelElement = strprintf(
                        " (Po%s)"
                        , pblockindex->IsProofOfStake()? "S" : "W"   // i.e. PoS or PoW
                                         );
    sTemp += "(<b >" + sStandardItemModelElement + "</b >)<br />";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "nStakeModifier";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    sStandardItemModelElement = strprintf(
                        " %016"PRI64x" "
                        , pblockindex->nStakeModifier
                                         );
    sTemp += sStandardItemModelElement + "<br />";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "nStakeModifierChecksum";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    sStandardItemModelElement = strprintf(
                        " %08x "
                        , pblockindex->nStakeModifierChecksum
                                         );
    sTemp += sStandardItemModelElement + "<br />";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________

    if ( 0 != pblockindex->hashProofOfStake )
    {
        std::string
            sHPOS1 = "hashProofOfStake = ",
            sHPOS2 = "",
            sHPOS3 = "\n",
            sHPOS = "";

        sHPOS2 = pblockindex->hashProofOfStake.ToString();
        sHPOS = sHPOS1 + sHPOS2 + sHPOS3;

        sStandardItemModelElement = "hashProofOfStake";
        sTemp += sStandardItemModelElement + " = ";
        pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                               );
        sStandardItemModelElement = pblockindex->hashProofOfStake.ToString();
        sTemp += sStandardItemModelElement + "<br />\n";
        pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                               );
        ++nRowCount;
    //_________________________________________________________________________
    }

    sStandardItemModelElement = "prevoutStake";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    sStandardItemModelElement = strprintf(
                        " (%s) "
                        , pblockindex->prevoutStake.ToString().c_str()
                                         );
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "nStakeTime";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    sStandardItemModelElement = strprintf(
                        " %d "
                        , pblockindex->nStakeTime
                                         );
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "merkle root hash";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    sStandardItemModelElement = strprintf(
                        " %s "
                        , pblockindex->hashMerkleRoot.ToString().c_str()
                                         );
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "Block hash";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    sStandardItemModelElement = strprintf(
                        " %s"
                        ""
                        , pblockindex->GetBlockHash().ToString().c_str()
                                         );
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "CBlock";
    sTemp += "\n<h3 ><b >" + sStandardItemModelElement + "</b ></h3 >\n";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            ""
                           );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "hash";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    sStandardItemModelElement = strprintf(
                        " %s"
                        , block.GetHash().ToString().c_str()
                                         );
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "ver";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    sStandardItemModelElement = strprintf(
                        " %d"
                        , block.nVersion
                                         );
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "hashPrevBlock";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    sStandardItemModelElement = strprintf(
                        " %s"
                        , block.hashPrevBlock.ToString().c_str()
                                         );
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "hashMerkleRoot";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    sStandardItemModelElement = strprintf(
                        " %s"
                        , block.hashMerkleRoot.ToString().c_str()
                                         );
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "nTime";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    sStandardItemModelElement = strprintf(
                        " %u (local %s)"
                        , block.nTime, sTime.c_str()
                                         );
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________

    const int 
        nArbitaryHexDigitsToShow = 16;                

    sStandardItemModelElement = "nBits";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    sStandardItemModelElement = strprintf(
                        " %08x (target %s...)"
                        , block.nBits, sTarget.substr(0,nArbitaryHexDigitsToShow).c_str()
                                         );
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "nNonce";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    sStandardItemModelElement = strprintf(
                        " %u(dec) %08x(hex)"
                        , block.nNonce, block.nNonce
                                         );
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "block.vtx count";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    sStandardItemModelElement = strprintf(
                        " %"PRIszu" "
                        , block.vtx.size()
                                         );
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________

    sStandardItemModelElement = "vchBlockSig";
    sTemp += "<b >" + sStandardItemModelElement + "</b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    //sStandardItemModelElement = strprintf(
    //                    " %s"
    //                    , HexStr(block.vchBlockSig.begin(), block.vchBlockSig.end()).c_str()
    //                                     );
    sStandardItemModelElement = " " + HexStr(block.vchBlockSig.begin(), block.vchBlockSig.end());
    sTemp += sStandardItemModelElement + "<br />\n";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    //_________________________________________________________________________
    int
        nVTxSize = block.vtx.size();
    for (unsigned int i = 0; i < nVTxSize; ++i)
    {
        sStandardItemModelElement = strprintf( "vtx[ %d ]", i );
        sTemp += sStandardItemModelElement;
        pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                               );
        sStandardItemModelElement = " " + block.vtx[i].ToString(); // this may need work
        sTemp += "&nbsp;&nbsp;" + sStandardItemModelElement + "<br />\n";
        pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                               );
        ++nRowCount;
    //_________________________________________________________________________
        //pQSIMblockinfo->setRowCount( nRowCount + 1 );
        /**************************************************
        std::string 
            str;            // CTransaction.ToString()
        str = IsCoinBase()? "Coinbase" : (IsCoinStake()? "Coinstake" : "CTransaction");
        str += strprintf(
                        "("
                        "<b >hash</b >=%s"
                        "<b >nTime</b >=%d"
                        "<b >ver</b >=%d"
                        "<b >vin.size</b >=%"PRIszu""
                        "<b >vout.size</b >=%"PRIszu""
                        "<b >nLockTime</b >=%d"
                        ")"
                        "\n"
                        ""
                        , GetHash().ToString().substr(0,10).c_str()
                        , nTime
                        , nVersion
                        , vin.size()
                        , vout.size()
                        , nLockTime
                        );
        for (unsigned int i = 0; i < vin.size(); ++i)
        {            // CTxIn.ToString()
            str += "    " + vin[i].ToString() + "\n";

            str += "CTxIn(";
            str += prevout.ToString();
            if (prevout.IsNull())
                str += strprintf(", coinbase %s", HexStr(scriptSig).c_str());
            else
                str += strprintf(", scriptSig=%s", scriptSig.ToString().substr(0,24).c_str());
            if (nSequence != std::numeric_limits<unsigned int>::max())
                str += strprintf(", nSequence=%u", nSequence);
            str += ")";
            //return str;
        }
        for (unsigned int i = 0; i < vout.size(); ++i)
        {
            str += "    " + vout[i].ToString() + "\n";

            if (IsEmpty()) 
                return "CTxOut(empty)";
            if (scriptPubKey.size() < 6)
                return "CTxOut(error)";
            return strprintf(
                            "CTxOut(nValue=%s, scriptPubKey=%s)"
                            , FormatMoney(nValue).c_str()
                            , scriptPubKey.ToString().c_str()
                            );
        }
        //return str;
        **************************************************/
    }
    //_________________________________________________________________________
    int
        nSize = block.vMerkleTree.size();

    sStandardItemModelElement = "vMerkleTree:"; 
    sTemp += "<b >" + sStandardItemModelElement + " </b >";
    pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                           );
    if ( 0 == nSize )
    {
        sStandardItemModelElement = strprintf(
                            "%s"
                            , block.hashMerkleRoot.ToString().c_str()
                                             );
    }
    else
    {
        sStandardItemModelElement = strprintf(
                            "  %s "
                            , block.vMerkleTree[ 0 ].ToString().c_str()
                                             );
    }
    sTemp += "&nbsp;&nbsp;" + sStandardItemModelElement + "<br />\n";
    pQSIMblockinfo->setData( 
                        pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                        sStandardItemModelElement.c_str()
                           );
    ++nRowCount;
    for ( int i = 1; i < nSize; ++i )
    {   
        sStandardItemModelElement = strprintf( "vMerkleTree[ %d ]", i );
        //sTemp += sStandardItemModelElement;
        pQSIMblockinfo->setData( 
                        pQSIMblockinfo->index( nRowCount, BLOCK_INFO_ITEM, QModelIndex() ),
                        sStandardItemModelElement.c_str()
                               );
        sStandardItemModelElement = strprintf(
                            "  %s "
                            , block.vMerkleTree[ i ].ToString().c_str()
                                             );
        sTemp += "&nbsp;&nbsp;" + sStandardItemModelElement + "<br />\n";
        pQSIMblockinfo->setData( 
                            pQSIMblockinfo->index( nRowCount, BLOCK_INFO_VALUE, QModelIndex() ),
                            sStandardItemModelElement.c_str()
                               );
        ++nRowCount;
    //_________________________________________________________________________
    }
    pQSIMblockinfo->setRowCount( nRowCount );

    pQTVblockinfo->setWordWrap( true ); // there seems to be a limit to cell width?? 
    pQTVblockinfo->setEditTriggers( QAbstractItemView::NoEditTriggers );
    pQTVblockinfo->setModel( pQSIMblockinfo );

    pQTVblockinfo->resizeColumnsToContents();
    pQTVblockinfo->resizeRowsToContents();

    return sTemp;
}
//_____________________________________________________________________________
// fills the Model with Block details and paints the view
//_____________________________________________________________________________

void BlockExplorerPage::fillBlockInfoPage( int currentHeight )
{
    CBlockIndex
        * pblockindex = mapBlockIndex[hashBestChain];

    while (pblockindex->nHeight > currentHeight)
        pblockindex = pblockindex->pprev;

    bool
        fTop = (NULL == pblockindex->pnext)? true: false;

    uint256 
      //hash = pblockindex->GetHash();
        hash = pblockindex->GetBlockHeader().GetHash();

    pblockindex = mapBlockIndex[ hash ];  // isn't this for Tx's and not blocks?
    
    CBlock 
        block;

    block.ReadFromDisk( pblockindex, true );

    CMerkleTx 
        txGen( block.vtx[ 0 ] );    // fixed it!!! Code that is inside read JSON!!!!!

    if( 0 == txGen.SetMerkleBranch( &block ) )  
    {
        pop_a_message_box( "curious?" );  
    }

    /********************************************/
    // now pblockindex & by implication, block contain all the information
    // one might need
    /********************************************/

    /********************************************
    Object                                  // a vector of pair types, or should be
        oJSONblock =  blockToJSON(          // if I take this out, it crashes???????????????
                                block, 
                                pblockindex, 
                                false  //true
                                 );
    int
        nSizeOfJSONblock = oJSONblock.size();

    json_spirit::Value 
        result = oJSONblock;

    // we have basically done a getblockbynumber # here!
    std::string 
        sJSONblockinfo;
 
    // format the JSON reply result
    if (result.type() == json_spirit::null_type)
        sJSONblockinfo = "";
    else 
        if (result.type() == json_spirit::str_type)
            sJSONblockinfo = result.get_str();
        else
            sJSONblockinfo = write_string(result, true);

    int
        nLengthOfResult = sJSONblockinfo.length();

    if ( nLengthOfResult > 0 )       // format it ourselves
    ********************************************/
    {
        std::string
            sX = BuildBlockinfoDetailsFrom( 
                                            block, 
                                            pblockindex, 
                                            pQSIMblockinfo, 
                                            pQTVblockinfo
                                          );
        this->pQTVblockinfo->clearSelection();
        this->show();
        //this->raise( );
        this->setVisible( true );
        this->activateWindow( );
    }
}
//_____________________________________________________________________________
//
//_____________________________________________________________________________

void BlockExplorerPage::showBkItem()
{
    //pop_a_message_box( "Clicked something!" );
}
//_____________________________________________________________________________
//
//_____________________________________________________________________________

void BlockExplorerPage::setModel(ClientModel *model)
{
    if(model)
    {
        BlockExplorerPage::setClientModel(model);
    }
}
//_____________________________________________________________________________
//
//_____________________________________________________________________________

void BlockExplorerPage::setClientModel(ClientModel *model)
{
    this->pclientModel = model;
    if(model)
    {
    }
}
//_____________________________________________________________________________
//
//_____________________________________________________________________________

//void BlockExplorerPage::followLink( const QUrl & link )
//{
//    pop_a_message_box( "Test!" );
//}
//_____________________________________________________________________________
//
//_____________________________________________________________________________

BlockExplorerPage::~BlockExplorerPage()
{
    //delete pQSIMblockinfo;

    delete ui;          
}
//_____________________________________________________________________________
//
//_____________________________________________________________________________

void BlockExplorerPage::on_closeButton_clicked()
{
    close();
}
//_____________________________________________________________________________
//_____________________________________________________________________________




























//_____________________________________________________________________________
//_____________________________________________________________________________
//
//_____________________________________________________________________________
TransactionExplorerPage::TransactionExplorerPage(QDialog *parent ) :
    QDialog(parent)
    //QWidget(parent)
    , ui(new Ui::TransactionExplorerPage)
    //, model(0)
{
    ui->setupUi(this);

    pclientModel = NULL;
    //this->pExplorerPage = NULL;

//    pQTBtransaction = ui->textBrowser;
    pQTVtxinfo = ui->tableView;

    pQTVtxinfo->setShowGrid( false );

    fTxInfoConnected = false;

    char 
        *pcArrayOfTxinfoHeaders[ TRANSACTION_INFO_VIEW_SIZE ];

    pcArrayOfTxinfoHeaders[ TRANSACTION_INFO_ITEM ] = "Name";
    pcArrayOfTxinfoHeaders[ TRANSACTION_INFO_VALUE ] = "Value";

    pQSIMtxinfo = new QStandardItemModel( nARBITRARY_LARGE_NUMBER_OF_ROWS, TRANSACTION_INFO_VIEW_SIZE, this );
    for (int column = 0; column < TRANSACTION_INFO_VIEW_SIZE; ++column)
    {
        pQSIMtxinfo->setHorizontalHeaderItem( 
                                            column, 
                                            new QStandardItem( 
                                                              QString( 
                                                                    pcArrayOfTxinfoHeaders[ column ] 
                                                                     ) 
                                                             ) 
                                            );
        //pQTVTxinfo->resizeColumnToContents( column );
    }
    pQTVtxinfo->setModel( pQSIMtxinfo );
    pQTVtxinfo->setEditTriggers( QAbstractItemView::NoEditTriggers );
}
//_____________________________________________________________________________
//
//_____________________________________________________________________________

void TransactionExplorerPage::setClientModel(ClientModel *model)
{
    this->pclientModel = model;
    if(model)
    {
    }
}
//_____________________________________________________________________________
//
//_____________________________________________________________________________

void TransactionExplorerPage::setModel(ClientModel *model)
{
    if(model)
    {
        TransactionExplorerPage::setClientModel(model);
    }
}
//_____________________________________________________________________________
//
//_____________________________________________________________________________

TransactionExplorerPage::~TransactionExplorerPage()
{
    //delete pQSIMtxinfo;
    
    delete ui;          
}
//_____________________________________________________________________________
//
//_____________________________________________________________________________

void TransactionExplorerPage::on_closeButton_clicked()
{
    close();
}
//_____________________________________________________________________________
//_____________________________________________________________________________


























//_____________________________________________________________________________
//_____________________________________________________________________________
//
//_____________________________________________________________________________

CLastTxHash::CLastTxHash( )
{
    lastHash = 0;
    //nNumberOfExplorers = 2;
    explorer_counter = nNumberOfExplorers;
}
//_____________________________________________________________________________
//
//_____________________________________________________________________________
void CLastTxHash::storeLasthash( uint256 &hash )
{
    lastHash = hash;
    if( 0 == --explorer_counter )
        explorer_counter = nNumberOfExplorers;

}
//_____________________________________________________________________________
//
//_____________________________________________________________________________

uint256 CLastTxHash::retrieveLastHash()
{
    return lastHash;
}
//_____________________________________________________________________________
//_____________________________________________________________________________
