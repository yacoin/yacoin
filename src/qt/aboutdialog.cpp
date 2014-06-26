#include "aboutdialog.h"
#include "ui_aboutdialog.h"
#include "clientmodel.h"

#include "version.h"

#include "db.h"
#include <boost/version.hpp> 
#include <openssl/crypto.h>

AboutDialog::AboutDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AboutDialog)
{
    ui->setupUi(this);
}

void AboutDialog::setModel(ClientModel *model)
{
    if(model)
    {
        int
            nBdbMajor,
            nBdbMinor,
            nBdbPatch;

        (void)db_version( &nBdbMajor, &nBdbMinor, &nBdbPatch );
        std::string
            sOpenSSLVersion = "",
            sBdbVersion = "",
            sBoostVersion = "",
            sBoostWin = "";

        sOpenSSLVersion = strprintf("&nbsp;&nbsp;&nbsp;&nbsp;"
                                    //"&nbsp;&nbsp;"
                                    "(<b>OpenSSL</b> %s"
                                    "",
                                    SSLeay_version(SSLEAY_VERSION)
                                   );
        sBdbVersion = strprintf(    "&nbsp;&nbsp;&nbsp;&nbsp;"
                                    //"&nbsp;&nbsp;"
                                    "<b>BerkeleyDB</b> %d.%d.%d"
                                    "", 
                                    nBdbMajor,
                                    nBdbMinor,
                                    nBdbPatch
                                   );
        sBoostVersion = strprintf(  "&nbsp;&nbsp;&nbsp;&nbsp;"
                                    //"&nbsp;&nbsp;"
                                    "<b>Boost</b> %d.%d.%d"         // miiill (most, insignificant, least) digits
                                    "",
                                    BOOST_VERSION / 100000,
                                    (BOOST_VERSION / 100) % 1000,
                                    BOOST_VERSION % 100
                                     );
#ifdef BOOST_WINDOWS
        sBoostWin =          (  "&nbsp;&nbsp;&nbsp;&nbsp;"
                                //"&nbsp;&nbsp;"
                                "Windows platform is available to Boost" 
                             );
#endif
        ui->versionLabel->setText(
                                  model->formatFullVersion() +
                                  QString::fromStdString(
                                                        //"(" +
                                                        sOpenSSLVersion +
                                                        sBdbVersion +
                                                        sBoostVersion +
                                                        sBoostWin +
                                                        ")"
                                                         )
                                 );
    }
}

AboutDialog::~AboutDialog()
{
    delete ui;
}

void AboutDialog::on_buttonBox_accepted()
{
    close();
}
