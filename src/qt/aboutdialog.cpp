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
#ifdef WIN32
    const char *pC = __DATE__; //"mmm dd yyyy"

    ui->copyrightLabel->setText(
                                tr("Copyright") + 
                                QString(" &copy; 2009-2012 ") + 
                                tr("The NovaCoin developers,") +
                                QString(" &copy; <b>%1</b> ").arg( &pC[ 7 ] ) + 
                                tr("The YACoin developers.") 
                               );
#else
    // Copyright © 2009-2012 The NovaCoin developers, 2013 The YACoin developers. 
    ui->copyrightLabel->setText(
                                tr("Copyright") + 
                                QString(" &copy; 2009-2012 ") + 
                                tr("The NovaCoin developers,") +
                                QString(" 2013 ") + 
                                tr("The YACoin developers.")
                               );
#endif
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

        sOpenSSLVersion = strprintf(
                                    "<br />"
                                      //"&nbsp;&nbsp;"
                                    "<b>OpenSSL</b> %s"
                                    "",
                                    SSLeay_version(SSLEAY_VERSION)
                                   );
        sBdbVersion = strprintf(
                                    "<br />"
                                    //"&nbsp;&nbsp;"
                                    "<b>BerkeleyDB</b> %d.%d.%d"
                                    "",
                                    nBdbMajor,
                                    nBdbMinor,
                                    nBdbPatch
                                   );
        sBoostVersion = strprintf(
                                    "<br />"
                                    //"&nbsp;&nbsp;"
                                    "<b>Boost</b> %d.%d.%d"         // miiill (most, insignificant, least) digits
                                    "",
                                    BOOST_VERSION / 100000,
                                    (BOOST_VERSION / 100) % 1000,
                                    BOOST_VERSION % 100
                                     );
#ifdef BOOST_WINDOWS
        sBoostWin =          (
                                "<br />"
                                //"&nbsp;&nbsp;"
                                "Windows platform is available to Boost" 
                             );
#endif
        ui->versionLabel->setText(
                                  model->formatFullVersion() +
                                  QString::fromStdString(
                                                        sOpenSSLVersion +
                                                        sBdbVersion +
                                                        sBoostVersion +
                                                        sBoostWin
                                                         )
                                 );
    }
}

AboutDialog::~AboutDialog()
{
    delete ui;
}

void AboutDialog::on_closeButton_clicked()
{
    close();
}
