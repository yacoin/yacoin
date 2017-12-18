#include "aboutdialog.h"
#include "ui_aboutdialog.h"

#include "dialogwindowflags.h"

#include "clientmodel.h"

#include "version.h"

#include <QKeyEvent>

AboutDialog::AboutDialog(QWidget *parent) :
    QWidget(parent, DIALOGWINDOWHINTS),
    ui(new Ui::AboutDialog)
{
    ui->setupUi(this);
#ifdef WIN32
    const char *pC = __DATE__; //"mmm dd yyyy"
    ui->copyrightLabel->setText(
        //Copyright © 2009-2015 The Bitcoin developers
        //Copyright © 2011-2012 The PPCoin Developers
        //Copyright © 2014 The Peerunity Developers
        //Copyright © 2014 The EmerCoin Developers
        //Copyright © 2012-2015 The NovaCoin developers
        //Copyright © 2013-2015 The Yacoin developers

                                tr("Copyright") + QString(" &copy; 2009-2014 ") + tr("The Bitcoin developers,") + "<br \\>" +
                                tr("Copyright") + QString(" &copy; 2011-2012 ") + tr("The PPCoin developers,") + "<br \\>" +
                                tr("Copyright") + QString(" &copy; 2014 ") + tr("The Peerunity developers,") + "<br \\>" +
                                tr("Copyright") + QString(" &copy; 2014 ") + tr("The EmerCoin developers,") + "<br \\>" +
                                tr("Copyright") + QString(" &copy; 2012-2015 ") + tr("The NovaCoin developers,") + "<br \\>" +
                                tr("Copyright") + QString(" &copy; 2013-<b>%1</b> ").arg( &pC[ 7 ] ) + tr("The YACoin developers.") 
                               );
#else
#endif
}

void AboutDialog::setModel(ClientModel *model)
{
    if(model)
    {
        ui->versionLabel->setText(model->formatFullVersion());
    }
}

AboutDialog::~AboutDialog()
{
    delete ui;
}

void AboutDialog::keyPressEvent(QKeyEvent *event)
{
#ifdef ANDROID
    if(event->key() == Qt::Key_Back)
    {
        close();
    }
#else
    if(event->key() == Qt::Key_Escape)
    {
        close();
    }
#endif
}

void AboutDialog::on_pushButton_clicked()
{
    close();
}
