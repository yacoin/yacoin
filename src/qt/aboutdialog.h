#ifndef ABOUTDIALOG_H
#define ABOUTDIALOG_H

#include <QWidget>
#include <QPushButton>

namespace Ui {
    class AboutDialog;
}
class ClientModel;

/** "About" dialog box */
class AboutDialog : public QWidget
{
    Q_OBJECT

public:
    explicit AboutDialog(QWidget *parent = 0);
    ~AboutDialog();

    void setModel(ClientModel *model);
private:
    Ui::AboutDialog *ui;

    void keyPressEvent(QKeyEvent *);

private slots:

    void on_pushButton_clicked();
};

#endif // ABOUTDIALOG_H
