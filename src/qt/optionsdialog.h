#ifndef OPTIONSDIALOG_H
#define OPTIONSDIALOG_H

#include <QWidget>

namespace Ui {
class OptionsDialog;
}
class OptionsModel;
class MonitoredDataMapper;
class QValidatedLineEdit;

/** Preferences dialog. */
class OptionsDialog : public QWidget
{
    Q_OBJECT

public:
    explicit OptionsDialog(QWidget *parent = 0);
    ~OptionsDialog();

    void setModel(OptionsModel *model);
    void setMapper();

protected:
    bool eventFilter(QObject *object, QEvent *event);
    void keyPressEvent(QKeyEvent *);

private slots:
    /* enable only apply button */
    void enableApplyButton();
    /* disable only apply button */
    void disableApplyButton();
    /* enable apply button and OK button */
    void enableSaveButtons();
    /* disable apply button and OK button */
    void disableSaveButtons();
    /* set apply button and OK button state (enabled / disabled) */
    void setSaveButtonState(bool fState);
    /* set OK button state (enabled / disabled) */
    void setOkButtonState(bool fState);
    void on_okButton_clicked();
    void on_cancelButton_clicked();
    void on_applyButton_clicked();

    void showRestartWarning_Proxy();
    void showRestartWarning_Tor();
    void showRestartWarning_Lang();
    void showRestartWarning_URL();
    void showRestartWarning(bool fPersistent = false);
    void updateDisplayUnit();
    void clearStatusLabel();
    void updateProxyValidationState();
    /* query the networks, for which the default proxy is used */
    void updateDefaultProxyNets();

signals:
    void proxyIpValid(QValidatedLineEdit *object, bool fValid);
    void torIpValid(QValidatedLineEdit *object, bool fValid);
    void validationDidChange(QValidatedLineEdit *validatedLineEdit);

private:
    Ui::OptionsDialog *ui;
    OptionsModel *model;
    MonitoredDataMapper *mapper;
    bool fRestartWarningDisplayed_Proxy;
    bool fRestartWarningDisplayed_Tor;
    bool fRestartWarningDisplayed_Lang;
    bool fRestartWarningDisplayed_URL;
    bool fProxyIpValid;
    bool fTorIpValid;
};

#endif // OPTIONSDIALOG_H
