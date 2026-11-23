#pragma once

#include <QMainWindow>
#include <QProcess>

class QCheckBox;
class QCloseEvent;
class QLineEdit;
class QPlainTextEdit;
class QProgressBar;
class QPushButton;
class QLabel;

namespace vpngate::installer {

class MainWindow final : public QMainWindow {
public:
    explicit MainWindow(QWidget *parent = nullptr);

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    void chooseSource();
    void choosePrefix();
    void startInstall(bool dryRun);
    void startUninstall();
    void startVerify();
    void launchCli(const QStringList &arguments);
    void consumeOutput();
    void appendLog(const QString &line);
    QString cliExecutable() const;
    void setBusy(bool busy);

    QLineEdit *sourceEdit_ = nullptr;
    QLineEdit *prefixEdit_ = nullptr;
    QCheckBox *forceModifiedCheck_ = nullptr;
    QPlainTextEdit *logView_ = nullptr;
    QProgressBar *progressBar_ = nullptr;
    QLabel *phaseLabel_ = nullptr;
    QLabel *statusLabel_ = nullptr;
    QPushButton *previewButton_ = nullptr;
    QPushButton *installButton_ = nullptr;
    QPushButton *verifyButton_ = nullptr;
    QPushButton *uninstallButton_ = nullptr;
    QProcess process_;
    QByteArray pendingOutput_;
};

} // namespace vpngate::installer
