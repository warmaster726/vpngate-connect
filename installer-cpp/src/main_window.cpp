#include "main_window.hpp"

#include "installer_core.hpp"

#include <QCheckBox>
#include <QCloseEvent>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QFont>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QStandardPaths>
#include <QTextCursor>
#include <QVBoxLayout>
#include <QWidget>

namespace vpngate::installer {
namespace {

QString appSuffix() {
#if defined(Q_OS_WIN)
    return QStringLiteral(".exe");
#else
    return {};
#endif
}

} // namespace

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    setWindowTitle(QStringLiteral("VPN Gate Connect Installer"));
    setMinimumSize(760, 580);

    auto *central = new QWidget(this);
    auto *layout = new QVBoxLayout(central);
    layout->setContentsMargins(24, 22, 24, 20);
    layout->setSpacing(14);

    auto *title = new QLabel(QStringLiteral("VPN Gate Connect"), central);
    QFont titleFont = title->font();
    titleFont.setPointSize(titleFont.pointSize() + 7);
    titleFont.setBold(true);
    title->setFont(titleFont);
    layout->addWidget(title);

    auto *subtitle = new QLabel(QStringLiteral("C++ installer migration · %1").arg(hostDescription()), central);
    subtitle->setStyleSheet(QStringLiteral("color: #586477;"));
    layout->addWidget(subtitle);

    auto *migrationNotice = new QLabel(
        QStringLiteral("This GUI currently performs per-user install and manifest-based cleanup. "
                       "Full host workflows are available from the CLI on Linux, macOS, and Windows, but "
                       "macOS/Windows behavior still needs native parity and side-effect testing. Keep using "
                       "the existing platform scripts until those checks pass."), central);
    migrationNotice->setWordWrap(true);
    migrationNotice->setStyleSheet(QStringLiteral("background: #fff4d8; color: #704b00; padding: 10px; border-radius: 6px;"));
    layout->addWidget(migrationNotice);

    auto *form = new QFormLayout;
    form->setLabelAlignment(Qt::AlignLeft);
    form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);

    auto *sourceRow = new QWidget(central);
    auto *sourceLayout = new QHBoxLayout(sourceRow);
    sourceLayout->setContentsMargins(0, 0, 0, 0);
    sourceEdit_ = new QLineEdit(defaultSourceDir(), sourceRow);
    auto *sourceBrowse = new QPushButton(QStringLiteral("Browse…"), sourceRow);
    sourceLayout->addWidget(sourceEdit_, 1);
    sourceLayout->addWidget(sourceBrowse);
    form->addRow(QStringLiteral("Source checkout"), sourceRow);

    auto *prefixRow = new QWidget(central);
    auto *prefixLayout = new QHBoxLayout(prefixRow);
    prefixLayout->setContentsMargins(0, 0, 0, 0);
    prefixEdit_ = new QLineEdit(defaultPrefix(), prefixRow);
    auto *prefixBrowse = new QPushButton(QStringLiteral("Browse…"), prefixRow);
    prefixLayout->addWidget(prefixEdit_, 1);
    prefixLayout->addWidget(prefixBrowse);
    form->addRow(QStringLiteral("Per-user install location"), prefixRow);
    layout->addLayout(form);

    auto *options = new QHBoxLayout;
    forceModifiedCheck_ = new QCheckBox(QStringLiteral("Force removal/replacement of modified files listed in the installer manifest"), central);
    options->addWidget(forceModifiedCheck_);
    options->addStretch(1);
    layout->addLayout(options);

    auto *buttons = new QHBoxLayout;
    previewButton_ = new QPushButton(QStringLiteral("Preview plan"), central);
    installButton_ = new QPushButton(QStringLiteral("Install / Update"), central);
    verifyButton_ = new QPushButton(QStringLiteral("Verify"), central);
    uninstallButton_ = new QPushButton(QStringLiteral("Uninstall"), central);
    buttons->addWidget(previewButton_);
    buttons->addStretch(1);
    buttons->addWidget(verifyButton_);
    buttons->addWidget(uninstallButton_);
    buttons->addWidget(installButton_);
    layout->addLayout(buttons);

    phaseLabel_ = new QLabel(QStringLiteral("Ready · no changes have been made."), central);
    layout->addWidget(phaseLabel_);
    progressBar_ = new QProgressBar(central);
    progressBar_->setRange(0, 100);
    progressBar_->setValue(0);
    progressBar_->setTextVisible(true);
    progressBar_->setFormat(QStringLiteral("%p%"));
    layout->addWidget(progressBar_);

    logView_ = new QPlainTextEdit(central);
    logView_->setReadOnly(true);
    logView_->setPlaceholderText(QStringLiteral("Operation plan and installer output will appear here."));
    layout->addWidget(logView_, 1);

    statusLabel_ = new QLabel(QStringLiteral("GUI actions are per-user. CLI host workflows are implemented; native macOS/Windows validation and script replacement remain pending."), central);
    statusLabel_->setWordWrap(true);
    statusLabel_->setStyleSheet(QStringLiteral("color: #586477;"));
    layout->addWidget(statusLabel_);

    setCentralWidget(central);

    connect(sourceBrowse, &QPushButton::clicked, this, [this] { chooseSource(); });
    connect(prefixBrowse, &QPushButton::clicked, this, [this] { choosePrefix(); });
    connect(previewButton_, &QPushButton::clicked, this, [this] { startInstall(true); });
    connect(installButton_, &QPushButton::clicked, this, [this] { startInstall(false); });
    connect(verifyButton_, &QPushButton::clicked, this, [this] { startVerify(); });
    connect(uninstallButton_, &QPushButton::clicked, this, [this] { startUninstall(); });

    process_.setProcessChannelMode(QProcess::MergedChannels);
    connect(&process_, &QProcess::readyReadStandardOutput, this, [this] { consumeOutput(); });
    connect(&process_, &QProcess::readyReadStandardError, this, [this] { consumeOutput(); });
    connect(&process_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError) {
        appendLog(QStringLiteral("[error] %1").arg(process_.errorString()));
        setBusy(false);
    });
    connect(&process_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
            [this](int exitCode, QProcess::ExitStatus status) {
                consumeOutput();
                const bool success = status == QProcess::NormalExit && exitCode == 0;
                statusLabel_->setText(success ? QStringLiteral("Operation completed.")
                                              : QStringLiteral("Operation did not complete; see the output above."));
                phaseLabel_->setText(success ? QStringLiteral("Complete") : QStringLiteral("Stopped or failed"));
                if (!success && progressBar_->value() < 100) {
                    progressBar_->setFormat(QStringLiteral("Stopped at %p%"));
                }
                setBusy(false);
            });
}

void MainWindow::closeEvent(QCloseEvent *event) {
    if (process_.state() != QProcess::NotRunning) {
        QMessageBox::information(this, QStringLiteral("Operation in progress"),
                                 QStringLiteral("Wait for the installer operation to finish before closing this window."));
        event->ignore();
        return;
    }
    QMainWindow::closeEvent(event);
}

void MainWindow::chooseSource() {
    const QString selected = QFileDialog::getExistingDirectory(this, QStringLiteral("Select VPN Gate source checkout"), sourceEdit_->text());
    if (!selected.isEmpty()) {
        sourceEdit_->setText(selected);
    }
}

void MainWindow::choosePrefix() {
    const QString selected = QFileDialog::getExistingDirectory(this, QStringLiteral("Select per-user install location"), prefixEdit_->text());
    if (!selected.isEmpty()) {
        prefixEdit_->setText(selected);
    }
}

void MainWindow::startInstall(bool dryRun) {
    const QString source = sourceEdit_->text().trimmed();
    const QString prefix = prefixEdit_->text().trimmed();
    if (source.isEmpty() || prefix.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("Missing path"), QStringLiteral("Select a source checkout and install location first."));
        return;
    }
    if (!dryRun) {
        const auto answer = QMessageBox::question(
            this, QStringLiteral("Confirm per-user install"),
            QStringLiteral("Build the existing Rust CLI and GUI from this checkout, then install them under:\n\n%1\n\n"
                           "This migration build does not change system packages or machine-wide settings.").arg(prefix),
            QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);
        if (answer != QMessageBox::Yes) {
            return;
        }
    }
    QStringList arguments{QStringLiteral("install"), QStringLiteral("--source"), source,
                          QStringLiteral("--prefix"), prefix, QStringLiteral("--user-only")};
    if (dryRun) {
        arguments.append(QStringLiteral("--dry-run"));
    } else {
        arguments.append(QStringLiteral("--yes"));
    }
    if (forceModifiedCheck_->isChecked()) {
        arguments.append(QStringLiteral("--force"));
    }
    launchCli(arguments);
}

void MainWindow::startUninstall() {
    const QString prefix = prefixEdit_->text().trimmed();
    const QString warning = forceModifiedCheck_->isChecked()
        ? QStringLiteral("Remove the tracked VPN Gate files, including files changed since installation, and standard VPN Gate cache/config directories?\n\nUnrelated files and third-party packages are not removed.")
        : QStringLiteral("Remove tracked VPN Gate files that still match their recorded SHA-256 and the standard VPN Gate cache/config directories?\n\nModified tracked files will be kept. Unrelated files and third-party packages are not removed.");
    if (QMessageBox::warning(this, QStringLiteral("Confirm uninstall"), warning,
                             QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes) {
        return;
    }
    QStringList arguments{QStringLiteral("uninstall"), QStringLiteral("--prefix"), prefix,
                          QStringLiteral("--yes"), QStringLiteral("--user-only")};
    if (forceModifiedCheck_->isChecked()) {
        arguments.append(QStringLiteral("--force"));
    }
    launchCli(arguments);
}

void MainWindow::startVerify() {
    launchCli({QStringLiteral("verify"), QStringLiteral("--prefix"), prefixEdit_->text().trimmed(),
               QStringLiteral("--user-only")});
}

QString MainWindow::cliExecutable() const {
    const QString name = QStringLiteral("vpngate-installer%1").arg(appSuffix());
    const QString sibling = QDir(QCoreApplication::applicationDirPath()).filePath(name);
    if (QFileInfo(sibling).isExecutable()) {
        return sibling;
    }
    return QStandardPaths::findExecutable(name);
}

void MainWindow::launchCli(const QStringList &arguments) {
    if (process_.state() != QProcess::NotRunning) {
        return;
    }
    const QString cli = cliExecutable();
    if (cli.isEmpty()) {
        QMessageBox::critical(this, QStringLiteral("Installer CLI not found"),
                              QStringLiteral("The companion vpngate-installer executable must be beside this GUI."));
        return;
    }
    logView_->clear();
    pendingOutput_.clear();
    progressBar_->setValue(0);
    progressBar_->setFormat(QStringLiteral("%p%"));
    phaseLabel_->setText(QStringLiteral("Starting…"));
    statusLabel_->setText(QStringLiteral("Working in the current user's account; no administrator elevation is requested by this migration build."));
    setBusy(true);
    QStringList cliArguments = arguments;
    cliArguments.append(QStringLiteral("--machine-progress"));
    process_.setProgram(cli);
    process_.setArguments(cliArguments);
    process_.start();
}

void MainWindow::consumeOutput() {
    pendingOutput_.append(process_.readAllStandardOutput());
    pendingOutput_.append(process_.readAllStandardError());
    int newline = -1;
    while ((newline = pendingOutput_.indexOf('\n')) >= 0) {
        QByteArray raw = pendingOutput_.left(newline);
        pendingOutput_.remove(0, newline + 1);
        if (raw.endsWith('\r')) {
            raw.chop(1);
        }
        const QString line = QString::fromUtf8(raw);
        if (line.startsWith(QStringLiteral("@@PROGRESS\t"))) {
            const QStringList fields = line.split('\t');
            if (fields.size() >= 4) {
                bool completedOk = false;
                bool totalOk = false;
                const int completed = fields[1].toInt(&completedOk);
                const int total = fields[2].toInt(&totalOk);
                if (completedOk && totalOk && total > 0) {
                    progressBar_->setValue(qBound(0, completed * 100 / total, 100));
                    phaseLabel_->setText(fields.mid(3).join(QLatin1Char('\t')));
                }
            }
        } else if (!line.isEmpty()) {
            appendLog(line);
        }
    }
}

void MainWindow::appendLog(const QString &line) {
    logView_->appendPlainText(line);
    QTextCursor cursor = logView_->textCursor();
    cursor.movePosition(QTextCursor::End);
    logView_->setTextCursor(cursor);
}

void MainWindow::setBusy(bool busy) {
    previewButton_->setEnabled(!busy);
    installButton_->setEnabled(!busy);
    verifyButton_->setEnabled(!busy);
    uninstallButton_->setEnabled(!busy);
    sourceEdit_->setEnabled(!busy);
    prefixEdit_->setEnabled(!busy);
    forceModifiedCheck_->setEnabled(!busy);
}

} // namespace vpngate::installer
