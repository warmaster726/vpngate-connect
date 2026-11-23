#pragma once

#include <QString>
#include <QStringList>

#include <functional>

namespace vpngate::installer {

enum class Action {
    Install,
    Uninstall,
    Verify,
};

struct Options {
    Action action = Action::Install;
    QString sourceDir;
    QString prefix;
    bool dryRun = false;
    bool noBuild = false;
    bool assumeYes = false;
    bool force = false;
    std::function<void(int completed, int total, const QString &phase)> progress;
};

struct Result {
    int exitCode = 0;
    QStringList output;
};

QString defaultPrefix();
QString defaultSourceDir();
QString hostDescription();
bool supportedHost(QString *reason = nullptr);
QString helpText();
QString manifestPathForPrefix(const QString &prefix);
Result run(const Options &options);
int runCli(const QStringList &arguments);

} // namespace vpngate::installer
