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
    bool fullWorkflow = false;
    bool allowSystemPrefix = false;
    bool validateNativeArtifacts = false;
    bool skipDependencies = false;
    bool purgePackages = false;
    bool keepToolchain = false;
    bool removeToolchain = false;
    bool installOpenVPN = false;
    bool skipOpenVPN = false;
    bool restoreNatTRule = false;
    bool userOnly = false;
    QString repoSlug = QStringLiteral("warmaster726/vpngate-connect");
    QString branchName;
    QString targetHome;
    QString cacheDir;
    QString buildTargetTriple;
    QString compilePackageManager;
    QStringList compilePackagesInstalled;
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
