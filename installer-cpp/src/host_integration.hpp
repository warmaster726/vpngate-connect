#pragma once

#include "installer_core.hpp"

namespace vpngate::installer {

// Host-level work shared by the replacement installer. These operations are
// deliberately separate from the manifest-owned client-file transaction.
QString systemInstallPrefix();
QString hostTargetHome(const Options &options);
QString hostCacheDirectory(const Options &options);
bool windowsAdministratorAvailable();
bool validateSourceArchiveEntries(const QStringList &paths, const QStringList &verboseEntries,
                                  QString *error);
bool downloadSourceArchive(const Options &options, const QString &stagingRoot,
                           QString *sourceRoot, QStringList *output, QString *error);
bool prepareBuildToolchain(Options &options, const QString &stagingRoot,
                           QStringList *output, QString *cargoHome,
                           QString *rustupHome, QString *error);
Result prepareHostInstall(Options &options);
Result finishHostInstall(const Options &options);
Result finishHostUninstall(const Options &options);
Result cleanupLegacyInstall(const Options &options);

} // namespace vpngate::installer
