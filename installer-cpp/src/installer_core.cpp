#include "installer_core.hpp"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QSaveFile>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QTextStream>
#include <QVector>

#include <algorithm>
#include <functional>
#include <memory>
#include <set>
#include <utility>

#if defined(Q_OS_WIN)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <io.h>
#else
#include <sys/utsname.h>
#include <unistd.h>
#endif

#if defined(Q_OS_MACOS)
#include <sys/sysctl.h>
#endif

namespace vpngate::installer {
namespace {

constexpr auto kProductId = "net.vpngate.connect";
constexpr int kManifestSchema = 1;

struct PlannedFile {
    QString relativePath;
    QString sourcePath;
    QByteArray generatedContents;
    bool generated = false;
    bool executable = false;
};

struct ManifestEntry {
    QString relativePath;
    QByteArray sha256;
};

struct Manifest {
    QString prefix;
    QVector<ManifestEntry> files;
    QVector<QString> createdDirectories;
};

QString executableSuffix() {
#if defined(Q_OS_WIN)
    return QStringLiteral(".exe");
#else
    return {};
#endif
}

QString absoluteCleanPath(const QString &path) {
    return QDir::cleanPath(QFileInfo(path).absoluteFilePath());
}

bool samePath(const QString &left, const QString &right) {
#if defined(Q_OS_WIN)
    return QString::compare(QDir::cleanPath(left), QDir::cleanPath(right), Qt::CaseInsensitive) == 0;
#else
    return QDir::cleanPath(left) == QDir::cleanPath(right);
#endif
}

bool safeRelativePath(const QString &path) {
    if (path.trimmed().isEmpty() || QDir::isAbsolutePath(path)) {
        return false;
    }
    const QString normalized = QDir::cleanPath(QDir::fromNativeSeparators(path));
    if (normalized == QStringLiteral(".") || normalized == QStringLiteral("..")
        || normalized.startsWith(QStringLiteral("../"))) {
        return false;
    }
    const QStringList parts = normalized.split('/', Qt::SkipEmptyParts);
    if (parts.isEmpty()) {
        return false;
    }
    for (const QString &part : parts) {
        if (part == QStringLiteral("..") || part == QStringLiteral(".")) {
            return false;
        }
    }
    return true;
}

bool validIconSizeComponent(const QString &component) {
    if (component == QStringLiteral("scalable")) {
        return true;
    }
    const int separator = component.indexOf(QLatin1Char('x'));
    if (separator <= 0 || separator == component.size() - 1
        || component.indexOf(QLatin1Char('x'), separator + 1) >= 0) {
        return false;
    }
    bool widthOk = false;
    bool heightOk = false;
    const int width = component.left(separator).toInt(&widthOk);
    const int height = component.mid(separator + 1).toInt(&heightOk);
    return widthOk && heightOk && width > 0 && height > 0;
}

bool allowedInstallerFilePath(const QString &path) {
#if defined(Q_OS_WIN)
    static const QStringList allowed{
        QStringLiteral("vpngate.exe"), QStringLiteral("vpngate-gui.exe"),
        QStringLiteral("vpngate.ico"), QStringLiteral("vpngate-256.png"),
        QStringLiteral("share/vpngate/LICENSE"),
    };
    return allowed.contains(path);
#elif defined(Q_OS_MACOS)
    static const QStringList allowed{
        QStringLiteral("Contents/MacOS/vpngate"), QStringLiteral("Contents/MacOS/vpngate-gui"),
        QStringLiteral("Contents/Resources/vpngate.svg"), QStringLiteral("Contents/Resources/vpngate-512.png"),
        QStringLiteral("Contents/Info.plist"), QStringLiteral("Contents/PkgInfo"),
        QStringLiteral("Contents/Resources/LICENSE"),
    };
    return allowed.contains(path);
#else
    static const QStringList allowed{
        QStringLiteral("bin/vpngate"), QStringLiteral("bin/vpngate-gui"),
        QStringLiteral("share/icons/hicolor/scalable/apps/vpngate.svg"),
        QStringLiteral("share/applications/vpngate-gui.desktop"),
        QStringLiteral("share/vpngate/LICENSE"),
    };
    if (allowed.contains(path)) {
        return true;
    }
    const QString prefix = QStringLiteral("share/icons/hicolor/");
    const QString suffix = QStringLiteral("/apps/vpngate.png");
    if (!path.startsWith(prefix) || !path.endsWith(suffix)) {
        return false;
    }
    const QString size = path.mid(prefix.size(), path.size() - prefix.size() - suffix.size());
    return validIconSizeComponent(size);
#endif
}

bool allowedInstallerDirectoryPath(const QString &path) {
#if defined(Q_OS_WIN)
    static const QStringList allowed{
        QStringLiteral("share"), QStringLiteral("share/vpngate"),
    };
    return allowed.contains(path);
#elif defined(Q_OS_MACOS)
    static const QStringList allowed{
        QStringLiteral("Contents"), QStringLiteral("Contents/MacOS"), QStringLiteral("Contents/Resources"),
    };
    return allowed.contains(path);
#else
    static const QStringList allowed{
        QStringLiteral("bin"), QStringLiteral("share"), QStringLiteral("share/icons"),
        QStringLiteral("share/icons/hicolor"), QStringLiteral("share/icons/hicolor/scalable"),
        QStringLiteral("share/icons/hicolor/scalable/apps"), QStringLiteral("share/applications"),
        QStringLiteral("share/vpngate"),
    };
    if (allowed.contains(path)) {
        return true;
    }
    const QString prefix = QStringLiteral("share/icons/hicolor/");
    if (!path.startsWith(prefix)) {
        return false;
    }
    const QString suffix = path.mid(prefix.size());
    const QStringList parts = suffix.split(QLatin1Char('/'));
    return (parts.size() == 1 && validIconSizeComponent(parts[0]) && parts[0] != QStringLiteral("scalable"))
        || (parts.size() == 2 && validIconSizeComponent(parts[0]) && parts[0] != QStringLiteral("scalable")
            && parts[1] == QStringLiteral("apps"));
#endif
}

QString joinedPath(const QString &root, const QString &relative) {
    return QDir(root).filePath(QDir::fromNativeSeparators(relative));
}

bool pathHasSymlinkParent(const QString &prefix, const QString &relative);

bool isWithinPrefix(const QString &prefix, const QString &candidate) {
    const QString root = absoluteCleanPath(prefix);
    const QString path = absoluteCleanPath(candidate);
    QString childPrefix = root;
    if (!childPrefix.endsWith(QDir::separator())) {
        childPrefix.append(QDir::separator());
    }
#if defined(Q_OS_WIN)
    return path.compare(root, Qt::CaseInsensitive) == 0
        || path.startsWith(childPrefix, Qt::CaseInsensitive);
#else
    return path == root || path.startsWith(childPrefix);
#endif
}

bool ensurePrefixDirectory(const QString &prefix, QString *error) {
    const QString absolute = absoluteCleanPath(prefix);
    const QFileInfo existing(absolute);
    if (existing.exists() && existing.isSymLink()) {
        if (error) {
            *error = QStringLiteral("Refusing to use a symbolic link as the install prefix: %1").arg(absolute);
        }
        return false;
    }
    if (existing.exists() && !existing.isDir()) {
        if (error) {
            *error = QStringLiteral("Install prefix is not a directory: %1").arg(absolute);
        }
        return false;
    }
    if (!existing.exists() && !QDir().mkpath(absolute)) {
        if (error) {
            *error = QStringLiteral("Could not create install prefix: %1").arg(absolute);
        }
        return false;
    }
    const QFileInfo after(absolute);
    if (!after.isDir() || after.isSymLink()) {
        if (error) {
            *error = QStringLiteral("Install prefix changed during setup; refusing to follow it: %1").arg(absolute);
        }
        return false;
    }
    return true;
}

bool ensureSafeParentDirectories(const QString &prefix, const QString &relativePath,
                                 QStringList *created, QString *error) {
    if (!safeRelativePath(relativePath)) {
        if (error) {
            *error = QStringLiteral("Unsafe manifest/install path: %1").arg(relativePath);
        }
        return false;
    }
    const QString parentRel = QFileInfo(relativePath).path();
    if (parentRel == QStringLiteral(".")) {
        return true;
    }

    QString current = absoluteCleanPath(prefix);
    const QStringList parts = QDir::fromNativeSeparators(parentRel).split('/', Qt::SkipEmptyParts);
    QString accumulated;
    for (const QString &part : parts) {
        if (part == QStringLiteral(".") || part == QStringLiteral("..")) {
            if (error) {
                *error = QStringLiteral("Unsafe parent directory in path: %1").arg(relativePath);
            }
            return false;
        }
        if (!accumulated.isEmpty()) {
            accumulated += QLatin1Char('/');
        }
        accumulated += part;
        current = QDir(current).filePath(part);
        const QFileInfo info(current);
        if (info.exists() && info.isSymLink()) {
            if (error) {
                *error = QStringLiteral("Refusing to write through a symbolic-link directory: %1").arg(current);
            }
            return false;
        }
        if (info.exists() && !info.isDir()) {
            if (error) {
                *error = QStringLiteral("A file blocks an install directory: %1").arg(current);
            }
            return false;
        }
        if (!info.exists()) {
            if (!QDir().mkdir(current)) {
                if (error) {
                    *error = QStringLiteral("Could not create directory: %1").arg(current);
                }
                return false;
            }
            if (created && !created->contains(accumulated)) {
                created->append(accumulated);
            }
        }
        if (!isWithinPrefix(prefix, current)) {
            if (error) {
                *error = QStringLiteral("Install path escaped its prefix: %1").arg(current);
            }
            return false;
        }
    }
    return true;
}

QByteArray hashFile(const QString &path, QString *error = nullptr) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        if (error) {
            *error = QStringLiteral("Could not read %1: %2").arg(path, file.errorString());
        }
        return {};
    }
    QCryptographicHash hash(QCryptographicHash::Sha256);
    if (!hash.addData(&file)) {
        if (error) {
            *error = QStringLiteral("Could not hash %1: %2").arg(path, file.errorString());
        }
        return {};
    }
    return hash.result().toHex();
}

QFileDevice::Permissions filePermissions(bool executable) {
    auto permissions = QFileDevice::ReadOwner | QFileDevice::WriteOwner
        | QFileDevice::ReadGroup | QFileDevice::ReadOther;
    if (executable) {
        permissions |= QFileDevice::ExeOwner | QFileDevice::ExeGroup | QFileDevice::ExeOther;
    }
    return permissions;
}

bool atomicCopy(const QString &source, const QString &destination, bool executable, QString *error) {
    QFile input(source);
    if (!input.open(QIODevice::ReadOnly)) {
        if (error) {
            *error = QStringLiteral("Could not open build artifact %1: %2").arg(source, input.errorString());
        }
        return false;
    }
    QSaveFile output(destination);
    output.setDirectWriteFallback(false);
    if (!output.open(QIODevice::WriteOnly)) {
        if (error) {
            *error = QStringLiteral("Could not stage %1: %2").arg(destination, output.errorString());
        }
        return false;
    }
    while (!input.atEnd()) {
        const QByteArray chunk = input.read(64 * 1024);
        if (chunk.isEmpty() && input.error() != QFileDevice::NoError) {
            if (error) {
                *error = QStringLiteral("Could not read build artifact %1: %2").arg(source, input.errorString());
            }
            output.cancelWriting();
            return false;
        }
        if (output.write(chunk) != chunk.size()) {
            if (error) {
                *error = QStringLiteral("Could not write %1: %2").arg(destination, output.errorString());
            }
            output.cancelWriting();
            return false;
        }
    }
    if (!output.setPermissions(filePermissions(executable))) {
        if (error) {
            *error = QStringLiteral("Could not set safe file permissions on %1").arg(destination);
        }
        output.cancelWriting();
        return false;
    }
    if (!output.commit()) {
        if (error) {
            *error = QStringLiteral("Could not commit %1: %2").arg(destination, output.errorString());
        }
        return false;
    }
    return true;
}

bool atomicWrite(const QByteArray &contents, const QString &destination, bool executable, QString *error) {
    QSaveFile output(destination);
    output.setDirectWriteFallback(false);
    if (!output.open(QIODevice::WriteOnly)) {
        if (error) {
            *error = QStringLiteral("Could not create %1: %2").arg(destination, output.errorString());
        }
        return false;
    }
    if (output.write(contents) != contents.size()) {
        if (error) {
            *error = QStringLiteral("Could not write %1: %2").arg(destination, output.errorString());
        }
        output.cancelWriting();
        return false;
    }
    if (!output.setPermissions(filePermissions(executable))) {
        if (error) {
            *error = QStringLiteral("Could not set safe file permissions on %1").arg(destination);
        }
        output.cancelWriting();
        return false;
    }
    if (!output.commit()) {
        if (error) {
            *error = QStringLiteral("Could not commit %1: %2").arg(destination, output.errorString());
        }
        return false;
    }
    return true;
}

QString desktopExecValue(QString path) {
    path = QDir::fromNativeSeparators(absoluteCleanPath(path));
    path.replace(QStringLiteral("\\"), QStringLiteral("\\\\"));
    path.replace(QStringLiteral("\""), QStringLiteral("\\\""));
    return QStringLiteral("\"%1\"").arg(path);
}

QString findCargo() {
    const QString cargoName = QStringLiteral("cargo%1").arg(executableSuffix());
    const QString onPath = QStandardPaths::findExecutable(cargoName);
    if (!onPath.isEmpty()) {
        return onPath;
    }
    QString cargoHome = qEnvironmentVariable("CARGO_HOME");
    if (cargoHome.isEmpty()) {
        cargoHome = QDir::home().filePath(QStringLiteral(".cargo"));
    }
    const QString candidate = QDir(cargoHome).filePath(QStringLiteral("bin/%1").arg(cargoName));
    const QFileInfo info(candidate);
    return info.isFile() && !info.isSymLink() ? candidate : QString();
}

QString findSourceArtifact(const QString &sourceRoot, const QString &name,
                           const QString &buildTargetDir = {}) {
    const QString binaryName = name + executableSuffix();
    if (!buildTargetDir.isEmpty()) {
        return QDir(buildTargetDir).filePath(QStringLiteral("release/%1").arg(binaryName));
    }

    QStringList candidates;
    candidates.append(QDir(sourceRoot).filePath(QStringLiteral("target/release/%1").arg(binaryName)));
    if (name == QStringLiteral("vpngate-gui")) {
        candidates.append(QDir(sourceRoot).filePath(QStringLiteral("crates/vpngate-gui/target/release/%1").arg(binaryName)));
    }
    QStringList targetRoots{QDir(sourceRoot).filePath(QStringLiteral("target"))};
    if (name == QStringLiteral("vpngate-gui")) {
        targetRoots.append(QDir(sourceRoot).filePath(QStringLiteral("crates/vpngate-gui/target")));
    }
    for (const QString &targetRoot : std::as_const(targetRoots)) {
        const QDir targetDir(targetRoot);
        const QFileInfoList targetConfigurations = targetDir.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot);
        for (const QFileInfo &configuration : targetConfigurations) {
            candidates.append(QDir(configuration.filePath()).filePath(QStringLiteral("release/%1").arg(binaryName)));
        }
    }
    candidates.append(QDir(sourceRoot).filePath(binaryName));
    for (const QString &candidate : std::as_const(candidates)) {
        const QFileInfo info(candidate);
        if (info.isFile() && !info.isSymLink()) {
            return candidate;
        }
    }
    return candidates.first();
}

bool runCargoBuild(const QString &sourceRoot, const QString &cargo,
                   const QStringList &arguments, QStringList *output,
                   const std::function<void(int, int, const QString &)> &progress,
                   int progressStep, const QString &phase, QString *error) {
    QProcess process;
    process.setWorkingDirectory(sourceRoot);
    process.setProgram(cargo);
    process.setArguments(arguments);
    process.setProcessChannelMode(QProcess::MergedChannels);
    process.start();
    if (!process.waitForStarted(10'000)) {
        if (error) {
            *error = QStringLiteral("Could not start Cargo: %1").arg(process.errorString());
        }
        return false;
    }
    int polls = 0;
    while (process.state() != QProcess::NotRunning) {
        process.waitForFinished(250);
        if (progress && (++polls % 8) == 0) {
            progress(progressStep, 5, phase);
        }
        const QByteArray chunk = process.readAll();
        if (!chunk.isEmpty() && output) {
            const QString text = QString::fromLocal8Bit(chunk).trimmed();
            if (!text.isEmpty()) {
                output->append(text.split('\n'));
            }
        }
    }
    const QByteArray tail = process.readAll();
    if (!tail.isEmpty() && output) {
        const QString text = QString::fromLocal8Bit(tail).trimmed();
        if (!text.isEmpty()) {
            output->append(text.split('\n'));
        }
    }
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        if (error) {
            *error = QStringLiteral("Cargo build failed with exit code %1").arg(process.exitCode());
        }
        return false;
    }
    return true;
}

bool buildDesktop(const QString &sourceRoot, const QString &buildTargetDir,
                  QStringList *output,
                  const std::function<void(int, int, const QString &)> &progress,
                  QString *error) {
    const QString cargo = findCargo();
    if (cargo.isEmpty()) {
        if (error) {
            *error = QStringLiteral("Cargo was not found. This migration build does not bootstrap Rust yet; install the stable Rust toolchain or use the existing platform installer.");
        }
        return false;
    }
    output->append(QStringLiteral("Building the existing Rust CLI service and native GUI with Cargo in temporary storage."));
    if (progress) {
        progress(1, 5, QStringLiteral("Building the CLI with Cargo"));
    }
    if (!runCargoBuild(sourceRoot, cargo,
                       {QStringLiteral("build"), QStringLiteral("--locked"), QStringLiteral("--release"),
                        QStringLiteral("-p"), QStringLiteral("vpngate-cli"),
                        QStringLiteral("--target-dir"), buildTargetDir},
                       output, progress, 1, QStringLiteral("Building the CLI with Cargo"), error)) {
        return false;
    }
    if (progress) {
        progress(2, 5, QStringLiteral("CLI build complete; preparing the GUI build"));
        progress(3, 5, QStringLiteral("Building the GUI with Cargo"));
    }
    if (!runCargoBuild(sourceRoot, cargo,
                       {QStringLiteral("build"), QStringLiteral("--locked"), QStringLiteral("--release"),
                        QStringLiteral("--manifest-path"), QStringLiteral("crates/vpngate-gui/Cargo.toml"),
                        QStringLiteral("--bin"), QStringLiteral("vpngate-gui"),
                        QStringLiteral("--target-dir"), buildTargetDir},
                       output, progress, 3, QStringLiteral("Building the GUI with Cargo"), error)) {
        return false;
    }
    if (progress) {
        progress(4, 5, QStringLiteral("Client binaries built; preparing install transaction"));
    }
    return true;
}

QString desktopEntryContents(const QString &prefix) {
    const QString gui = joinedPath(prefix, QStringLiteral("bin/vpngate-gui"));
    const QString icon = joinedPath(prefix, QStringLiteral("share/icons/hicolor/scalable/apps/vpngate.svg"));
    return QStringLiteral(
        "[Desktop Entry]\n"
        "Version=1.0\n"
        "Type=Application\n"
        "Name=VPN Gate Connect\n"
        "GenericName=VPN Client\n"
        "Comment=Native graphical VPN Gate client\n"
        "Exec=%1\n"
        "Icon=%2\n"
        "Terminal=false\n"
        "Categories=Network;Security;\n"
        "Keywords=vpn;vpngate;l2tp;ipsec;openvpn;gui;\n"
        "StartupNotify=true\n")
        .arg(desktopExecValue(gui), QDir::fromNativeSeparators(icon));
}

[[maybe_unused]] QByteArray macInfoPlist() {
    return QByteArrayLiteral(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\"><dict>\n"
        "<key>CFBundleExecutable</key><string>vpngate-gui</string>\n"
        "<key>CFBundleIdentifier</key><string>net.vpngate.connect</string>\n"
        "<key>CFBundleName</key><string>VPN Gate Connect</string>\n"
        "<key>CFBundlePackageType</key><string>APPL</string>\n"
        "<key>CFBundleVersion</key><string>0.1.0</string>\n"
        "<key>LSMinimumSystemVersion</key><string>11.0</string>\n"
        "</dict></plist>\n");
}

bool addCopy(QVector<PlannedFile> *files, const QString &source, const QString &relative,
             bool executable, QString *error, bool allowMissing = false) {
    const QFileInfo info(source);
    if (info.isSymLink() || (info.exists() && !info.isFile()) || (!allowMissing && !info.isFile())) {
        if (error) {
            *error = QStringLiteral("Required installer input is missing or unsafe: %1").arg(source);
        }
        return false;
    }
    files->append({relative, source, {}, false, executable});
    return true;
}

bool createPlan(const QString &sourceRoot, const QString &prefix,
                QVector<PlannedFile> *files, QString *error,
                const QString &buildTargetDir = {}, bool allowMissingArtifacts = false) {
    const QString cli = findSourceArtifact(sourceRoot, QStringLiteral("vpngate"), buildTargetDir);
    const QString gui = findSourceArtifact(sourceRoot, QStringLiteral("vpngate-gui"), buildTargetDir);
    const QString exe = executableSuffix();

#if defined(Q_OS_WIN)
    if (!addCopy(files, cli, QStringLiteral("vpngate.exe"), true, error, allowMissingArtifacts)
        || !addCopy(files, gui, QStringLiteral("vpngate-gui.exe"), true, error, allowMissingArtifacts)
        || !addCopy(files, QDir(sourceRoot).filePath(QStringLiteral("assets/vpngate.ico")),
                    QStringLiteral("vpngate.ico"), false, error)
        || !addCopy(files, QDir(sourceRoot).filePath(QStringLiteral("assets/vpngate-256.png")),
                    QStringLiteral("vpngate-256.png"), false, error)) {
        return false;
    }
#elif defined(Q_OS_MACOS)
    if (!addCopy(files, cli, QStringLiteral("Contents/MacOS/vpngate"), true, error, allowMissingArtifacts)
        || !addCopy(files, gui, QStringLiteral("Contents/MacOS/vpngate-gui"), true, error, allowMissingArtifacts)
        || !addCopy(files, QDir(sourceRoot).filePath(QStringLiteral("assets/vpngate.svg")),
                    QStringLiteral("Contents/Resources/vpngate.svg"), false, error)
        || !addCopy(files, QDir(sourceRoot).filePath(QStringLiteral("assets/vpngate-512.png")),
                    QStringLiteral("Contents/Resources/vpngate-512.png"), false, error)) {
        return false;
    }
    files->append({QStringLiteral("Contents/Info.plist"), {}, macInfoPlist(), true, false});
    files->append({QStringLiteral("Contents/PkgInfo"), {}, QByteArrayLiteral("APPL????"), true, false});
#else
    if (!addCopy(files, cli, QStringLiteral("bin/vpngate%1").arg(exe), true, error, allowMissingArtifacts)
        || !addCopy(files, gui, QStringLiteral("bin/vpngate-gui%1").arg(exe), true, error, allowMissingArtifacts)
        || !addCopy(files, QDir(sourceRoot).filePath(QStringLiteral("assets/vpngate.svg")),
                    QStringLiteral("share/icons/hicolor/scalable/apps/vpngate.svg"), false, error)) {
        return false;
    }

    const QString iconRoot = QDir(sourceRoot).filePath(QStringLiteral("assets/icons/hicolor"));
    const QFileInfo iconRootInfo(iconRoot);
    if (!iconRootInfo.isDir() || iconRootInfo.isSymLink()) {
        if (error) {
            *error = QStringLiteral("Required Linux icon directory is missing or unsafe: %1").arg(iconRoot);
        }
        return false;
    }
    QDirIterator iterator(iconRoot, QDir::Files | QDir::NoDotAndDotDot, QDirIterator::Subdirectories);
    while (iterator.hasNext()) {
        const QString sourceFile = iterator.next();
        const QFileInfo info(sourceFile);
        if (info.isSymLink()) {
            if (error) {
                *error = QStringLiteral("Refusing to package a symbolic-link icon: %1").arg(sourceFile);
            }
            return false;
        }
        const QString relativeFromIcons = QDir(iconRoot).relativeFilePath(sourceFile);
        const QString target = QStringLiteral("share/icons/hicolor/%1").arg(relativeFromIcons);
        if (!addCopy(files, sourceFile, target, false, error)) {
            return false;
        }
    }
    files->append({QStringLiteral("share/applications/vpngate-gui.desktop"), {},
                   desktopEntryContents(prefix).toUtf8(), true, false});
#endif

    const QString license = QDir(sourceRoot).filePath(QStringLiteral("LICENSE"));
    if (QFileInfo(license).isFile() && !QFileInfo(license).isSymLink()) {
#if defined(Q_OS_MACOS)
        files->append({QStringLiteral("Contents/Resources/LICENSE"), license, {}, false, false});
#else
        files->append({QStringLiteral("share/vpngate/LICENSE"), license, {}, false, false});
#endif
    }
    return true;
}

bool stageFile(const PlannedFile &item, const QString &destination, QString *error) {
    if (item.generated) {
        return atomicWrite(item.generatedContents, destination, item.executable, error);
    }
    return atomicCopy(item.sourcePath, destination, item.executable, error);
}

bool readManifest(const QString &prefix, Manifest *manifest, QString *error) {
    const QString path = manifestPathForPrefix(prefix);
    const QFileInfo prefixInfo(absoluteCleanPath(prefix));
    if (!prefixInfo.exists() || !prefixInfo.isDir() || prefixInfo.isSymLink()) {
        if (error) {
            *error = QStringLiteral("Install prefix is missing, not a directory, or a symbolic link: %1").arg(prefix);
        }
        return false;
    }
    const QString manifestRelative = QDir(prefix).relativeFilePath(path);
    if (!safeRelativePath(manifestRelative) || pathHasSymlinkParent(prefix, manifestRelative)) {
        if (error) {
            *error = QStringLiteral("Refusing to read the installer manifest through an unsafe path: %1").arg(path);
        }
        return false;
    }
    const QFileInfo info(path);
    if (!info.exists() && !info.isSymLink()) {
        if (error) {
            *error = QStringLiteral("No VPN Gate C++ installer manifest exists under %1").arg(prefix);
        }
        return false;
    }
    if (!info.isFile() || info.isSymLink()) {
        if (error) {
            *error = QStringLiteral("Refusing to read a non-regular or symbolic-link manifest: %1").arg(path);
        }
        return false;
    }
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        if (error) {
            *error = QStringLiteral("Could not read install manifest: %1").arg(file.errorString());
        }
        return false;
    }
    QJsonParseError parseError{};
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        if (error) {
            *error = QStringLiteral("Install manifest is invalid JSON: %1").arg(parseError.errorString());
        }
        return false;
    }
    const QJsonObject object = document.object();
    if (object.value(QStringLiteral("schema")).toInt(-1) != kManifestSchema
        || object.value(QStringLiteral("product")).toString() != QString::fromLatin1(kProductId)
        || !samePath(object.value(QStringLiteral("prefix")).toString(), absoluteCleanPath(prefix))) {
        if (error) {
            *error = QStringLiteral("Install manifest has an unsupported schema, product ID, or prefix.");
        }
        return false;
    }

    Manifest parsed;
    parsed.prefix = absoluteCleanPath(prefix);
    const QJsonValue filesValue = object.value(QStringLiteral("files"));
    if (!filesValue.isArray()) {
        if (error) {
            *error = QStringLiteral("Install manifest file inventory is missing.");
        }
        return false;
    }
    std::set<QString> seen;
    for (const QJsonValue &value : filesValue.toArray()) {
        if (!value.isObject()) {
            if (error) {
                *error = QStringLiteral("Install manifest contains an invalid file entry.");
            }
            return false;
        }
        const QJsonObject entry = value.toObject();
        const QString relative = entry.value(QStringLiteral("path")).toString();
        const QByteArray digest = entry.value(QStringLiteral("sha256")).toString().toLatin1();
        const QString canonicalRelative = QDir::cleanPath(QDir::fromNativeSeparators(relative));
        const bool validDigest = digest.size() == 64 && std::all_of(digest.cbegin(), digest.cend(), [](char ch) {
            return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
        });
        if (!safeRelativePath(relative) || canonicalRelative != QDir::fromNativeSeparators(relative)
            || !allowedInstallerFilePath(canonicalRelative) || !validDigest) {
            if (error) {
                *error = QStringLiteral("Install manifest contains an unsafe path or invalid SHA-256: %1").arg(relative);
            }
            return false;
        }
        if (seen.contains(canonicalRelative)) {
            if (error) {
                *error = QStringLiteral("Install manifest contains a duplicate path: %1").arg(relative);
            }
            return false;
        }
        seen.insert(canonicalRelative);
        parsed.files.append({canonicalRelative, digest.toLower()});
    }
    const QJsonValue directoriesValue = object.value(QStringLiteral("createdDirectories"));
    if (!directoriesValue.isArray()) {
        if (error) {
            *error = QStringLiteral("Install manifest created-directory inventory is missing.");
        }
        return false;
    }
    std::set<QString> seenDirectories;
    for (const QJsonValue &value : directoriesValue.toArray()) {
        const QString relative = value.toString();
        const QString canonicalRelative = QDir::cleanPath(QDir::fromNativeSeparators(relative));
        if (!safeRelativePath(relative) || canonicalRelative != QDir::fromNativeSeparators(relative)
            || !allowedInstallerDirectoryPath(canonicalRelative) || seenDirectories.contains(canonicalRelative)) {
            if (error) {
                *error = QStringLiteral("Install manifest contains an unsafe or duplicate directory: %1").arg(relative);
            }
            return false;
        }
        seenDirectories.insert(canonicalRelative);
        parsed.createdDirectories.append(canonicalRelative);
    }
    *manifest = std::move(parsed);
    return true;
}

bool writeManifest(const QString &prefix, const QVector<ManifestEntry> &entries,
                   QStringList *createdDirectories, QString *error) {
    const QString path = manifestPathForPrefix(prefix);
    const QFileInfo existingManifest(path);
    if (existingManifest.isSymLink() || (existingManifest.exists() && !existingManifest.isFile())) {
        if (error) {
            *error = QStringLiteral("Refusing to replace a non-regular or symbolic-link manifest: %1").arg(path);
        }
        return false;
    }
    if (!createdDirectories
        || !ensureSafeParentDirectories(prefix, QDir(prefix).relativeFilePath(path), createdDirectories, error)) {
        return false;
    }
    QJsonArray files;
    for (const ManifestEntry &entry : entries) {
        files.append(QJsonObject{
            {QStringLiteral("path"), entry.relativePath},
            {QStringLiteral("sha256"), QString::fromLatin1(entry.sha256)},
        });
    }
    QJsonArray directories;
    QStringList uniqueDirectories = *createdDirectories;
    uniqueDirectories.removeDuplicates();
    *createdDirectories = uniqueDirectories;
    for (const QString &directory : std::as_const(uniqueDirectories)) {
        directories.append(directory);
    }
    const QJsonObject object{
        {QStringLiteral("schema"), kManifestSchema},
        {QStringLiteral("product"), QString::fromLatin1(kProductId)},
        {QStringLiteral("prefix"), absoluteCleanPath(prefix)},
        {QStringLiteral("files"), files},
        {QStringLiteral("createdDirectories"), directories},
    };
    return atomicWrite(QJsonDocument(object).toJson(QJsonDocument::Indented), path, false, error);
}

const ManifestEntry *findEntry(const QVector<ManifestEntry> &entries, const QString &relative) {
    for (const ManifestEntry &entry : entries) {
        if (entry.relativePath == relative) {
            return &entry;
        }
    }
    return nullptr;
}

bool pathHasSymlinkParent(const QString &prefix, const QString &relative) {
    QString current = absoluteCleanPath(prefix);
    if (QFileInfo(current).isSymLink()) {
        return true;
    }
    const QString parent = QFileInfo(relative).path();
    if (parent == QStringLiteral(".")) {
        return QFileInfo(current).isSymLink();
    }
    for (const QString &part : QDir::fromNativeSeparators(parent).split('/', Qt::SkipEmptyParts)) {
        if (part == QStringLiteral(".") || part == QStringLiteral("..")) {
            return true;
        }
        current = QDir(current).filePath(part);
        const QFileInfo info(current);
        if (info.isSymLink()) {
            return true;
        }
        if (!info.exists()) {
            return false;
        }
        if (!info.isDir()) {
            return true;
        }
    }
    return false;
}

void removeEmptyCreatedDirectories(const QString &prefix, const QStringList &directories,
                                   QStringList *output) {
    QStringList ordered = directories;
    std::sort(ordered.begin(), ordered.end(), [](const QString &a, const QString &b) {
        return a.count('/') > b.count('/');
    });
    ordered.removeDuplicates();
    for (const QString &relative : ordered) {
        if (!safeRelativePath(relative)) {
            continue;
        }
        const QString path = joinedPath(prefix, relative);
        const QFileInfo info(path);
        if (!info.exists() || !info.isDir() || info.isSymLink() || !isWithinPrefix(prefix, path)) {
            continue;
        }
        if (QDir().rmdir(path)) {
            if (output) {
                output->append(QStringLiteral("[ok] Removed empty install directory: %1").arg(path));
            }
        } else if (output) {
            const QDir directory(path);
            output->append(directory.isEmpty()
                               ? QStringLiteral("[warning] Could not remove empty install directory: %1").arg(path)
                               : QStringLiteral("[preserved] Install directory contains unrelated data: %1").arg(path));
        }
    }
}

QVector<QString> defaultAppStateDirectories() {
    QVector<QString> paths;
#if defined(Q_OS_WIN)
    QString localAppData = qEnvironmentVariable("LOCALAPPDATA");
    if (localAppData.isEmpty() || !QDir::isAbsolutePath(localAppData) || QDir(localAppData).isRoot()) {
        localAppData = QDir::home().filePath(QStringLiteral("AppData/Local"));
    }
    paths.append(QDir(localAppData).filePath(QStringLiteral("vpngate")));
#elif defined(Q_OS_MACOS)
    QString home = qEnvironmentVariable("HOME");
    if (home.isEmpty() || !QDir::isAbsolutePath(home) || QDir(home).isRoot()) {
        home = QDir::homePath();
    }
    paths.append(QDir(home).filePath(QStringLiteral("Library/Caches/vpngate")));
    paths.append(QDir(home).filePath(QStringLiteral(".config/vpngate")));
#else
    QString cacheHome = qEnvironmentVariable("XDG_CACHE_HOME");
    if (cacheHome.isEmpty() || !QDir::isAbsolutePath(cacheHome) || QDir(cacheHome).isRoot()) {
        cacheHome = QDir::home().filePath(QStringLiteral(".cache"));
    }
    QString configHome = qEnvironmentVariable("XDG_CONFIG_HOME");
    if (configHome.isEmpty() || !QDir::isAbsolutePath(configHome) || QDir(configHome).isRoot()) {
        configHome = QDir::home().filePath(QStringLiteral(".config"));
    }
    paths.append(QDir(cacheHome).filePath(QStringLiteral("vpngate")));
    paths.append(QDir(configHome).filePath(QStringLiteral("vpngate")));
#endif
    return paths;
}

bool removeKnownAppStateDirectory(const QString &path, QString *error) {
    const QFileInfo info(path);
    if (!info.exists() && !info.isSymLink()) {
        return true;
    }
    if (info.isSymLink()) {
        if (error) {
            *error = QStringLiteral("Refusing to remove a VPN Gate state-directory symlink or follow its target: %1").arg(path);
        }
        return false;
    }
    if (!info.isDir()) {
        if (error) {
            *error = QStringLiteral("Expected VPN Gate state directory but found a non-directory: %1").arg(path);
        }
        return false;
    }
    if (!QDir(path).removeRecursively()) {
        if (error) {
            *error = QStringLiteral("Could not remove VPN Gate state directory %1").arg(path);
        }
        return false;
    }
    return true;
}

bool confirmOperation(const Options &options, QStringList *output) {
    if (options.assumeYes) {
        return true;
    }
    output->append(QStringLiteral("No changes made. Review the plan and rerun with --yes to proceed."));
    return false;
}

bool validateSourceRoot(const QString &sourceRoot, QString *error) {
    const QStringList required{
        QStringLiteral("Cargo.toml"),
        QStringLiteral("crates/vpngate-gui/Cargo.toml"),
        QStringLiteral("assets/vpngate.svg"),
    };
    for (const QString &relative : required) {
        const QFileInfo info(QDir(sourceRoot).filePath(relative));
        if (!info.isFile() || info.isSymLink()) {
            if (error) {
                *error = QStringLiteral("Source directory does not look like a VPN Gate checkout (missing %1)").arg(relative);
            }
            return false;
        }
    }
    return true;
}

QString normalizePrefixOrDefault(const QString &prefix) {
    return absoluteCleanPath(prefix.isEmpty() ? defaultPrefix() : prefix);
}

bool validatePerUserPrefix(const QString &prefix, QString *error) {
    const QString normalized = absoluteCleanPath(prefix);
    if (QDir(normalized).isRoot()) {
        if (error) {
            *error = QStringLiteral("The install prefix must be a per-user directory, not a filesystem root.");
        }
        return false;
    }
    QStringList systemRoots;
#if defined(Q_OS_WIN)
    systemRoots = {
        qEnvironmentVariable("WINDIR"),
        qEnvironmentVariable("SYSTEMROOT"),
        qEnvironmentVariable("PROGRAMFILES"),
        qEnvironmentVariable("PROGRAMFILES(X86)"),
        qEnvironmentVariable("PROGRAMW6432"),
        qEnvironmentVariable("PROGRAMDATA"),
    };
#else
    systemRoots = {
        QStringLiteral("/usr"), QStringLiteral("/bin"), QStringLiteral("/sbin"),
        QStringLiteral("/lib"), QStringLiteral("/lib64"), QStringLiteral("/etc"),
        QStringLiteral("/opt"), QStringLiteral("/var"),
    };
#if defined(Q_OS_MACOS)
    systemRoots.append({QStringLiteral("/Applications"), QStringLiteral("/Library"),
                        QStringLiteral("/System"), QStringLiteral("/private/var")});
#endif
#endif
    for (const QString &root : std::as_const(systemRoots)) {
        if (!root.isEmpty() && isWithinPrefix(root, normalized)) {
            if (error) {
                *error = QStringLiteral("This migration build is per-user only and refuses system-wide install prefixes: %1")
                             .arg(normalized);
            }
            return false;
        }
    }
    return true;
}

Result verifyInstall(const QString &prefix, const Options &options) {
    Result result;
    Manifest manifest;
    QString error;
    if (!readManifest(prefix, &manifest, &error)) {
        result.exitCode = 1;
        result.output.append(QStringLiteral("[error] %1").arg(error));
        return result;
    }
    int issues = 0;
    result.output.append(QStringLiteral("Checking %1 installer-owned file(s) under %2")
                             .arg(manifest.files.size()).arg(manifest.prefix));
    const int progressTotal = qMax(1, manifest.files.size());
    for (int index = 0; index < manifest.files.size(); ++index) {
        const ManifestEntry &entry = manifest.files[index];
        if (options.progress) {
            options.progress(index + 1, progressTotal,
                             QStringLiteral("Verifying %1").arg(entry.relativePath));
        }
        const QString path = joinedPath(prefix, entry.relativePath);
        const QFileInfo info(path);
        if (!isWithinPrefix(prefix, path) || !safeRelativePath(entry.relativePath) || pathHasSymlinkParent(prefix, entry.relativePath)) {
            ++issues;
            result.output.append(QStringLiteral("[error] Unsafe path in install inventory: %1").arg(entry.relativePath));
            continue;
        }
        if (!info.exists() || info.isSymLink() || !info.isFile()) {
            ++issues;
            result.output.append(QStringLiteral("[error] Missing or non-regular file: %1").arg(path));
            continue;
        }
        const QByteArray actual = hashFile(path, &error);
        if (actual.isEmpty() || actual != entry.sha256) {
            ++issues;
            result.output.append(QStringLiteral("[error] File was changed after installation: %1").arg(path));
        }
    }
    if (options.progress) {
        options.progress(progressTotal, progressTotal, QStringLiteral("Verification complete"));
    }
    if (issues == 0) {
        result.output.append(QStringLiteral("[ok] Every installer-owned file is present and matches its recorded SHA-256."));
    } else {
        result.exitCode = 1;
        result.output.append(QStringLiteral("[error] Verification found %1 issue(s).").arg(issues));
    }
    return result;
}

Result uninstall(const QString &prefix, const Options &options) {
    Result result;
    Manifest manifest;
    QString error;
    if (!readManifest(prefix, &manifest, &error)) {
        result.exitCode = 1;
        result.output.append(QStringLiteral("[error] %1").arg(error));
        return result;
    }

    result.output.append(QStringLiteral("Uninstall plan: remove only files recorded by the C++ installer manifest."));
    result.output.append(QStringLiteral("Install prefix: %1").arg(manifest.prefix));
    for (const ManifestEntry &entry : manifest.files) {
        result.output.append(QStringLiteral("  - %1").arg(joinedPath(prefix, entry.relativePath)));
    }
    const QVector<QString> stateDirectories = defaultAppStateDirectories();
    for (const QString &directory : stateDirectories) {
        result.output.append(QStringLiteral("  - app-owned state (if present): %1").arg(directory));
    }
    result.output.append(QStringLiteral("Third-party packages and unrelated files are not removed."));
    result.output.append(QStringLiteral("Custom VPNGATE_CACHE_DIR / --cache-dir locations are not discoverable and will be left alone."));
    if (options.dryRun) {
        result.output.append(QStringLiteral("[dry-run] No files or system settings were changed."));
        if (options.progress) {
            const int total = manifest.files.size() + stateDirectories.size() + 1;
            options.progress(total, total, QStringLiteral("Uninstall preview complete"));
        }
        return result;
    }
    if (!confirmOperation(options, &result.output)) {
        result.exitCode = 2;
        return result;
    }

    QStringList leftovers;
    const int progressTotal = manifest.files.size() + stateDirectories.size() + 1;
    for (int index = 0; index < manifest.files.size(); ++index) {
        const ManifestEntry &entry = manifest.files[index];
        if (options.progress) {
            options.progress(index + 1, progressTotal,
                             QStringLiteral("Removing tracked file %1").arg(entry.relativePath));
        }
        if (!safeRelativePath(entry.relativePath)) {
            leftovers.append(entry.relativePath);
            result.output.append(QStringLiteral("[error] Refusing unsafe manifest path: %1").arg(entry.relativePath));
            continue;
        }
        const QString path = joinedPath(prefix, entry.relativePath);
        if (!isWithinPrefix(prefix, path) || pathHasSymlinkParent(prefix, entry.relativePath)) {
            leftovers.append(entry.relativePath);
            result.output.append(QStringLiteral("[error] Refusing to follow an unsafe path: %1").arg(path));
            continue;
        }
        const QFileInfo info(path);
        if (!info.exists() && !info.isSymLink()) {
            result.output.append(QStringLiteral("[ok] Already absent: %1").arg(path));
            continue;
        }
        if (info.isSymLink() && !options.force) {
            leftovers.append(entry.relativePath);
            result.output.append(QStringLiteral("[preserved] Replaced by a symbolic link; use --force to remove the link itself: %1").arg(path));
            continue;
        }
        if (!info.isSymLink() && !info.isFile()) {
            leftovers.append(entry.relativePath);
            result.output.append(QStringLiteral("[preserved] Not a regular file: %1").arg(path));
            continue;
        }
        if (!info.isSymLink()) {
            const QByteArray actual = hashFile(path, &error);
            if (actual.isEmpty()) {
                leftovers.append(entry.relativePath);
                result.output.append(QStringLiteral("[error] %1").arg(error));
                continue;
            }
            if (actual != entry.sha256 && !options.force) {
                leftovers.append(entry.relativePath);
                result.output.append(QStringLiteral("[preserved] Modified after installation; use --force to remove: %1").arg(path));
                continue;
            }
        }
        if (!QFile::remove(path)) {
            leftovers.append(entry.relativePath);
            result.output.append(QStringLiteral("[error] Could not remove %1").arg(path));
            continue;
        }
        result.output.append(QStringLiteral("[ok] Removed %1").arg(path));
    }

    if (leftovers.isEmpty()) {
        for (const ManifestEntry &entry : manifest.files) {
            const QString path = joinedPath(prefix, entry.relativePath);
            const QFileInfo info(path);
            if (info.exists() || info.isSymLink()) {
                leftovers.append(entry.relativePath);
                result.output.append(QStringLiteral("[error] Verification after removal found a tracked file still present: %1").arg(path));
            }
        }
    }

    bool stateCleanupFailed = false;
    if (leftovers.isEmpty()) {
        for (int i = 0; i < stateDirectories.size(); ++i) {
            const QString &directory = stateDirectories[i];
            const QFileInfo before(directory);
            const bool wasPresent = before.exists() || before.isSymLink();
            QString stateError;
            if (!removeKnownAppStateDirectory(directory, &stateError)) {
                stateCleanupFailed = true;
                result.output.append(QStringLiteral("[error] %1").arg(stateError));
            } else if (QFileInfo(directory).exists() || QFileInfo(directory).isSymLink()) {
                stateCleanupFailed = true;
                result.output.append(QStringLiteral("[error] VPN Gate app state remains after cleanup: %1").arg(directory));
            } else if (wasPresent) {
                result.output.append(QStringLiteral("[ok] Removed app state: %1").arg(directory));
            }
            if (options.progress) {
                options.progress(manifest.files.size() + i + 1,
                                 manifest.files.size() + stateDirectories.size() + 1,
                                 QStringLiteral("Cleaning app state: %1").arg(directory));
            }
        }
    }

    const QString manifestPath = manifestPathForPrefix(prefix);
    if (leftovers.isEmpty() && !stateCleanupFailed) {
        if (QFileInfo(manifestPath).isSymLink() || !QFile::remove(manifestPath)
            || QFileInfo(manifestPath).exists() || QFileInfo(manifestPath).isSymLink()) {
            stateCleanupFailed = true;
            result.output.append(QStringLiteral("[error] Could not verify removal of installer manifest: %1").arg(manifestPath));
        }
    }

    if (!leftovers.isEmpty() || stateCleanupFailed) {
        // Retain a smaller inventory for a safe retry; state cleanup is retried from the
        // standard product-specific locations whenever an empty inventory is uninstalled.
        QVector<ManifestEntry> remaining;
        for (const ManifestEntry &entry : manifest.files) {
            const QString path = joinedPath(prefix, entry.relativePath);
            if (leftovers.contains(entry.relativePath) || QFileInfo(path).exists() || QFileInfo(path).isSymLink()) {
                remaining.append(entry);
            }
        }
        QStringList remainingDirectories = manifest.createdDirectories;
        if (!writeManifest(prefix, remaining, &remainingDirectories, &error)) {
            result.output.append(QStringLiteral("[error] Could not update the remaining-file inventory: %1").arg(error));
        }
        result.exitCode = 1;
        result.output.append(QStringLiteral("[error] Uninstall incomplete; tracked files or app state remain. The installer inventory is retained for retry where possible."));
    } else {
        removeEmptyCreatedDirectories(prefix, manifest.createdDirectories, &result.output);
#if defined(Q_OS_WIN) || defined(Q_OS_MACOS)
        const QFileInfo rootInfo(prefix);
        if (rootInfo.exists() && rootInfo.isDir() && !rootInfo.isSymLink()) {
            QDir().rmdir(prefix); // only removes a product-specific root if it is empty
        }
#endif
        if (options.progress) {
            options.progress(manifest.files.size() + stateDirectories.size() + 1,
                             manifest.files.size() + stateDirectories.size() + 1,
                             QStringLiteral("Uninstall complete"));
        }
        result.output.append(QStringLiteral("[ok] Uninstall complete; all tracked client files and standard app state were removed."));
    }
    return result;
}

bool createPlan(const QString &sourceRoot, const QString &prefix,
                QVector<PlannedFile> *files, QString *error,
                const QString &buildTargetDir, bool allowMissingArtifacts);

} // namespace

QString defaultPrefix() {
#if defined(Q_OS_WIN)
    QString localAppData = qEnvironmentVariable("LOCALAPPDATA");
    if (localAppData.isEmpty() || !QDir::isAbsolutePath(localAppData)) {
        localAppData = QDir::home().filePath(QStringLiteral("AppData/Local"));
    }
    return QDir(localAppData).filePath(QStringLiteral("Programs/VPNGate"));
#elif defined(Q_OS_MACOS)
    return QDir::home().filePath(QStringLiteral("Applications/VPN Gate Connect.app"));
#else
    return QDir::home().filePath(QStringLiteral(".local"));
#endif
}

QString defaultSourceDir() {
    QStringList candidates;
    candidates.append(QDir::currentPath());
    candidates.append(QCoreApplication::applicationDirPath());
    for (const QString &candidate : std::as_const(candidates)) {
        QDir directory(candidate);
        for (int level = 0; level < 8; ++level) {
            if (QFileInfo(directory.filePath(QStringLiteral("Cargo.toml"))).isFile()
                && QFileInfo(directory.filePath(QStringLiteral("crates/vpngate-gui/Cargo.toml"))).isFile()) {
                return directory.absolutePath();
            }
            if (!directory.cdUp()) {
                break;
            }
        }
    }
    return QDir::currentPath();
}

QString hostDescription() {
#if defined(Q_OS_WIN)
    SYSTEM_INFO info{};
    GetNativeSystemInfo(&info);
    const QString native = info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64
        ? QStringLiteral("ARM64")
        : info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64
            ? QStringLiteral("x86_64") : QStringLiteral("unsupported architecture");
    return QStringLiteral("Windows · native %1 · process %2")
        .arg(native, QSysInfo::currentCpuArchitecture());
#elif defined(Q_OS_MACOS)
    struct utsname info{};
    const QString machine = uname(&info) == 0 ? QString::fromLocal8Bit(info.machine) : QSysInfo::currentCpuArchitecture();
    return QStringLiteral("macOS · native %1").arg(machine);
#elif defined(Q_OS_LINUX)
    struct utsname info{};
    const QString machine = uname(&info) == 0 ? QString::fromLocal8Bit(info.machine) : QSysInfo::currentCpuArchitecture();
    return QStringLiteral("Linux · native %1").arg(machine);
#else
    return QStringLiteral("Unsupported operating system");
#endif
}

bool supportedHost(QString *reason) {
    QString why;
#if defined(Q_OS_WIN)
    SYSTEM_INFO info{};
    GetNativeSystemInfo(&info);
    const QString process = QSysInfo::currentCpuArchitecture().toLower();
    if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
        if (process != QStringLiteral("x86_64") && process != QStringLiteral("amd64")) {
            why = QStringLiteral("The Windows installer must run as a native x86_64 process; 32-bit binaries are unsupported.");
        }
    } else if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
        if (process != QStringLiteral("arm64") && process != QStringLiteral("aarch64")) {
            why = QStringLiteral("Windows-on-ARM requires a native ARM64 installer; x64 emulation is not supported.");
        }
    } else {
        why = QStringLiteral("Only native x86_64 and ARM64 Windows hosts are supported.");
    }
#elif defined(Q_OS_MACOS)
    int translated = 0;
    size_t size = sizeof(translated);
    if (sysctlbyname("sysctl.proc_translated", &translated, &size, nullptr, 0) == 0 && translated == 1) {
        why = QStringLiteral("Rosetta execution is not supported. Start the native Apple Silicon installer.");
    } else {
        struct utsname info{};
        const QString machine = uname(&info) == 0 ? QString::fromLocal8Bit(info.machine).toLower()
                                                  : QSysInfo::currentCpuArchitecture().toLower();
        if (machine != QStringLiteral("arm64") && machine != QStringLiteral("aarch64")
            && machine != QStringLiteral("x86_64") && machine != QStringLiteral("amd64")) {
            why = QStringLiteral("Only native 64-bit Intel or Apple Silicon macOS hosts are supported.");
        }
    }
#elif defined(Q_OS_LINUX)
    struct utsname info{};
    const QString machine = uname(&info) == 0 ? QString::fromLocal8Bit(info.machine).toLower()
                                              : QSysInfo::currentCpuArchitecture().toLower();
    if (machine != QStringLiteral("x86_64") && machine != QStringLiteral("amd64")
        && machine != QStringLiteral("aarch64") && machine != QStringLiteral("arm64")) {
        why = QStringLiteral("Only native 64-bit x86_64 and ARM64 Linux hosts are supported.");
    }
#else
    why = QStringLiteral("This installer supports native Linux, Windows, and macOS only.");
#endif
    if (reason) {
        *reason = why;
    }
    return why.isEmpty();
}

QString manifestPathForPrefix(const QString &prefix) {
#if defined(Q_OS_MACOS)
    return QDir(prefix).filePath(QStringLiteral("Contents/Resources/vpngate-installer-manifest.json"));
#else
    return QDir(prefix).filePath(QStringLiteral("share/vpngate/installer-manifest.json"));
#endif
}

QString helpText() {
    return QStringLiteral(
        "VPN Gate Connect C++ installer (migration prototype)\n\n"
        "Usage:\n"
        "  vpngate-installer install   --source <checkout> [--prefix <dir>] [--dry-run] [--no-build] [--yes]\n"
        "  vpngate-installer uninstall  [--prefix <dir>] [--dry-run] [--yes] [--force]\n"
        "  vpngate-installer verify     [--prefix <dir>]\n"
        "  vpngate-installer --help | --version\n\n"
        "This branch installs per-user only. It builds the existing Rust CLI and GUI with Cargo,\n"
        "records installed-file SHA-256 hashes, and removes only files from that inventory.\n"
        "System package installation, machine-wide settings, and toolchain bootstrapping are not\n"
        "ported yet; the current platform scripts remain the full-featured installer for now.\n"
        "Use --dry-run to preview. Real changes require --yes (GUI actions confirm before invoking the CLI).\n"
        "--force permits removing modified files that are already listed in the installer manifest;\n"
        "it never broadens cleanup to unrelated files or package-manager contents.\n");
}

namespace {

Result install(const QString &sourceRoot, const QString &prefix, const Options &options) {
    Result result;
    QString error;
    if (options.progress) {
        options.progress(0, 5, QStringLiteral("Validating source checkout"));
    }
    if (!validateSourceRoot(sourceRoot, &error)) {
        result.exitCode = 1;
        result.output.append(QStringLiteral("[error] %1").arg(error));
        return result;
    }

    QString hostError;
    if (!supportedHost(&hostError)) {
        result.exitCode = 1;
        result.output.append(QStringLiteral("[error] %1").arg(hostError));
        return result;
    }
    if (options.progress) {
        options.progress(1, 5, QStringLiteral("Source and host checks passed"));
    }

    QVector<PlannedFile> files;
    QString artifactRoot;
    std::unique_ptr<QTemporaryDir> buildOutput;
    if (!options.dryRun && !options.noBuild) {
        result.output.append(QStringLiteral("[plan] Build vpngate and vpngate-gui from the selected source checkout."));
        result.output.append(QStringLiteral("[plan] Install per-user under %1; no system paths or machine-wide settings will be changed.").arg(prefix));
        if (!confirmOperation(options, &result.output)) {
            result.exitCode = 2;
            return result;
        }
        buildOutput = std::make_unique<QTemporaryDir>();
        if (!buildOutput->isValid()) {
            result.exitCode = 1;
            result.output.append(QStringLiteral("[error] Could not create temporary storage for the native Cargo build."));
            return result;
        }
        artifactRoot = buildOutput->path();
        if (!buildDesktop(sourceRoot, artifactRoot, &result.output, options.progress, &error)) {
            result.exitCode = 1;
            result.output.append(QStringLiteral("[error] %1").arg(error));
            return result;
        }
        if (!createPlan(sourceRoot, prefix, &files, &error, artifactRoot, false)) {
            result.exitCode = 1;
            result.output.append(QStringLiteral("[error] %1").arg(error));
            return result;
        }
    } else {
        const bool allowMissingArtifacts = options.dryRun && !options.noBuild;
        if (allowMissingArtifacts) {
            result.output.append(QStringLiteral("[plan] Would build the Rust CLI and GUI with Cargo first."));
        }
        if (!createPlan(sourceRoot, prefix, &files, &error, {}, allowMissingArtifacts)) {
            result.exitCode = 1;
            result.output.append(QStringLiteral("[error] %1").arg(error));
            return result;
        }
    }
    if (options.progress && (options.dryRun || options.noBuild)) {
        options.progress(1, 5, QStringLiteral("Install plan prepared"));
    }

    result.output.append(QStringLiteral("Install plan (%1 file(s)):").arg(files.size()));
    for (const PlannedFile &file : files) {
        result.output.append(QStringLiteral("  - %1").arg(joinedPath(prefix, file.relativePath)));
    }
    result.output.append(QStringLiteral("Installer manifest: %1").arg(manifestPathForPrefix(prefix)));
    result.output.append(QStringLiteral("Install mode: per-user; no sudo, UAC, registry, firewall, or package-manager changes."));
    if (options.dryRun) {
        result.output.append(QStringLiteral("[dry-run] No files were written."));
        if (options.progress) {
            options.progress(5, 5, QStringLiteral("Dry-run complete; no files were written"));
        }
        return result;
    }
    if (options.noBuild && !options.assumeYes) {
        if (!confirmOperation(options, &result.output)) {
            result.exitCode = 2;
            return result;
        }
    } else if (options.noBuild && options.assumeYes) {
        // Already authorized by the CLI flag or GUI confirmation.
    }

    if (!ensurePrefixDirectory(prefix, &error)) {
        result.exitCode = 1;
        result.output.append(QStringLiteral("[error] %1").arg(error));
        return result;
    }

    Manifest previous;
    const QString manifestPath = manifestPathForPrefix(prefix);
    const QFileInfo existingManifest(manifestPath);
    const bool hasManifest = existingManifest.exists() || existingManifest.isSymLink();
    if (hasManifest && !readManifest(prefix, &previous, &error)) {
        result.exitCode = 1;
        result.output.append(QStringLiteral("[error] Existing install inventory could not be trusted: %1").arg(error));
        return result;
    }
    for (const PlannedFile &file : files) {
        if (!safeRelativePath(file.relativePath)) {
            result.exitCode = 1;
            result.output.append(QStringLiteral("[error] Unsafe generated install path: %1").arg(file.relativePath));
            return result;
        }
        const QString destination = joinedPath(prefix, file.relativePath);
        if (!isWithinPrefix(prefix, destination)) {
            result.exitCode = 1;
            result.output.append(QStringLiteral("[error] Install destination escaped prefix: %1").arg(destination));
            return result;
        }
        const QFileInfo info(destination);
        if (info.exists() || info.isSymLink()) {
            const ManifestEntry *owned = hasManifest ? findEntry(previous.files, file.relativePath) : nullptr;
            if (!owned) {
                result.exitCode = 1;
                result.output.append(QStringLiteral("[error] Refusing to overwrite a file not owned by this installer: %1").arg(destination));
                return result;
            }
            if (info.isSymLink() && !options.force) {
                result.exitCode = 1;
                result.output.append(QStringLiteral("[error] Existing installer-owned path became a symbolic link; use --force to replace the link itself: %1").arg(destination));
                return result;
            }
            if (!info.isSymLink() && info.isFile()) {
                const QByteArray actual = hashFile(destination, &error);
                if (actual.isEmpty()) {
                    result.exitCode = 1;
                    result.output.append(QStringLiteral("[error] %1").arg(error));
                    return result;
                }
                if (actual != owned->sha256 && !options.force) {
                    result.exitCode = 1;
                    result.output.append(QStringLiteral("[error] Existing installer-owned file was modified; use --force to replace it: %1").arg(destination));
                    return result;
                }
            } else if (!info.isSymLink()) {
                result.exitCode = 1;
                result.output.append(QStringLiteral("[error] Destination is not a regular file: %1").arg(destination));
                return result;
            }
        }
        if (pathHasSymlinkParent(prefix, file.relativePath)) {
            result.exitCode = 1;
            result.output.append(QStringLiteral("[error] Refusing to write through a symbolic-link directory: %1").arg(destination));
            return result;
        }
    }

    if (options.progress) {
        options.progress(4, 5, QStringLiteral("Staging verified files and preparing atomic install"));
    }
    QTemporaryDir staging(QDir(prefix).filePath(QStringLiteral(".vpngate-stage-XXXXXX")));
    if (!staging.isValid()) {
        result.exitCode = 1;
        result.output.append(QStringLiteral("[error] Could not create a transaction staging directory under %1").arg(prefix));
        return result;
    }

    QStringList createdDirectories = previous.createdDirectories;
    QVector<ManifestEntry> newEntries;
    for (const PlannedFile &file : files) {
        if (options.progress) {
            options.progress(4, 5, QStringLiteral("Staging %1").arg(file.relativePath));
        }
        QString stageError;
        const QString stagedPath = joinedPath(staging.path(), file.relativePath);
        if (!ensureSafeParentDirectories(staging.path(), file.relativePath, nullptr, &stageError)) {
            result.exitCode = 1;
            result.output.append(QStringLiteral("[error] %1").arg(stageError));
            return result;
        }
        if (!stageFile(file, stagedPath, &stageError)) {
            result.exitCode = 1;
            result.output.append(QStringLiteral("[error] %1").arg(stageError));
            return result;
        }
        const QByteArray digest = hashFile(stagedPath, &stageError);
        if (digest.isEmpty()) {
            result.exitCode = 1;
            result.output.append(QStringLiteral("[error] %1").arg(stageError));
            return result;
        }
        newEntries.append({file.relativePath, digest});
    }

    struct Backup {
        QString destination;
        QString backup;
        bool hadOriginal = false;
        bool newFileInstalled = false;
    };
    QVector<Backup> backups;
    bool transactionOk = true;
    QString transactionError;
    for (const PlannedFile &file : files) {
        if (options.progress) {
            options.progress(4, 5, QStringLiteral("Committing %1").arg(file.relativePath));
        }
        const QString destination = joinedPath(prefix, file.relativePath);
        if (!ensureSafeParentDirectories(prefix, file.relativePath, &createdDirectories, &transactionError)) {
            transactionOk = false;
            break;
        }
        const QString stagedPath = joinedPath(staging.path(), file.relativePath);
        Backup record;
        record.destination = destination;
        const QFileInfo info(destination);
        if (info.exists() || info.isSymLink()) {
            record.hadOriginal = true;
            record.backup = joinedPath(staging.path(), QStringLiteral(".backup/%1").arg(file.relativePath));
            if (!ensureSafeParentDirectories(staging.path(), QStringLiteral(".backup/%1").arg(file.relativePath), nullptr, &transactionError)
                || !QFile::rename(destination, record.backup)) {
                transactionOk = false;
                if (transactionError.isEmpty()) {
                    transactionError = QStringLiteral("Could not back up existing file before replacement: %1").arg(destination);
                }
                break;
            }
        }
        backups.append(record);
        if (!QFile::rename(stagedPath, destination)) {
            transactionOk = false;
            transactionError = QStringLiteral("Could not commit staged file: %1").arg(destination);
            break;
        }
        backups.last().newFileInstalled = true;
    }

    if (transactionOk) {
        for (const ManifestEntry &old : previous.files) {
            const bool planned = std::any_of(files.cbegin(), files.cend(), [&old](const PlannedFile &file) {
                return file.relativePath == old.relativePath;
            });
            if (!planned) {
                const QString stalePath = joinedPath(prefix, old.relativePath);
                const QFileInfo info(stalePath);
                if (!info.exists() && !info.isSymLink()) {
                    continue;
                }
                if ((info.isSymLink() && !options.force)
                    || (!info.isSymLink() && !info.isFile())
                    || (info.isFile() && !options.force && hashFile(stalePath) != old.sha256)
                    || pathHasSymlinkParent(prefix, old.relativePath)) {
                    newEntries.append(old);
                    result.output.append(QStringLiteral("[preserved] Obsolete tracked item was modified or became unsafe: %1")
                                             .arg(stalePath));
                    continue;
                }
                // Back up obsolete entries too so a manifest-write failure can roll back.
                const QString backupPath = joinedPath(staging.path(), QStringLiteral(".backup-stale/%1").arg(old.relativePath));
                if (!ensureSafeParentDirectories(staging.path(), QStringLiteral(".backup-stale/%1").arg(old.relativePath), nullptr, &transactionError)
                    || !QFile::rename(stalePath, backupPath)) {
                    transactionOk = false;
                    if (transactionError.isEmpty()) {
                        transactionError = QStringLiteral("Could not stage obsolete file for cleanup: %1").arg(stalePath);
                    }
                    break;
                }
                backups.append({stalePath, backupPath, true, false});
            }
        }
    }

    if (transactionOk && !writeManifest(prefix, newEntries, &createdDirectories, &transactionError)) {
        transactionOk = false;
    }

    if (!transactionOk) {
        for (auto it = backups.rbegin(); it != backups.rend(); ++it) {
            if (it->newFileInstalled) {
                QFile::remove(it->destination);
            }
            if (it->hadOriginal && QFileInfo::exists(it->backup)) {
                QFile::rename(it->backup, it->destination);
            }
        }
        removeEmptyCreatedDirectories(prefix, createdDirectories, nullptr);
        result.exitCode = 1;
        result.output.append(QStringLiteral("[error] Install transaction rolled back: %1").arg(transactionError));
        return result;
    }

    if (options.progress) {
        options.progress(5, 5, QStringLiteral("Install complete"));
    }
    result.output.append(QStringLiteral("[ok] Installed %1 file(s) under %2").arg(files.size()).arg(prefix));
    result.output.append(QStringLiteral("[ok] Inventory written with SHA-256 hashes; uninstaller will remove only tracked entries."));
    result.output.append(QStringLiteral("[note] This migration build is per-user only. System packages, firewall/NAT-T settings, and legacy global installs are not changed."));
    return result;
}

} // namespace

Result run(const Options &options) {
    const QString prefix = normalizePrefixOrDefault(options.prefix);
    QString scopeError;
    if (!validatePerUserPrefix(prefix, &scopeError)) {
        Result rejected;
        rejected.exitCode = 1;
        rejected.output.append(QStringLiteral("[error] %1").arg(scopeError));
        return rejected;
    }
    if (options.action == Action::Verify) {
        return verifyInstall(prefix, options);
    }
    if (options.action == Action::Uninstall) {
        return uninstall(prefix, options);
    }
    QString source = options.sourceDir.isEmpty() ? defaultSourceDir() : options.sourceDir;
    source = absoluteCleanPath(source);
    return install(source, prefix, options);
}

int runCli(const QStringList &arguments) {
    QTextStream out(stdout);
    QTextStream err(stderr);
    if (arguments.isEmpty() || arguments.contains(QStringLiteral("--help")) || arguments.contains(QStringLiteral("-h"))) {
        out << helpText();
        return 0;
    }
    if (arguments.contains(QStringLiteral("--version"))) {
        out << "vpngate-installer " << QCoreApplication::applicationVersion() << Qt::endl;
        return 0;
    }

    Options options;
    QString action;
    int index = 0;
    if (arguments.first() == QStringLiteral("--uninstall")) {
        action = QStringLiteral("uninstall");
        index = 1;
    } else {
        action = arguments.first();
        index = 1;
    }
    if (action == QStringLiteral("install")) {
        options.action = Action::Install;
    } else if (action == QStringLiteral("uninstall")) {
        options.action = Action::Uninstall;
    } else if (action == QStringLiteral("verify")) {
        options.action = Action::Verify;
    } else {
        err << "[error] Unknown action: " << action << Qt::endl << helpText();
        return 2;
    }

    bool machineProgress = false;
    while (index < arguments.size()) {
        const QString argument = arguments[index++];
        if (argument == QStringLiteral("--machine-progress")) {
            machineProgress = true;
        } else if (argument == QStringLiteral("--dry-run")) {
            options.dryRun = true;
        } else if (argument == QStringLiteral("--no-build")) {
            options.noBuild = true;
        } else if (argument == QStringLiteral("--yes") || argument == QStringLiteral("-y")) {
            options.assumeYes = true;
        } else if (argument == QStringLiteral("--force")) {
            options.force = true;
        } else if (argument == QStringLiteral("--source") || argument == QStringLiteral("--prefix")) {
            if (index >= arguments.size()) {
                err << "[error] " << argument << " requires a path." << Qt::endl;
                return 2;
            }
            const QString value = arguments[index++];
            if (argument == QStringLiteral("--source")) {
                options.sourceDir = value;
            } else {
                options.prefix = value;
            }
        } else {
            err << "[error] Unknown option: " << argument << Qt::endl;
            return 2;
        }
    }

    options.progress = [&out, machineProgress](int completed, int total, const QString &phase) {
        QString safePhase = phase;
        safePhase.replace(QLatin1Char('\t'), QLatin1Char(' '));
        safePhase.replace(QLatin1Char('\n'), QLatin1Char(' '));
        safePhase.replace(QLatin1Char('\r'), QLatin1Char(' '));
        if (machineProgress) {
            out << "@@PROGRESS\t" << completed << '\t' << total << '\t' << safePhase << Qt::endl;
        } else {
            out << '[' << completed << '/' << total << "] " << safePhase << Qt::endl;
        }
    };

    const Result result = run(options);
    for (const QString &line : result.output) {
        out << line << Qt::endl;
    }
    return result.exitCode;
}

} // namespace vpngate::installer
