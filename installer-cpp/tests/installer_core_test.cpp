#include "installer_core.hpp"
#include "host_integration.hpp"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>
#include <QTextStream>
#include <QSysInfo>

#include <cstdlib>

using namespace vpngate::installer;

namespace {

QString temporaryDirectoryTemplate() {
#if defined(Q_OS_MACOS)
    // macOS rejects installer prefixes under /private/var, where QTemporaryDir
    // normally lives. Keep test fixtures under the user's home instead.
    return QDir(QDir::homePath()).filePath(QStringLiteral(".vpngate-installer-test-XXXXXX"));
#else
    return {};
#endif
}

[[noreturn]] void fail(const QString &message) {
    QTextStream(stderr) << "TEST FAILURE: " << message << Qt::endl;
    std::exit(1);
}

void require(bool condition, const QString &message) {
    if (!condition) {
        fail(message);
    }
}

void writeFile(const QString &path, const QByteArray &contents) {
    require(QDir().mkpath(QFileInfo(path).path()), QStringLiteral("could not create test directory for %1").arg(path));
    QFile file(path);
    require(file.open(QIODevice::WriteOnly | QIODevice::Truncate), QStringLiteral("could not create test file %1").arg(path));
    require(file.write(contents) == contents.size(), QStringLiteral("could not write test file %1").arg(path));
    file.close();
    QFile::setPermissions(path, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner
                                   | QFileDevice::ReadGroup | QFileDevice::ExeGroup
                                   | QFileDevice::ReadOther | QFileDevice::ExeOther);
}

void setLittleEndian(QByteArray *bytes, qsizetype offset, quint64 value, int width) {
    for (int index = 0; index < width; ++index) {
        (*bytes)[offset + index] = static_cast<char>((value >> (index * 8)) & 0xff);
    }
}

QByteArray readFile(const QString &path) {
    QFile file(path);
    require(file.open(QIODevice::ReadOnly), QStringLiteral("could not read test file %1").arg(path));
    return file.readAll();
}

class ScopedTestEnvironmentVariable final {
public:
    ScopedTestEnvironmentVariable(const char *name, const QByteArray &value)
        : name_(name), wasSet_(qEnvironmentVariableIsSet(name)), previous_(qgetenv(name)) {
        qputenv(name, value);
    }

    ~ScopedTestEnvironmentVariable() {
        if (wasSet_) {
            qputenv(name_.constData(), previous_);
        } else {
            qunsetenv(name_.constData());
        }
    }

private:
    QByteArray name_;
    bool wasSet_ = false;
    QByteArray previous_;
};

class ScopedAppStateEnvironment final {
public:
    explicit ScopedAppStateEnvironment(const QString &root) {
#if defined(Q_OS_LINUX)
        hadCacheHome_ = qEnvironmentVariableIsSet("XDG_CACHE_HOME");
        hadConfigHome_ = qEnvironmentVariableIsSet("XDG_CONFIG_HOME");
        oldCacheHome_ = qgetenv("XDG_CACHE_HOME");
        oldConfigHome_ = qgetenv("XDG_CONFIG_HOME");
        cacheHome_ = QDir(root).filePath(QStringLiteral("cache"));
        configHome_ = QDir(root).filePath(QStringLiteral("config"));
        qputenv("XDG_CACHE_HOME", cacheHome_.toUtf8());
        qputenv("XDG_CONFIG_HOME", configHome_.toUtf8());
#elif defined(Q_OS_WIN)
        hadLocalAppData_ = qEnvironmentVariableIsSet("LOCALAPPDATA");
        oldLocalAppData_ = qgetenv("LOCALAPPDATA");
        localAppData_ = QDir(root).filePath(QStringLiteral("local-app-data"));
        qputenv("LOCALAPPDATA", localAppData_.toUtf8());
#elif defined(Q_OS_MACOS)
        hadHome_ = qEnvironmentVariableIsSet("HOME");
        oldHome_ = qgetenv("HOME");
        home_ = QDir(root).filePath(QStringLiteral("home"));
        qputenv("HOME", home_.toUtf8());
#endif
    }

    ~ScopedAppStateEnvironment() {
#if defined(Q_OS_LINUX)
        restore("XDG_CACHE_HOME", hadCacheHome_, oldCacheHome_);
        restore("XDG_CONFIG_HOME", hadConfigHome_, oldConfigHome_);
#elif defined(Q_OS_WIN)
        restore("LOCALAPPDATA", hadLocalAppData_, oldLocalAppData_);
#elif defined(Q_OS_MACOS)
        restore("HOME", hadHome_, oldHome_);
#endif
    }

#if defined(Q_OS_LINUX)
    QString cacheHome() const { return cacheHome_; }
    QString configHome() const { return configHome_; }
#elif defined(Q_OS_WIN)
    QString localAppData() const { return localAppData_; }
#elif defined(Q_OS_MACOS)
    QString home() const { return home_; }
#endif

private:
    static void restore(const char *name, bool wasSet, const QByteArray &previous) {
        if (wasSet) {
            qputenv(name, previous);
        } else {
            qunsetenv(name);
        }
    }

#if defined(Q_OS_LINUX)
    bool hadCacheHome_ = false;
    bool hadConfigHome_ = false;
    QByteArray oldCacheHome_;
    QByteArray oldConfigHome_;
    QString cacheHome_;
    QString configHome_;
#elif defined(Q_OS_WIN)
    bool hadLocalAppData_ = false;
    QByteArray oldLocalAppData_;
    QString localAppData_;
#elif defined(Q_OS_MACOS)
    bool hadHome_ = false;
    QByteArray oldHome_;
    QString home_;
#endif
};

QString artifactName(const QString &stem) {
#if defined(Q_OS_WIN)
    return stem + QStringLiteral(".exe");
#else
    return stem;
#endif
}

QString installedCliPath(const QString &prefix) {
#if defined(Q_OS_WIN)
    return QDir(prefix).filePath(QStringLiteral("vpngate.exe"));
#elif defined(Q_OS_MACOS)
    return QDir(prefix).filePath(QStringLiteral("Contents/MacOS/vpngate"));
#else
    return QDir(prefix).filePath(QStringLiteral("bin/vpngate"));
#endif
}

QString installedLicensePath(const QString &prefix) {
#if defined(Q_OS_MACOS)
    return QDir(prefix).filePath(QStringLiteral("Contents/Resources/LICENSE"));
#else
    return QDir(prefix).filePath(QStringLiteral("share/vpngate/LICENSE"));
#endif
}

void makeFakeCheckout(const QString &root) {
    writeFile(QDir(root).filePath(QStringLiteral("Cargo.toml")), QByteArrayLiteral("[workspace]\n"));
    writeFile(QDir(root).filePath(QStringLiteral("crates/vpngate-gui/Cargo.toml")), QByteArrayLiteral("[package]\n"));
    writeFile(QDir(root).filePath(QStringLiteral("assets/vpngate.svg")), QByteArrayLiteral("<svg/>\n"));
    writeFile(QDir(root).filePath(QStringLiteral("assets/vpngate.ico")), QByteArrayLiteral("icon"));
    writeFile(QDir(root).filePath(QStringLiteral("assets/vpngate-256.png")), QByteArrayLiteral("png"));
    writeFile(QDir(root).filePath(QStringLiteral("assets/vpngate-512.png")), QByteArrayLiteral("png"));
    writeFile(QDir(root).filePath(QStringLiteral("assets/icons/hicolor/16x16/apps/vpngate.png")), QByteArrayLiteral("png16"));
    writeFile(QDir(root).filePath(QStringLiteral("LICENSE")), QByteArrayLiteral("test license"));
    writeFile(QDir(root).filePath(QStringLiteral("target/release/%1").arg(artifactName(QStringLiteral("vpngate")))), QByteArrayLiteral("cli-binary"));
    writeFile(QDir(root).filePath(QStringLiteral("target/release/%1").arg(artifactName(QStringLiteral("vpngate-gui")))), QByteArrayLiteral("gui-binary"));
}

Options fakeInstallOptions(const QString &source, const QString &prefix) {
    Options options;
    options.action = Action::Install;
    options.sourceDir = source;
    options.prefix = prefix;
    options.noBuild = true;
    options.assumeYes = true;
    return options;
}

void testFullWorkflowRequiresExplicitAuthorization() {
    Options options;
    options.action = Action::Install;
    options.fullWorkflow = true;
    const Result denied = run(options);
    require(denied.exitCode == 2, QStringLiteral("full workflow proceeded without explicit authorization"));
    require(denied.output.join('\n').contains(QStringLiteral("--yes")),
            QStringLiteral("full workflow did not explain the explicit confirmation requirement"));
}

void testNativeBinaryArchitectureValidation() {
    QString error;
    const QString testExecutable = QCoreApplication::applicationFilePath();
    require(validateNativeBinaryArchitecture(testExecutable, &error),
            QStringLiteral("the native test executable failed architecture validation: %1").arg(error));

    QTemporaryDir temp(temporaryDirectoryTemplate());
    require(temp.isValid(), QStringLiteral("temporary directory unavailable"));
    const QString architecture = QSysInfo::currentCpuArchitecture().toLower();
    const bool hostIsArm64 = architecture == QStringLiteral("arm64")
        || architecture == QStringLiteral("aarch64");
    require(hostIsArm64 || architecture == QStringLiteral("x86_64")
                || architecture == QStringLiteral("amd64"),
            QStringLiteral("test is running on an unexpected host architecture: %1").arg(architecture));

    QByteArray wrongArchitecture;
#if defined(Q_OS_WIN)
    wrongArchitecture = QByteArray(0x86, '\0');
    wrongArchitecture[0] = 'M';
    wrongArchitecture[1] = 'Z';
    setLittleEndian(&wrongArchitecture, 0x3c, 0x80, 4);
    wrongArchitecture[0x80] = 'P';
    wrongArchitecture[0x81] = 'E';
    setLittleEndian(&wrongArchitecture, 0x84, hostIsArm64 ? 0x8664 : 0xaa64, 2);
#elif defined(Q_OS_MACOS)
    wrongArchitecture = QByteArray(32, '\0');
    wrongArchitecture[0] = static_cast<char>(0xcf);
    wrongArchitecture[1] = static_cast<char>(0xfa);
    wrongArchitecture[2] = static_cast<char>(0xed);
    wrongArchitecture[3] = static_cast<char>(0xfe);
    setLittleEndian(&wrongArchitecture, 4, hostIsArm64 ? 0x01000007 : 0x0100000c, 4);
    setLittleEndian(&wrongArchitecture, 12, 2, 4); // MH_EXECUTE.
#else
    wrongArchitecture = QByteArray(64, '\0');
    wrongArchitecture[0] = static_cast<char>(0x7f);
    wrongArchitecture[1] = 'E';
    wrongArchitecture[2] = 'L';
    wrongArchitecture[3] = 'F';
    wrongArchitecture[4] = 2; // ELFCLASS64.
    wrongArchitecture[5] = 1; // ELFDATA2LSB.
    wrongArchitecture[6] = 1; // EV_CURRENT.
    setLittleEndian(&wrongArchitecture, 16, 2, 2); // ET_EXEC.
    setLittleEndian(&wrongArchitecture, 18, hostIsArm64 ? 62 : 183, 2);
#endif
    const QString wrongPath = QDir(temp.path()).filePath(QStringLiteral("wrong-architecture"));
    writeFile(wrongPath, wrongArchitecture);
    error.clear();
    require(!validateNativeBinaryArchitecture(wrongPath, &error)
                && error.contains(QStringLiteral("architecture mismatch")),
            QStringLiteral("a valid executable header for another architecture was not rejected: %1").arg(error));

    const QString malformedPath = QDir(temp.path()).filePath(QStringLiteral("not-an-executable"));
    writeFile(malformedPath, QByteArrayLiteral("not a native executable"));
    error.clear();
    require(!validateNativeBinaryArchitecture(malformedPath, &error) && !error.isEmpty(),
            QStringLiteral("a malformed native artifact was not rejected"));

    const QString fakeSource = QDir(temp.path()).filePath(QStringLiteral("fake-source"));
    const QString rejectedPrefix = QDir(temp.path()).filePath(QStringLiteral("rejected-install"));
    require(QDir().mkpath(fakeSource), QStringLiteral("could not create fake source root"));
    makeFakeCheckout(fakeSource);
    Options guardedInstall = fakeInstallOptions(fakeSource, rejectedPrefix);
    guardedInstall.validateNativeArtifacts = true;
    const Result rejectedInstall = run(guardedInstall);
    require(rejectedInstall.exitCode != 0
                && rejectedInstall.output.join('\n').contains(QStringLiteral("Native artifact validation failed")),
            QStringLiteral("installer accepted fake non-native client artifacts"));
    require(!QFileInfo::exists(rejectedPrefix),
            QStringLiteral("artifact validation failure created the install prefix"));
}

void testSourceArchiveEntryValidation() {
    QString error;
    const QStringList safePaths{QStringLiteral("vpngate-connect-main/"),
                                QStringLiteral("vpngate-connect-main/Cargo.toml")};
    const QStringList safeTypes{QStringLiteral("drwxr-xr-x root/root 0 2026-01-01 vpngate-connect-main/"),
                                QStringLiteral("-rw-r--r-- root/root 12 2026-01-01 vpngate-connect-main/Cargo.toml")};
    require(validateSourceArchiveEntries(safePaths, safeTypes, &error),
            QStringLiteral("normal source archive entries were rejected: %1").arg(error));

    error.clear();
    require(!validateSourceArchiveEntries({QStringLiteral("../outside")},
                {QStringLiteral("-rw-r--r-- root/root 1 2026-01-01 ../outside")}, &error)
                && error.contains(QStringLiteral("unsafe path")),
            QStringLiteral("archive traversal entry was not rejected"));

    error.clear();
    require(!validateSourceArchiveEntries({QStringLiteral("C:/outside")},
                {QStringLiteral("-rw-r--r-- root/root 1 2026-01-01 C:/outside")}, &error),
            QStringLiteral("Windows drive-absolute archive entry was not rejected"));

    error.clear();
    require(!validateSourceArchiveEntries({QStringLiteral("dir\\\\outside")},
                {QStringLiteral("-rw-r--r-- root/root 1 2026-01-01 dir\\\\outside")}, &error),
            QStringLiteral("backslash archive entry was not rejected"));

    error.clear();
    require(!validateSourceArchiveEntries({QStringLiteral("repo/link")},
                {QStringLiteral("lrwxrwxrwx root/root 0 2026-01-01 repo/link -> ../outside")}, &error)
                && error.contains(QStringLiteral("symlink")),
            QStringLiteral("symbolic link archive entry was not rejected"));

    error.clear();
    require(!validateSourceArchiveEntries({QStringLiteral("repo/hardlink")},
                {QStringLiteral("hrw-r--r-- root/root 0 2026-01-01 repo/hardlink link to repo/file")}, &error)
                && error.contains(QStringLiteral("hardlink")),
            QStringLiteral("hardlink archive entry was not rejected"));

    error.clear();
    require(!validateSourceArchiveEntries({QStringLiteral("repo/file")}, {}, &error),
            QStringLiteral("inconsistent archive listings were not rejected"));
}

#if defined(Q_OS_LINUX)
void testFullSystemDryRunPlansHostAndManifestFiles() {
    QTemporaryDir temp(temporaryDirectoryTemplate());
    require(temp.isValid(), QStringLiteral("temporary directory unavailable"));
    const QString source = QDir(temp.path()).filePath(QStringLiteral("source"));
    const QString targetHome = QDir(temp.path()).filePath(QStringLiteral("target-home"));
    require(QDir().mkpath(source), QStringLiteral("could not create source root"));
    require(QDir().mkpath(targetHome), QStringLiteral("could not create target home"));
    makeFakeCheckout(source);

    Options options;
    options.action = Action::Install;
    options.sourceDir = source;
    options.prefix = QDir(temp.path()).filePath(QStringLiteral("system-install"));
    options.targetHome = targetHome;
    options.cacheDir = QDir(targetHome).filePath(QStringLiteral(".cache/vpngate"));
    options.fullWorkflow = true;
    options.dryRun = true;
    options.noBuild = true;
    const Result preview = run(options);
    require(preview.exitCode == 0, preview.output.join('\n'));
    require(preview.output.join('\n').contains(QStringLiteral("[plan]")),
            QStringLiteral("full workflow dry-run omitted host actions"));
    require(preview.output.join('\n').contains(QDir(options.prefix).filePath(QStringLiteral("bin/vpngate"))),
            QStringLiteral("full workflow dry-run omitted the native CLI install path"));
    require(!QFileInfo::exists(options.prefix),
            QStringLiteral("full workflow dry-run created its install prefix"));
    require(!QFileInfo::exists(options.cacheDir),
            QStringLiteral("full workflow dry-run created its cache directory"));
}
#endif

#if defined(Q_OS_WIN)
void testWindowsHostDryRunUsesScopedInstallPaths() {
    QTemporaryDir temp(temporaryDirectoryTemplate());
    require(temp.isValid(), QStringLiteral("temporary directory unavailable"));
    ScopedAppStateEnvironment appState(QDir(temp.path()).filePath(QStringLiteral("app-state")));
    const QString source = QDir(temp.path()).filePath(QStringLiteral("source"));
    const QString targetHome = QDir(temp.path()).filePath(QStringLiteral("target-home"));
    require(QDir().mkpath(source), QStringLiteral("could not create source root"));
    require(QDir().mkpath(targetHome), QStringLiteral("could not create target home"));
    makeFakeCheckout(source);

    Options options;
    options.action = Action::Install;
    options.sourceDir = source;
    options.prefix = systemInstallPrefix();
    options.targetHome = targetHome;
    options.cacheDir = QDir(appState.localAppData()).filePath(QStringLiteral("vpngate"));
    options.fullWorkflow = true;
    options.dryRun = true;
    options.noBuild = true;
    const Result preview = run(options);
    const QString transcript = preview.output.join('\n');
    require(preview.exitCode == 0, transcript);
    require(transcript.contains(QStringLiteral("[plan]")),
            QStringLiteral("Windows full workflow dry-run omitted host actions"));
    require(transcript.contains(QDir(options.prefix).filePath(QStringLiteral("vpngate.exe"))),
            QStringLiteral("Windows full workflow dry-run omitted the native CLI install path"));
    require(!QFileInfo::exists(options.prefix),
            QStringLiteral("Windows full workflow dry-run created its install directory"));
    require(!QFileInfo::exists(options.cacheDir),
            QStringLiteral("Windows full workflow dry-run created its cache directory"));
}
#endif

#if defined(Q_OS_MACOS)
void testMacSystemDryRunUsesNativeCommandLayout() {
    QTemporaryDir temp(temporaryDirectoryTemplate());
    require(temp.isValid(), QStringLiteral("temporary directory unavailable"));
    const QString source = QDir(temp.path()).filePath(QStringLiteral("source"));
    const QString targetHome = QDir(temp.path()).filePath(QStringLiteral("target-home"));
    require(QDir().mkpath(source), QStringLiteral("could not create source root"));
    require(QDir().mkpath(targetHome), QStringLiteral("could not create target home"));
    makeFakeCheckout(source);

    Options options;
    options.action = Action::Install;
    options.sourceDir = source;
    options.prefix = systemInstallPrefix();
    options.targetHome = targetHome;
    options.cacheDir = QDir(targetHome).filePath(QStringLiteral("Library/Caches/vpngate"));
    options.fullWorkflow = true;
    options.dryRun = true;
    options.noBuild = true;
    const Result preview = run(options);
    const QString transcript = preview.output.join('\n');
    require(preview.exitCode == 0, transcript);
    require(transcript.contains(QStringLiteral("/usr/local/bin/vpngate")),
            QStringLiteral("macOS system install did not plan the CLI command path"));
    require(transcript.contains(QStringLiteral("/usr/local/bin/vpngate-gui")),
            QStringLiteral("macOS system install did not plan the GUI command path"));
    require(transcript.contains(QStringLiteral("/usr/local/share/vpngate/installer-manifest.json")),
            QStringLiteral("macOS system manifest was not planned under /usr/local/share"));
    require(!transcript.contains(QStringLiteral("/usr/local/Contents/MacOS")),
            QStringLiteral("macOS system workflow incorrectly planned an application bundle inside /usr/local"));
    require(!QFileInfo::exists(options.cacheDir),
            QStringLiteral("macOS full workflow dry-run created its cache directory"));
}
#endif

#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
void testCargoBuildUsesExplicitTargetAndTargetedOutputLayout() {
    QTemporaryDir temp(temporaryDirectoryTemplate());
    require(temp.isValid(), QStringLiteral("temporary directory unavailable"));
    ScopedAppStateEnvironment appState(QDir(temp.path()).filePath(QStringLiteral("app-state")));
    const QString source = QDir(temp.path()).filePath(QStringLiteral("source"));
    const QString prefix = QDir(temp.path()).filePath(QStringLiteral("install"));
    const QString cargoHome = QDir(temp.path()).filePath(QStringLiteral("cargo-home"));
    const QString cargoBin = QDir(cargoHome).filePath(QStringLiteral("bin"));
    const QString cargoLog = QDir(temp.path()).filePath(QStringLiteral("cargo-arguments.log"));
    require(QDir().mkpath(source), QStringLiteral("could not create source root"));
    require(QDir().mkpath(cargoBin), QStringLiteral("could not create fake Cargo directory"));
    makeFakeCheckout(source);
    require(QDir(QDir(source).filePath(QStringLiteral("target"))).removeRecursively(),
            QStringLiteral("could not remove fake host-default build artifacts"));

    const QString fakeCargoPath = QDir(cargoBin).filePath(QStringLiteral("cargo"));
    writeFile(fakeCargoPath, QByteArrayLiteral(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$CARGO_TEST_LOG\"\n"
        "target=''\n"
        "target_dir=''\n"
        "package=''\n"
        "while [ \"$#\" -gt 0 ]; do\n"
        "  case \"$1\" in\n"
        "    --target) target=\"$2\"; shift 2 ;;\n"
        "    --target-dir) target_dir=\"$2\"; shift 2 ;;\n"
        "    -p) package=\"$2\"; shift 2 ;;\n"
        "    *) shift ;;\n"
        "  esac\n"
        "done\n"
        "[ -n \"$target\" ] && [ -n \"$target_dir\" ] || exit 23\n"
        "name=vpngate-gui\n"
        "if [ \"$package\" = 'vpngate-cli' ]; then name=vpngate; fi\n"
        "out=\"$target_dir/$target/release/$name\"\n"
        "/bin/mkdir -p \"$target_dir/$target/release\" || exit 24\n"
        "/bin/cp \"$VPNGATE_TEST_BINARY\" \"$out\" || exit 25\n"
        "/bin/chmod 755 \"$out\" || exit 26\n"
    ));

    ScopedTestEnvironmentVariable path("PATH", cargoBin.toLocal8Bit());
    ScopedTestEnvironmentVariable cargo("CARGO_HOME", cargoHome.toLocal8Bit());
    ScopedTestEnvironmentVariable log("CARGO_TEST_LOG", cargoLog.toLocal8Bit());
    ScopedTestEnvironmentVariable nativeBinary("VPNGATE_TEST_BINARY",
                                                QCoreApplication::applicationFilePath().toLocal8Bit());

    Options options;
    options.action = Action::Install;
    options.sourceDir = source;
    options.prefix = prefix;
    options.assumeYes = true;
    options.buildTargetTriple = QStringLiteral("test-native-target");
    options.validateNativeArtifacts = true;
    const QByteArray expectedArtifact = readFile(QCoreApplication::applicationFilePath());
    const Result installed = run(options);
    require(installed.exitCode == 0, installed.output.join('\n'));
    const QString arguments = QString::fromLocal8Bit(readFile(cargoLog));
    require(arguments.count(QStringLiteral("--target test-native-target")) == 2,
            QStringLiteral("Cargo was not given the explicit target for both binaries: %1").arg(arguments));
    require(readFile(installedCliPath(prefix)) == expectedArtifact,
            QStringLiteral("CLI artifact was not discovered in the target-specific Cargo directory"));
    const QString guiPath = QDir(QFileInfo(installedCliPath(prefix)).path())
        .filePath(artifactName(QStringLiteral("vpngate-gui")));
    require(readFile(guiPath) == expectedArtifact,
            QStringLiteral("GUI artifact was not discovered in the target-specific Cargo directory"));

    Options verify;
    verify.action = Action::Verify;
    verify.prefix = prefix;
    const Result verified = run(verify);
    require(verified.exitCode == 0, verified.output.join('\n'));
    Options uninstall;
    uninstall.action = Action::Uninstall;
    uninstall.prefix = prefix;
    uninstall.assumeYes = true;
    const Result removed = run(uninstall);
    require(removed.exitCode == 0, removed.output.join('\n'));
}
#endif

void testInstallVerifyUninstallPreservesUnrelatedData() {
    QTemporaryDir temp(temporaryDirectoryTemplate());
    require(temp.isValid(), QStringLiteral("temporary directory unavailable"));
    ScopedAppStateEnvironment appState(QDir(temp.path()).filePath(QStringLiteral("app-state")));
    const QString source = QDir(temp.path()).filePath(QStringLiteral("source"));
    const QString prefix = QDir(temp.path()).filePath(QStringLiteral("install"));
    require(QDir().mkpath(source), QStringLiteral("could not create source root"));
    makeFakeCheckout(source);

    const Result installed = run(fakeInstallOptions(source, prefix));
    require(installed.exitCode == 0, installed.output.join('\n'));
    require(QFileInfo::exists(manifestPathForPrefix(prefix)), QStringLiteral("manifest was not installed"));

    Options verifyOptions;
    verifyOptions.action = Action::Verify;
    verifyOptions.prefix = prefix;
    const Result verified = run(verifyOptions);
    require(verified.exitCode == 0, verified.output.join('\n'));

    const QString unowned = QDir(prefix).filePath(QStringLiteral("user-notes.txt"));
    writeFile(unowned, QByteArrayLiteral("keep me"));

    QString appCache;
    QString appConfig;
    QString unrelatedCache;
    QString unrelatedConfig;
#if defined(Q_OS_LINUX)
    appCache = QDir(appState.cacheHome()).filePath(QStringLiteral("vpngate"));
    appConfig = QDir(appState.configHome()).filePath(QStringLiteral("vpngate"));
    unrelatedCache = QDir(appState.cacheHome()).filePath(QStringLiteral("other-app"));
    unrelatedConfig = QDir(appState.configHome()).filePath(QStringLiteral("other-app"));
    writeFile(QDir(appCache).filePath(QStringLiteral("session.bin")), QByteArrayLiteral("cache"));
    writeFile(QDir(appConfig).filePath(QStringLiteral("settings.json")), QByteArrayLiteral("{}"));
    writeFile(QDir(unrelatedCache).filePath(QStringLiteral("keep.bin")), QByteArrayLiteral("keep"));
    writeFile(QDir(unrelatedConfig).filePath(QStringLiteral("keep.json")), QByteArrayLiteral("keep"));
#elif defined(Q_OS_WIN)
    appCache = QDir(appState.localAppData()).filePath(QStringLiteral("vpngate"));
    unrelatedCache = QDir(appState.localAppData()).filePath(QStringLiteral("other-app"));
    writeFile(QDir(appCache).filePath(QStringLiteral("session.bin")), QByteArrayLiteral("cache"));
    writeFile(QDir(unrelatedCache).filePath(QStringLiteral("keep.bin")), QByteArrayLiteral("keep"));
#elif defined(Q_OS_MACOS)
    const QString cacheHome = QDir(appState.home()).filePath(QStringLiteral("Library/Caches"));
    const QString configHome = QDir(appState.home()).filePath(QStringLiteral(".config"));
    appCache = QDir(cacheHome).filePath(QStringLiteral("vpngate"));
    appConfig = QDir(configHome).filePath(QStringLiteral("vpngate"));
    unrelatedCache = QDir(cacheHome).filePath(QStringLiteral("other-app"));
    unrelatedConfig = QDir(configHome).filePath(QStringLiteral("other-app"));
    writeFile(QDir(appCache).filePath(QStringLiteral("session.bin")), QByteArrayLiteral("cache"));
    writeFile(QDir(appConfig).filePath(QStringLiteral("settings.json")), QByteArrayLiteral("{}"));
    writeFile(QDir(unrelatedCache).filePath(QStringLiteral("keep.bin")), QByteArrayLiteral("keep"));
    writeFile(QDir(unrelatedConfig).filePath(QStringLiteral("keep.json")), QByteArrayLiteral("keep"));
#endif

    Options uninstallOptions;
    uninstallOptions.action = Action::Uninstall;
    uninstallOptions.prefix = prefix;
    uninstallOptions.assumeYes = true;
    const Result removed = run(uninstallOptions);
    require(removed.exitCode == 0, removed.output.join('\n'));
    require(!QFileInfo::exists(manifestPathForPrefix(prefix)), QStringLiteral("manifest residue remains"));
    require(QFileInfo::exists(unowned), QStringLiteral("uninstaller removed an unrelated file"));
    require(!QFileInfo::exists(installedCliPath(prefix)), QStringLiteral("CLI binary residue remains"));
    require(!QFileInfo::exists(installedLicensePath(prefix)), QStringLiteral("license residue remains"));
#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
    require(!QFileInfo::exists(appCache), QStringLiteral("VPN Gate cache state was not removed"));
    require(!QFileInfo::exists(appConfig), QStringLiteral("VPN Gate config state was not removed"));
    require(QFileInfo::exists(QDir(unrelatedCache).filePath(QStringLiteral("keep.bin"))),
            QStringLiteral("uninstaller removed another application's cache"));
    require(QFileInfo::exists(QDir(unrelatedConfig).filePath(QStringLiteral("keep.json"))),
            QStringLiteral("uninstaller removed another application's config"));
#elif defined(Q_OS_WIN)
    require(!QFileInfo::exists(appCache), QStringLiteral("VPN Gate app state was not removed"));
    require(QFileInfo::exists(QDir(unrelatedCache).filePath(QStringLiteral("keep.bin"))),
            QStringLiteral("uninstaller removed unrelated local app data"));
#endif
#if defined(Q_OS_WIN) || defined(Q_OS_LINUX)
    require(!QFileInfo::exists(QDir(prefix).filePath(QStringLiteral("share"))),
            QStringLiteral("installer-created share directories remain after uninstall"));
#elif defined(Q_OS_MACOS)
    require(!QFileInfo::exists(QDir(prefix).filePath(QStringLiteral("Contents"))),
            QStringLiteral("installer-created app bundle contents remain after uninstall"));
#endif
}

void testDryRunAndNoOverwrite() {
    QTemporaryDir temp(temporaryDirectoryTemplate());
    require(temp.isValid(), QStringLiteral("temporary directory unavailable"));
    const QString source = QDir(temp.path()).filePath(QStringLiteral("source"));
    const QString prefix = QDir(temp.path()).filePath(QStringLiteral("install"));
    require(QDir().mkpath(source), QStringLiteral("could not create source root"));
    makeFakeCheckout(source);

    Options dry = fakeInstallOptions(source, prefix);
    dry.dryRun = true;
    const Result preview = run(dry);
    require(preview.exitCode == 0, preview.output.join('\n'));
    require(!QFileInfo::exists(prefix), QStringLiteral("--no-build dry-run created the install prefix"));

    Options forbiddenSystemPrefix = dry;
    forbiddenSystemPrefix.prefix = QDir::rootPath();
    const Result rejectedSystemPrefix = run(forbiddenSystemPrefix);
    require(rejectedSystemPrefix.exitCode != 0,
            QStringLiteral("installer accepted a filesystem-root install prefix"));

    QTemporaryDir sourceOnlyTemp(temporaryDirectoryTemplate());
    require(sourceOnlyTemp.isValid(), QStringLiteral("temporary directory unavailable for build dry-run"));
    const QString sourceOnly = QDir(sourceOnlyTemp.path()).filePath(QStringLiteral("source"));
    const QString dryPrefix = QDir(sourceOnlyTemp.path()).filePath(QStringLiteral("install"));
    require(QDir().mkpath(sourceOnly), QStringLiteral("could not create dry-run source root"));
    makeFakeCheckout(sourceOnly);
    require(QDir(QDir(sourceOnly).filePath(QStringLiteral("target"))).removeRecursively(),
            QStringLiteral("could not remove fake artifacts for dry-run"));
    Options buildDryRun;
    buildDryRun.action = Action::Install;
    buildDryRun.sourceDir = sourceOnly;
    buildDryRun.prefix = dryPrefix;
    buildDryRun.dryRun = true;
    const Result buildPreview = run(buildDryRun);
    require(buildPreview.exitCode == 0, buildPreview.output.join('\n'));
    require(!QFileInfo::exists(dryPrefix), QStringLiteral("default dry-run created the install prefix"));
    require(!QFileInfo::exists(QDir(sourceOnly).filePath(QStringLiteral("target"))),
            QStringLiteral("default dry-run created build output in the source checkout"));

    require(QDir().mkpath(QDir(prefix).filePath(QStringLiteral("bin"))), QStringLiteral("could not create conflict directory"));
    const QString conflict = installedCliPath(prefix);
    writeFile(conflict, QByteArrayLiteral("user-owned binary"));
    const Result blocked = run(fakeInstallOptions(source, prefix));
    require(blocked.exitCode != 0, QStringLiteral("installer overwrote an unowned file"));
    require(readFile(conflict) == QByteArrayLiteral("user-owned binary"),
            QStringLiteral("unowned file was changed"));
}

void testModifiedFilesArePreservedUnlessForced() {
    QTemporaryDir temp(temporaryDirectoryTemplate());
    require(temp.isValid(), QStringLiteral("temporary directory unavailable"));
    const QString source = QDir(temp.path()).filePath(QStringLiteral("source"));
    const QString prefix = QDir(temp.path()).filePath(QStringLiteral("install"));
    ScopedAppStateEnvironment appState(QDir(temp.path()).filePath(QStringLiteral("app-state")));
    require(QDir().mkpath(source), QStringLiteral("could not create source root"));
    makeFakeCheckout(source);
    const Result installed = run(fakeInstallOptions(source, prefix));
    require(installed.exitCode == 0, installed.output.join('\n'));

    const QString cli = installedCliPath(prefix);
    const QString userFile = QDir(QFileInfo(cli).path()).filePath(QStringLiteral("user-tool.txt"));
    writeFile(cli, QByteArrayLiteral("user-modified client"));
    writeFile(userFile, QByteArrayLiteral("unrelated"));

    Options uninstallOptions;
    uninstallOptions.action = Action::Uninstall;
    uninstallOptions.prefix = prefix;
    uninstallOptions.assumeYes = true;
    const Result safeUninstall = run(uninstallOptions);
    require(safeUninstall.exitCode != 0, QStringLiteral("uninstaller should report a modified tracked file"));
    require(readFile(cli) == QByteArrayLiteral("user-modified client"),
            QStringLiteral("uninstaller removed a modified tracked file without --force"));
    require(QFileInfo::exists(manifestPathForPrefix(prefix)),
            QStringLiteral("manifest was not retained for a safe uninstall retry"));

    uninstallOptions.force = true;
    const Result forcedUninstall = run(uninstallOptions);
    require(forcedUninstall.exitCode == 0, forcedUninstall.output.join('\n'));
    require(!QFileInfo::exists(cli), QStringLiteral("--force did not remove the modified tracked file"));
    require(QFileInfo::exists(userFile), QStringLiteral("--force removed an unrelated file"));
}

void testUpgradeRemovesObsoleteTrackedFiles() {
    QTemporaryDir temp(temporaryDirectoryTemplate());
    require(temp.isValid(), QStringLiteral("temporary directory unavailable"));
    const QString source = QDir(temp.path()).filePath(QStringLiteral("source"));
    const QString prefix = QDir(temp.path()).filePath(QStringLiteral("install"));
    ScopedAppStateEnvironment appState(QDir(temp.path()).filePath(QStringLiteral("app-state")));
    require(QDir().mkpath(source), QStringLiteral("could not create source root"));
    makeFakeCheckout(source);
    const Result installed = run(fakeInstallOptions(source, prefix));
    require(installed.exitCode == 0, installed.output.join('\n'));
    const QString oldLicense = installedLicensePath(prefix);
    require(QFileInfo::exists(oldLicense), QStringLiteral("license was not installed in test fixture"));

    require(QFile::remove(QDir(source).filePath(QStringLiteral("LICENSE"))),
            QStringLiteral("could not remove license from fake source checkout"));
    const Result updated = run(fakeInstallOptions(source, prefix));
    require(updated.exitCode == 0, updated.output.join('\n'));
    require(!QFileInfo::exists(oldLicense), QStringLiteral("upgrade left an obsolete tracked license behind"));

    Options verifyOptions;
    verifyOptions.action = Action::Verify;
    verifyOptions.prefix = prefix;
    const Result verified = run(verifyOptions);
    require(verified.exitCode == 0, verified.output.join('\n'));

    Options uninstallOptions;
    uninstallOptions.action = Action::Uninstall;
    uninstallOptions.prefix = prefix;
    uninstallOptions.assumeYes = true;
    const Result removed = run(uninstallOptions);
    require(removed.exitCode == 0, removed.output.join('\n'));
}

#if defined(Q_OS_LINUX)
void testUpgradeCommitFailureRollsBackFilesAndManifest() {
    QTemporaryDir temp(temporaryDirectoryTemplate());
    require(temp.isValid(), QStringLiteral("temporary directory unavailable"));
    ScopedAppStateEnvironment appState(QDir(temp.path()).filePath(QStringLiteral("app-state")));
    const QString source = QDir(temp.path()).filePath(QStringLiteral("source"));
    const QString prefix = QDir(temp.path()).filePath(QStringLiteral("install"));
    require(QDir().mkpath(source), QStringLiteral("could not create source root"));
    makeFakeCheckout(source);

    const Result installed = run(fakeInstallOptions(source, prefix));
    require(installed.exitCode == 0, installed.output.join('\n'));

    const QString cli = installedCliPath(prefix);
    const QString gui = QDir(QFileInfo(cli).path()).filePath(QStringLiteral("vpngate-gui"));
    const QString desktop = QDir(prefix).filePath(QStringLiteral("share/applications/vpngate-gui.desktop"));
    const QString manifestPath = manifestPathForPrefix(prefix);
    const QByteArray originalCli = readFile(cli);
    const QByteArray originalGui = readFile(gui);
    const QByteArray originalDesktop = readFile(desktop);
    const QByteArray originalManifest = readFile(manifestPath);

    writeFile(QDir(source).filePath(QStringLiteral("assets/icons/hicolor/32x32/apps/vpngate.png")),
              QByteArrayLiteral("new-icon"));
    writeFile(QDir(source).filePath(QStringLiteral("target/release/vpngate")), QByteArrayLiteral("upgraded-cli"));
    writeFile(QDir(source).filePath(QStringLiteral("target/release/vpngate-gui")), QByteArrayLiteral("upgraded-gui"));

    const QString blockingFile = QDir(prefix).filePath(QStringLiteral("share/icons/hicolor/32x32"));
    bool injectedFailure = false;
    Options upgrade = fakeInstallOptions(source, prefix);
    upgrade.progress = [&](int, int, const QString &phase) {
        if (!injectedFailure
            && phase == QStringLiteral("Committing share/icons/hicolor/32x32/apps/vpngate.png")) {
            writeFile(blockingFile, QByteArrayLiteral("unowned path obstruction"));
            injectedFailure = true;
        }
    };
    const Result rejected = run(upgrade);
    const QString transcript = rejected.output.join('\n');
    require(injectedFailure, QStringLiteral("commit-failure injection did not run"));
    require(rejected.exitCode != 0 && transcript.contains(QStringLiteral("Install transaction rolled back")),
            QStringLiteral("upgrade did not report a rolled-back commit failure: %1").arg(transcript));
    require(readFile(cli) == originalCli, QStringLiteral("failed upgrade did not restore the original CLI"));
    require(readFile(gui) == originalGui, QStringLiteral("failed upgrade did not restore the original GUI"));
    require(readFile(desktop) == originalDesktop, QStringLiteral("failed upgrade did not restore the original desktop entry"));
    require(readFile(manifestPath) == originalManifest, QStringLiteral("failed upgrade changed the install manifest"));
    require(QFileInfo::exists(blockingFile), QStringLiteral("rollback removed the unrelated injected obstruction"));

    require(QFile::remove(blockingFile), QStringLiteral("could not remove the injected obstruction"));
    Options verify;
    verify.action = Action::Verify;
    verify.prefix = prefix;
    const Result verified = run(verify);
    require(verified.exitCode == 0, verified.output.join('\n'));

    Options uninstall;
    uninstall.action = Action::Uninstall;
    uninstall.prefix = prefix;
    uninstall.assumeYes = true;
    const Result removed = run(uninstall);
    require(removed.exitCode == 0, removed.output.join('\n'));
}
#endif

void testStateCleanupFailureKeepsRetryInventory() {
    QTemporaryDir temp(temporaryDirectoryTemplate());
    require(temp.isValid(), QStringLiteral("temporary directory unavailable"));
    ScopedAppStateEnvironment appState(QDir(temp.path()).filePath(QStringLiteral("app-state")));
    const QString source = QDir(temp.path()).filePath(QStringLiteral("source"));
    const QString prefix = QDir(temp.path()).filePath(QStringLiteral("install"));
    require(QDir().mkpath(source), QStringLiteral("could not create source root"));
    makeFakeCheckout(source);
    const Result installed = run(fakeInstallOptions(source, prefix));
    require(installed.exitCode == 0, installed.output.join('\n'));

#if defined(Q_OS_LINUX)
    const QString stateHome = appState.cacheHome();
#elif defined(Q_OS_WIN)
    const QString stateHome = appState.localAppData();
#else
    const QString stateHome = QDir(appState.home()).filePath(QStringLiteral("Library/Caches"));
#endif
    const QString appStatePath = QDir(stateHome).filePath(QStringLiteral("vpngate"));
    writeFile(appStatePath, QByteArrayLiteral("not a directory"));

    Options uninstallOptions;
    uninstallOptions.action = Action::Uninstall;
    uninstallOptions.prefix = prefix;
    uninstallOptions.assumeYes = true;
    const Result incomplete = run(uninstallOptions);
    require(incomplete.exitCode != 0, QStringLiteral("uninstaller should report a non-directory app-state conflict"));
    require(QFileInfo::exists(manifestPathForPrefix(prefix)),
            QStringLiteral("manifest was discarded after app-state cleanup failed"));
    require(!QFileInfo::exists(installedCliPath(prefix)),
            QStringLiteral("tracked client files were not removed before state cleanup retry"));

    require(QFile::remove(appStatePath), QStringLiteral("could not remove the simulated app-state conflict"));
    writeFile(QDir(appStatePath).filePath(QStringLiteral("cache.bin")), QByteArrayLiteral("state"));
    const Result retry = run(uninstallOptions);
    require(retry.exitCode == 0, retry.output.join('\n'));
    require(!QFileInfo::exists(manifestPathForPrefix(prefix)),
            QStringLiteral("manifest was not removed after successful cleanup retry"));
    require(!QFileInfo::exists(appStatePath), QStringLiteral("app state remained after successful cleanup retry"));
}

void testPathTraversalRejected() {
    QTemporaryDir temp(temporaryDirectoryTemplate());
    require(temp.isValid(), QStringLiteral("temporary directory unavailable"));
    const QString source = QDir(temp.path()).filePath(QStringLiteral("source"));
    const QString prefix = QDir(temp.path()).filePath(QStringLiteral("install"));
    ScopedAppStateEnvironment appState(QDir(temp.path()).filePath(QStringLiteral("app-state")));
    const QString outside = QDir(temp.path()).filePath(QStringLiteral("outside-vpngate"));
    require(QDir().mkpath(source), QStringLiteral("could not create source root"));
    makeFakeCheckout(source);
    writeFile(outside, QByteArrayLiteral("outside data"));
    const Result installed = run(fakeInstallOptions(source, prefix));
    require(installed.exitCode == 0, installed.output.join('\n'));

    QFile manifest(manifestPathForPrefix(prefix));
    require(manifest.open(QIODevice::ReadOnly), QStringLiteral("could not open manifest for test"));
    QJsonParseError parseError{};
    QJsonDocument document = QJsonDocument::fromJson(manifest.readAll(), &parseError);
    manifest.close();
    require(parseError.error == QJsonParseError::NoError && document.isObject(),
            QStringLiteral("could not parse installer manifest for test"));
    QJsonObject object = document.object();
    QJsonArray files = object.value(QStringLiteral("files")).toArray();
    require(!files.isEmpty(), QStringLiteral("test manifest has no entries"));
    QJsonObject first = files.first().toObject();
    first.insert(QStringLiteral("path"), QStringLiteral("../../outside-vpngate"));
    files[0] = first;
    object.insert(QStringLiteral("files"), files);
    require(manifest.open(QIODevice::WriteOnly | QIODevice::Truncate), QStringLiteral("could not alter test manifest"));
    manifest.write(QJsonDocument(object).toJson(QJsonDocument::Indented));
    manifest.close();

    Options uninstallOptions;
    uninstallOptions.action = Action::Uninstall;
    uninstallOptions.prefix = prefix;
    uninstallOptions.assumeYes = true;
    uninstallOptions.force = true;
    const Result rejected = run(uninstallOptions);
    require(rejected.exitCode != 0, QStringLiteral("uninstaller accepted path traversal in manifest"));
    require(readFile(outside) == QByteArrayLiteral("outside data"),
            QStringLiteral("uninstaller touched a file outside the install prefix"));
}

void testManifestCannotClaimUnrelatedFiles() {
    QTemporaryDir temp(temporaryDirectoryTemplate());
    require(temp.isValid(), QStringLiteral("temporary directory unavailable"));
    const QString source = QDir(temp.path()).filePath(QStringLiteral("source"));
    const QString prefix = QDir(temp.path()).filePath(QStringLiteral("install"));
    ScopedAppStateEnvironment appState(QDir(temp.path()).filePath(QStringLiteral("app-state")));
    require(QDir().mkpath(source), QStringLiteral("could not create source root"));
    makeFakeCheckout(source);
    const Result installed = run(fakeInstallOptions(source, prefix));
    require(installed.exitCode == 0, installed.output.join('\n'));

    const QString unrelated = QDir(prefix).filePath(QStringLiteral("user-notes.txt"));
    writeFile(unrelated, QByteArrayLiteral("must remain"));
    QFile manifest(manifestPathForPrefix(prefix));
    require(manifest.open(QIODevice::ReadOnly), QStringLiteral("could not open manifest for test"));
    QJsonParseError parseError{};
    QJsonDocument document = QJsonDocument::fromJson(manifest.readAll(), &parseError);
    manifest.close();
    require(parseError.error == QJsonParseError::NoError && document.isObject(),
            QStringLiteral("could not parse installer manifest for test"));
    QJsonObject object = document.object();
    QJsonArray files = object.value(QStringLiteral("files")).toArray();
    files.append(QJsonObject{
        {QStringLiteral("path"), QStringLiteral("user-notes.txt")},
        {QStringLiteral("sha256"), QString(64, QLatin1Char('0'))},
    });
    object.insert(QStringLiteral("files"), files);
    require(manifest.open(QIODevice::WriteOnly | QIODevice::Truncate), QStringLiteral("could not alter test manifest"));
    manifest.write(QJsonDocument(object).toJson(QJsonDocument::Indented));
    manifest.close();

    Options uninstallOptions;
    uninstallOptions.action = Action::Uninstall;
    uninstallOptions.prefix = prefix;
    uninstallOptions.assumeYes = true;
    uninstallOptions.force = true;
    const Result rejected = run(uninstallOptions);
    require(rejected.exitCode != 0, QStringLiteral("uninstaller trusted a manifest entry for unrelated user data"));
    require(readFile(unrelated) == QByteArrayLiteral("must remain"),
            QStringLiteral("uninstaller removed unrelated user data listed in a tampered manifest"));
}

} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    testFullWorkflowRequiresExplicitAuthorization();
    testNativeBinaryArchitectureValidation();
    testSourceArchiveEntryValidation();
#if defined(Q_OS_LINUX)
    testFullSystemDryRunPlansHostAndManifestFiles();
#elif defined(Q_OS_WIN)
    testWindowsHostDryRunUsesScopedInstallPaths();
#elif defined(Q_OS_MACOS)
    testMacSystemDryRunUsesNativeCommandLayout();
#endif
    testInstallVerifyUninstallPreservesUnrelatedData();
    testDryRunAndNoOverwrite();
    testModifiedFilesArePreservedUnlessForced();
    testUpgradeRemovesObsoleteTrackedFiles();
#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
    testCargoBuildUsesExplicitTargetAndTargetedOutputLayout();
#endif
#if defined(Q_OS_LINUX)
    testUpgradeCommitFailureRollsBackFilesAndManifest();
#endif
    testStateCleanupFailureKeepsRetryInventory();
    testPathTraversalRejected();
    testManifestCannotClaimUnrelatedFiles();
    QTextStream(stdout) << "All installer core tests passed." << Qt::endl;
    return 0;
}
