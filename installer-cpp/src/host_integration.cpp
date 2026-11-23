#include "host_integration.hpp"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QDirIterator>
#include <QProcess>
#include <QProcessEnvironment>
#include <QRegularExpression>
#include <QSet>
#include <QStandardPaths>

#include <algorithm>
#include <string>
#include <utility>

#if defined(Q_OS_WIN)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <objbase.h>
#include <ras.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <winsvc.h>
#elif defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
#include <csignal>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace vpngate::installer {
namespace {

struct CommandResult {
    bool started = false;
    int exitCode = -1;
    QString output;
    QString error;
};

QString quoteForLog(const QString &value) {
    if (value.contains(QRegularExpression(QStringLiteral("[\\s\\\"']")))) {
        QString quoted = value;
        quoted.replace(QLatin1Char('\\'), QStringLiteral("\\\\"));
        quoted.replace(QLatin1Char('"'), QStringLiteral("\\\""));
        return QStringLiteral("\"%1\"").arg(quoted);
    }
    return value;
}

QString commandForLog(const QString &program, const QStringList &arguments) {
    QStringList rendered{quoteForLog(program)};
    for (const QString &argument : arguments) {
        rendered.append(quoteForLog(argument));
    }
    return rendered.join(QLatin1Char(' '));
}

CommandResult runCommand(const QString &program, const QStringList &arguments,
                         const QProcessEnvironment &environment = QProcessEnvironment::systemEnvironment()) {
    CommandResult result;
    QProcess process;
    process.setProgram(program);
    process.setArguments(arguments);
    QProcessEnvironment effectiveEnvironment = environment;
    if (QFileInfo(program).fileName() == QStringLiteral("apt-get")) {
        effectiveEnvironment.insert(QStringLiteral("DEBIAN_FRONTEND"), QStringLiteral("noninteractive"));
    }
    process.setProcessEnvironment(effectiveEnvironment);
    process.setProcessChannelMode(QProcess::MergedChannels);
    process.start();
    if (!process.waitForStarted(10'000)) {
        result.error = process.errorString();
        return result;
    }
    result.started = true;
    QByteArray output;
    while (process.state() != QProcess::NotRunning) {
        process.waitForFinished(250);
        output.append(process.readAll());
    }
    output.append(process.readAll());
    result.exitCode = process.exitStatus() == QProcess::NormalExit ? process.exitCode() : -1;
    result.output = QString::fromLocal8Bit(output).trimmed();
    if (result.exitCode != 0) {
        result.error = result.output.isEmpty()
            ? QStringLiteral("process exited with code %1").arg(result.exitCode)
            : result.output;
    }
    return result;
}

#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
CommandResult runAsUser(const QString &user, const QString &program, const QStringList &arguments,
                        const QStringList &environmentEntries) {
    QString runner;
    QStringList runnerArguments;
#if defined(Q_OS_LINUX)
    runner = QStandardPaths::findExecutable(QStringLiteral("runuser"));
    if (runner.isEmpty()) {
        return {false, -1, {}, QStringLiteral("runuser is not available")};
    }
    runnerArguments = {QStringLiteral("-u"), user, QStringLiteral("--"), QStringLiteral("env")};
#elif defined(Q_OS_MACOS)
    runner = QStandardPaths::findExecutable(QStringLiteral("sudo"));
    if (runner.isEmpty()) {
        return {false, -1, {}, QStringLiteral("sudo is not available")};
    }
    runnerArguments = {QStringLiteral("-u"), user, QStringLiteral("env")};
#endif
    runnerArguments.append(environmentEntries);
    runnerArguments.append(program);
    runnerArguments.append(arguments);
    return runCommand(runner, runnerArguments);
}
#endif

#if defined(Q_OS_WIN)
QString findWindowsGcc() {
    QString gcc = QStandardPaths::findExecutable(QStringLiteral("gcc.exe"));
    if (!gcc.isEmpty()) {
        return gcc;
    }
    QStringList roots{
        QDir(qEnvironmentVariable("LOCALAPPDATA")).filePath(QStringLiteral("Microsoft/WinGet/Packages")),
        QStringLiteral("C:/msys64/ucrt64/bin"), QStringLiteral("C:/msys64/mingw64/bin"),
        QStringLiteral("C:/mingw64/bin"),
    };
    for (const QString &root : roots) {
        const QString direct = QDir(root).filePath(QStringLiteral("gcc.exe"));
        if (QFileInfo(direct).isFile()) {
            return direct;
        }
    }
    QDirIterator iterator(roots.first(), {QStringLiteral("gcc.exe")}, QDir::Files,
                          QDirIterator::Subdirectories);
    int visited = 0;
    while (iterator.hasNext() && visited++ < 20'000) {
        const QString candidate = iterator.next();
        if (QFileInfo(candidate).isFile()) {
            return candidate;
        }
    }
    return {};
}

bool prepareWindowsMsvcEnvironment(const QString &architecture, QStringList *output) {
    if (!QStandardPaths::findExecutable(QStringLiteral("cl.exe")).isEmpty()) {
        return true;
    }
    QString vswhere = QDir(qEnvironmentVariable("ProgramFiles(x86)"))
        .filePath(QStringLiteral("Microsoft Visual Studio/Installer/vswhere.exe"));
    if (!QFileInfo(vswhere).isFile()) {
        vswhere = QStandardPaths::findExecutable(QStringLiteral("vswhere.exe"));
    }
    if (vswhere.isEmpty()) {
        return false;
    }
    const QString component = architecture == QStringLiteral("arm64")
        ? QStringLiteral("Microsoft.VisualStudio.Component.VC.Tools.ARM64")
        : QStringLiteral("Microsoft.VisualStudio.Component.VC.Tools.x86.x64");
    const CommandResult location = runCommand(vswhere,
        {QStringLiteral("-latest"), QStringLiteral("-products"), QStringLiteral("*"),
         QStringLiteral("-requires"), component, QStringLiteral("-property"),
         QStringLiteral("installationPath")});
    if (!location.started || location.exitCode != 0 || location.output.isEmpty()) {
        return false;
    }
    const QString devCmd = QDir(location.output.trimmed()).filePath(QStringLiteral("Common7/Tools/VsDevCmd.bat"));
    if (!QFileInfo(devCmd).isFile()) {
        return false;
    }
    const QString commandProcessor = QStandardPaths::findExecutable(QStringLiteral("cmd.exe"));
    if (commandProcessor.isEmpty()) {
        return false;
    }
    const QString command = QStringLiteral("call \"%1\" -no_logo -arch=%2 -host_arch=%2 && set")
                               .arg(devCmd, architecture);
    const CommandResult environment = runCommand(commandProcessor,
        {QStringLiteral("/d"), QStringLiteral("/s"), QStringLiteral("/c"), command});
    if (!environment.started || environment.exitCode != 0) {
        if (output && !environment.error.isEmpty()) {
            output->append(QStringLiteral("[warn] Visual Studio environment setup failed: %1").arg(environment.error));
        }
        return false;
    }
    for (const QString &line : environment.output.split(QRegularExpression(QStringLiteral("[\\r\\n]+")), Qt::SkipEmptyParts)) {
        const qsizetype separator = line.indexOf(QLatin1Char('='));
        if (separator <= 0) {
            continue;
        }
        const QByteArray name = line.left(separator).toLocal8Bit();
        const QByteArray value = line.mid(separator + 1).toLocal8Bit();
        qputenv(name.constData(), value);
    }
    return !QStandardPaths::findExecutable(QStringLiteral("cl.exe")).isEmpty();
}

bool isWindowsAdmin() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    TOKEN_ELEVATION elevation{};
    DWORD returned = 0;
    const BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &returned);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

bool registryReadDword(HKEY root, const QString &subkey, const QString &name,
                       DWORD *value, bool *exists) {
    if (exists) {
        *exists = false;
    }
    HKEY key = nullptr;
    const LONG opened = RegOpenKeyExW(root, reinterpret_cast<LPCWSTR>(subkey.utf16()), 0,
                                      KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key);
    if (opened == ERROR_FILE_NOT_FOUND) {
        return true;
    }
    if (opened != ERROR_SUCCESS) {
        return false;
    }
    DWORD type = 0;
    DWORD bytes = sizeof(DWORD);
    DWORD current = 0;
    const LONG queried = RegQueryValueExW(key, reinterpret_cast<LPCWSTR>(name.utf16()), nullptr,
                                          &type, reinterpret_cast<LPBYTE>(&current), &bytes);
    RegCloseKey(key);
    if (queried == ERROR_FILE_NOT_FOUND) {
        return true;
    }
    if (queried != ERROR_SUCCESS || type != REG_DWORD || bytes != sizeof(DWORD)) {
        return false;
    }
    if (value) {
        *value = current;
    }
    if (exists) {
        *exists = true;
    }
    return true;
}

bool registrySetDword(HKEY root, const QString &subkey, const QString &name, DWORD value) {
    HKEY key = nullptr;
    DWORD disposition = 0;
    const LONG created = RegCreateKeyExW(root, reinterpret_cast<LPCWSTR>(subkey.utf16()), 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &key, &disposition);
    Q_UNUSED(disposition);
    if (created != ERROR_SUCCESS) {
        return false;
    }
    const LONG written = RegSetValueExW(key, reinterpret_cast<LPCWSTR>(name.utf16()), 0, REG_DWORD,
                                        reinterpret_cast<const BYTE *>(&value), sizeof(value));
    RegCloseKey(key);
    return written == ERROR_SUCCESS;
}

bool registryDeleteValue(HKEY root, const QString &subkey, const QString &name) {
    HKEY key = nullptr;
    const LONG opened = RegOpenKeyExW(root, reinterpret_cast<LPCWSTR>(subkey.utf16()), 0,
                                      KEY_SET_VALUE | KEY_WOW64_64KEY, &key);
    if (opened == ERROR_FILE_NOT_FOUND) {
        return true;
    }
    if (opened != ERROR_SUCCESS) {
        return false;
    }
    const LONG deleted = RegDeleteValueW(key, reinterpret_cast<LPCWSTR>(name.utf16()));
    RegCloseKey(key);
    return deleted == ERROR_SUCCESS || deleted == ERROR_FILE_NOT_FOUND;
}

bool registryCreateKey(HKEY root, const QString &subkey) {
    HKEY key = nullptr;
    DWORD disposition = 0;
    const LONG created = RegCreateKeyExW(root, reinterpret_cast<LPCWSTR>(subkey.utf16()), 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_CREATE_SUB_KEY | KEY_WOW64_64KEY, nullptr, &key, &disposition);
    Q_UNUSED(disposition);
    if (key) {
        RegCloseKey(key);
    }
    return created == ERROR_SUCCESS;
}

bool registryReadString(HKEY root, const QString &subkey, const QString &name,
                        QString *value, DWORD *typeOut = nullptr, bool *exists = nullptr) {
    if (exists) {
        *exists = false;
    }
    HKEY key = nullptr;
    const LONG opened = RegOpenKeyExW(root, reinterpret_cast<LPCWSTR>(subkey.utf16()), 0,
                                      KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key);
    if (opened == ERROR_FILE_NOT_FOUND) {
        return true;
    }
    if (opened != ERROR_SUCCESS) {
        return false;
    }
    DWORD type = 0;
    DWORD bytes = 0;
    LONG queried = RegQueryValueExW(key, reinterpret_cast<LPCWSTR>(name.utf16()), nullptr,
                                    &type, nullptr, &bytes);
    if (queried == ERROR_FILE_NOT_FOUND) {
        RegCloseKey(key);
        return true;
    }
    if (queried != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
        RegCloseKey(key);
        return false;
    }
    QByteArray storage(static_cast<qsizetype>(bytes) + static_cast<qsizetype>(sizeof(wchar_t)), '\0');
    queried = RegQueryValueExW(key, reinterpret_cast<LPCWSTR>(name.utf16()), nullptr,
                               &type, reinterpret_cast<LPBYTE>(storage.data()), &bytes);
    RegCloseKey(key);
    if (queried != ERROR_SUCCESS) {
        return false;
    }
    if (value) {
        *value = QString::fromWCharArray(reinterpret_cast<const wchar_t *>(storage.constData()));
    }
    if (typeOut) {
        *typeOut = type;
    }
    if (exists) {
        *exists = true;
    }
    return true;
}

bool registryWriteString(HKEY root, const QString &subkey, const QString &name,
                         const QString &value, DWORD type) {
    HKEY key = nullptr;
    DWORD disposition = 0;
    const LONG created = RegCreateKeyExW(root, reinterpret_cast<LPCWSTR>(subkey.utf16()), 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &key, &disposition);
    Q_UNUSED(disposition);
    if (created != ERROR_SUCCESS) {
        return false;
    }
    const std::wstring wide = value.toStdWString();
    const DWORD bytes = static_cast<DWORD>((wide.size() + 1) * sizeof(wchar_t));
    const LONG written = RegSetValueExW(key, reinterpret_cast<LPCWSTR>(name.utf16()), 0, type,
                                        reinterpret_cast<const BYTE *>(wide.c_str()), bytes);
    RegCloseKey(key);
    return written == ERROR_SUCCESS;
}

QString normalizeWindowsPathEntry(QString entry) {
    entry = QDir::toNativeSeparators(QDir::cleanPath(entry.trimmed()));
    while (entry.size() > 3 && (entry.endsWith(QLatin1Char('\\')) || entry.endsWith(QLatin1Char('/')))) {
        entry.chop(1);
    }
    return entry;
}

bool updateWindowsUserPath(const QString &prefix, bool add, bool dryRun, QStringList *output) {
    static const QString key = QStringLiteral("Environment");
    QString existing;
    DWORD valueType = REG_EXPAND_SZ;
    bool present = false;
    if (!registryReadString(HKEY_CURRENT_USER, key, QStringLiteral("Path"), &existing, &valueType, &present)) {
        output->append(QStringLiteral("[warn] Could not read the current user's PATH registry value."));
        return false;
    }
    const QString normalizedPrefix = normalizeWindowsPathEntry(prefix);
    QStringList entries = existing.split(QLatin1Char(';'), Qt::SkipEmptyParts);
    QStringList filtered;
    bool found = false;
    for (const QString &entry : entries) {
        if (normalizeWindowsPathEntry(entry).compare(normalizedPrefix, Qt::CaseInsensitive) == 0) {
            if (add) {
                if (!found) {
                    filtered.append(normalizedPrefix);
                    found = true;
                }
            } else {
                found = true;
            }
        } else {
            filtered.append(entry.trimmed());
        }
    }
    if (add && !found) {
        filtered.append(normalizedPrefix);
    }
    if ((!add && !found) || (add && found && filtered.join(QLatin1Char(';')) == existing)) {
        output->append(add ? QStringLiteral("[ok] Install directory is already present in the current user's PATH.")
                           : QStringLiteral("[ok] Install directory was not present in the current user's PATH."));
        return true;
    }
    const QString updated = filtered.join(QLatin1Char(';'));
    if (dryRun) {
        output->append(QStringLiteral("[plan] %1 %2 %3 the current user's PATH registry value.")
                           .arg(add ? QStringLiteral("Add") : QStringLiteral("Remove"), normalizedPrefix,
                                add ? QStringLiteral("to") : QStringLiteral("from")));
        return true;
    }
    if (!registryWriteString(HKEY_CURRENT_USER, key, QStringLiteral("Path"), updated,
                             present && valueType == REG_SZ ? REG_SZ : REG_EXPAND_SZ)) {
        output->append(QStringLiteral("[warn] Could not update the current user's PATH registry value."));
        return false;
    }
    DWORD_PTR ignored = 0;
    SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
        reinterpret_cast<LPARAM>(L"Environment"), SMTO_ABORTIFHUNG, 5000, &ignored);
    output->append(add ? QStringLiteral("[ok] Added the install directory to the current user's PATH.")
                       : QStringLiteral("[ok] Removed the install directory from the current user's PATH."));
    return true;
}

QString windowsStartMenuLink(const Options &options) {
    QString programs;
    if (!options.targetHome.isEmpty()) {
        programs = QDir(options.targetHome).filePath(
            QStringLiteral("AppData/Roaming/Microsoft/Windows/Start Menu/Programs"));
    } else {
        programs = QStandardPaths::writableLocation(QStandardPaths::ApplicationsLocation);
    }
    if (programs.isEmpty()) {
        return {};
    }
    return QDir(programs).filePath(QStringLiteral("VPN Gate Connect.lnk"));
}

bool createWindowsShortcut(const Options &options, QStringList *output) {
    const QString linkPath = windowsStartMenuLink(options);
    const QString target = QDir(options.prefix.isEmpty() ? systemInstallPrefix() : options.prefix)
                               .filePath(QStringLiteral("vpngate-gui.exe"));
    if (linkPath.isEmpty()) {
        output->append(QStringLiteral("[warn] Could not locate the current user's Start Menu Programs folder."));
        return false;
    }
    if (options.dryRun) {
        output->append(QStringLiteral("[plan] Create the native GUI Start Menu shortcut: %1 -> %2")
                           .arg(linkPath, target));
        return true;
    }
    if (!QDir().mkpath(QFileInfo(linkPath).path())) {
        output->append(QStringLiteral("[warn] Could not create the Start Menu Programs directory."));
        return false;
    }
    const HRESULT initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool uninitialize = SUCCEEDED(initialized);
    if (FAILED(initialized) && initialized != RPC_E_CHANGED_MODE) {
        output->append(QStringLiteral("[warn] Could not initialize COM for Start Menu shortcut creation."));
        return false;
    }
    IShellLinkW *shellLink = nullptr;
    HRESULT status = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER,
                                      IID_IShellLinkW, reinterpret_cast<void **>(&shellLink));
    if (SUCCEEDED(status)) {
        shellLink->SetPath(reinterpret_cast<LPCWSTR>(target.utf16()));
        const QString workingDirectory = QFileInfo(target).path();
        shellLink->SetWorkingDirectory(reinterpret_cast<LPCWSTR>(workingDirectory.utf16()));
        shellLink->SetDescription(L"VPN Gate Connect");
        const QString icon = QDir(options.prefix.isEmpty() ? systemInstallPrefix() : options.prefix)
                                 .filePath(QStringLiteral("vpngate.ico"));
        if (QFileInfo(icon).isFile()) {
            shellLink->SetIconLocation(reinterpret_cast<LPCWSTR>(icon.utf16()), 0);
        }
        IPersistFile *persist = nullptr;
        status = shellLink->QueryInterface(IID_IPersistFile, reinterpret_cast<void **>(&persist));
        if (SUCCEEDED(status)) {
            status = persist->Save(reinterpret_cast<LPCWSTR>(linkPath.utf16()), TRUE);
            persist->Release();
        }
        shellLink->Release();
    }
    if (uninitialize) {
        CoUninitialize();
    }
    if (FAILED(status)) {
        output->append(QStringLiteral("[warn] Could not create the native GUI Start Menu shortcut (HRESULT 0x%1).")
                           .arg(static_cast<qulonglong>(status), 0, 16));
        return false;
    }
    output->append(QStringLiteral("[ok] Created native GUI Start Menu shortcut: %1").arg(linkPath));
    return true;
}

void removeWindowsShortcuts(const Options &options, QStringList *output) {
    QStringList paths;
    const QString primary = windowsStartMenuLink(options);
    if (!primary.isEmpty()) {
        paths.append(primary);
        paths.append(QDir(QFileInfo(primary).path()).filePath(QStringLiteral("VPN Gate Connect GUI.lnk")));
        paths.append(QDir(QFileInfo(primary).path()).filePath(QStringLiteral("VPN Gate.lnk")));
    }
    for (const QString &path : paths) {
        const QFileInfo info(path);
        if (!info.exists() && !info.isSymLink()) {
            continue;
        }
        if (options.dryRun) {
            output->append(QStringLiteral("[plan] Remove VPN Gate Start Menu shortcut: %1").arg(path));
        } else if (QFile::remove(path)) {
            output->append(QStringLiteral("[ok] Removed VPN Gate Start Menu shortcut: %1").arg(path));
        } else {
            output->append(QStringLiteral("[warn] Could not remove VPN Gate Start Menu shortcut: %1").arg(path));
        }
    }
}
#endif

bool runRequired(const Options &options, const QString &program, const QStringList &arguments,
                 QStringList *output, const QString &description) {
    if (options.dryRun) {
        output->append(QStringLiteral("[plan] %1: %2")
                           .arg(description, commandForLog(program, arguments)));
        return true;
    }
    const QString executable = QStandardPaths::findExecutable(program);
    if (executable.isEmpty()) {
        output->append(QStringLiteral("[error] Required command was not found: %1").arg(program));
        return false;
    }
    output->append(QStringLiteral("[*] %1").arg(description));
    const CommandResult result = runCommand(executable, arguments);
    if (!result.output.isEmpty()) {
        output->append(result.output.split(QLatin1Char('\n')));
    }
    if (!result.started || result.exitCode != 0) {
        output->append(QStringLiteral("[error] %1 failed: %2")
                           .arg(description, result.error.isEmpty() ? QStringLiteral("could not start command") : result.error));
        return false;
    }
    return true;
}

void runOptional(const Options &options, const QString &program, const QStringList &arguments,
                 QStringList *output, const QString &description) {
    if (options.dryRun) {
        output->append(QStringLiteral("[plan] %1: %2")
                           .arg(description, commandForLog(program, arguments)));
        return;
    }
    const QString executable = QStandardPaths::findExecutable(program);
    if (executable.isEmpty()) {
        output->append(QStringLiteral("[skip] %1 (optional command %2 is not installed).")
                           .arg(description, program));
        return;
    }
    const CommandResult result = runCommand(executable, arguments);
    if (result.started && result.exitCode == 0) {
        if (!result.output.isEmpty()) {
            output->append(result.output.split(QLatin1Char('\n')));
        }
    } else {
        output->append(QStringLiteral("[warn] %1 did not complete: %2")
                           .arg(description, result.error.isEmpty() ? QStringLiteral("could not start command") : result.error));
    }
}

QString targetHome(const Options &options) {
    if (!options.targetHome.isEmpty() && QDir::isAbsolutePath(options.targetHome)) {
        return QDir::cleanPath(options.targetHome);
    }
#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
    const QString sudoUser = qEnvironmentVariable("SUDO_USER");
    if (!sudoUser.isEmpty()) {
        const QByteArray name = sudoUser.toLocal8Bit();
        if (const passwd *entry = getpwnam(name.constData())) {
            const QString home = QFile::decodeName(entry->pw_dir);
            if (QDir::isAbsolutePath(home)) {
                return QDir::cleanPath(home);
            }
        }
    }
#endif
    return QDir::homePath();
}

QString cacheDirectory(const Options &options) {
    if (!options.cacheDir.isEmpty() && QDir::isAbsolutePath(options.cacheDir)) {
        return QDir::cleanPath(options.cacheDir);
    }
#if defined(Q_OS_WIN)
    QString localAppData = qEnvironmentVariable("LOCALAPPDATA");
    if (!options.targetHome.isEmpty()) {
        localAppData = QDir(targetHome(options)).filePath(QStringLiteral("AppData/Local"));
    }
    if (localAppData.isEmpty() || !QDir::isAbsolutePath(localAppData) || QDir(localAppData).isRoot()) {
        localAppData = QDir(targetHome(options)).filePath(QStringLiteral("AppData/Local"));
    }
    return QDir(localAppData).filePath(QStringLiteral("vpngate"));
#elif defined(Q_OS_MACOS)
    return QDir(targetHome(options)).filePath(QStringLiteral("Library/Caches/vpngate"));
#else
    return QDir(targetHome(options)).filePath(QStringLiteral(".cache/vpngate"));
#endif
}

#if defined(Q_OS_MACOS)
CommandResult runForTargetUser(const Options &options, const QString &program,
                               const QStringList &arguments,
                               const QStringList &additionalEnvironment = {}) {
    const QString sudoUser = qEnvironmentVariable("SUDO_USER").trimmed();
    if (::geteuid() == 0 && !sudoUser.isEmpty() && sudoUser != QStringLiteral("root")) {
        QStringList environment{QStringLiteral("HOME=%1").arg(targetHome(options))};
        environment.append(additionalEnvironment);
        return runAsUser(sudoUser, program, arguments, environment);
    }
    return runCommand(program, arguments);
}
#endif

bool removeKnownPath(const Options &options, const QString &path, QStringList *output,
                     const QString &description, bool recursive = false) {
    const QFileInfo info(path);
    if (!info.exists() && !info.isSymLink()) {
        return true;
    }
    if (options.dryRun) {
        output->append(QStringLiteral("[plan] Remove %1: %2").arg(description, path));
        return true;
    }
    bool removed = false;
    if (info.isSymLink() || info.isFile()) {
        removed = QFile::remove(path);
    } else if (info.isDir() && recursive) {
        removed = QDir(path).removeRecursively();
    }
    if (removed) {
        output->append(QStringLiteral("[ok] Removed %1: %2").arg(description, path));
        return true;
    }
    output->append(QStringLiteral("[warn] Could not remove %1: %2").arg(description, path));
    return false;
}

void cleanupTransientCache(const Options &options, const QString &directory, QStringList *output) {
    const QFileInfo info(directory);
    if (!info.isDir() || info.isSymLink()) {
        return;
    }
    static const QStringList fixedNames{
        QStringLiteral("active_state.json"), QStringLiteral("ikev1_state.json"),
        QStringLiteral("ikev1.pid"), QStringLiteral("openvpn.pid"),
        QStringLiteral("monitor.pid"), QStringLiteral("l2tp_route.json"),
        QStringLiteral("resolv.conf.bak"), QStringLiteral("ui_socks"),
        QStringLiteral("ui-control.json"), QStringLiteral("ui-control.json.lock"),
        QStringLiteral("ui-observer.log"),
    };
    for (const QString &name : fixedNames) {
        removeKnownPath(options, QDir(directory).filePath(name), output,
                        QStringLiteral("known VPN Gate cache file"));
    }
    if (options.dryRun) {
        output->append(QStringLiteral("[plan] Remove top-level VPN Gate *.ovpn, *.tmp, and *.bak files in %1").arg(directory));
        return;
    }
    QDir cache(directory);
    const QFileInfoList files = cache.entryInfoList(
        {QStringLiteral("*.ovpn"), QStringLiteral("*.tmp"), QStringLiteral("*.bak")},
        QDir::Files | QDir::Hidden | QDir::NoDotAndDotDot);
    for (const QFileInfo &file : files) {
        if (file.isSymLink()) {
            QFile::remove(file.filePath());
        } else if (file.isFile()) {
            QFile::remove(file.filePath());
        }
    }
}

#if defined(Q_OS_LINUX)
QSet<qint64> protectedProcessIds() {
    QSet<qint64> protectedIds;
    qint64 current = QCoreApplication::applicationPid();
    for (int hops = 0; current > 1 && hops < 64; ++hops) {
        if (protectedIds.contains(current)) {
            break;
        }
        protectedIds.insert(current);
        QFile status(QStringLiteral("/proc/%1/status").arg(current));
        if (!status.open(QIODevice::ReadOnly)) {
            break;
        }
        const QString text = QString::fromLatin1(status.readAll());
        const QRegularExpression re(QStringLiteral("(?:^|\\n)PPid:\\s*(\\d+)"));
        const QRegularExpressionMatch match = re.match(text);
        if (!match.hasMatch()) {
            break;
        }
        bool ok = false;
        const qint64 parent = match.captured(1).toLongLong(&ok);
        if (!ok || parent == current) {
            break;
        }
        current = parent;
    }
    return protectedIds;
}

QStringList productProcesses() {
    QStringList matches;
    const QSet<qint64> protectedIds = protectedProcessIds();
    const QFileInfo selfInfo(QCoreApplication::applicationFilePath());
    const QString selfName = selfInfo.fileName();
    const QDir proc(QStringLiteral("/proc"));
    const QStringList entries = proc.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (const QString &entry : entries) {
        bool pidOk = false;
        const qint64 pid = entry.toLongLong(&pidOk);
        if (!pidOk || protectedIds.contains(pid)) {
            continue;
        }
        QFile commandFile(proc.filePath(entry + QStringLiteral("/cmdline")));
        if (!commandFile.open(QIODevice::ReadOnly)) {
            continue;
        }
        QByteArray raw = commandFile.readAll();
        if (raw.isEmpty()) {
            continue;
        }
        raw.replace('\0', ' ');
        const QString command = QString::fromLocal8Bit(raw).trimmed();
        if (command.isEmpty() || command.contains(QStringLiteral("install-vpngate"), Qt::CaseInsensitive)
            || command.contains(selfName, Qt::CaseInsensitive)) {
            continue;
        }
        const QString executable = command.section(QLatin1Char(' '), 0, 0);
        const QString base = QFileInfo(executable).fileName();
        bool productProcess = command.contains(QStringLiteral("vpngate-launcher"), Qt::CaseInsensitive);
        if (!productProcess && (command.contains(QStringLiteral(" _monitor "))
                               || command.contains(QStringLiteral(" _ikev1 ")))
            && command.contains(QStringLiteral("vpngate"), Qt::CaseInsensitive)) {
            productProcess = true;
        }
        if (!productProcess && base == QStringLiteral("openvpn")
            && (command.contains(QStringLiteral("vpngate-")) || command.contains(QStringLiteral("/vpngate/")))) {
            productProcess = true;
        }
        if (!productProcess && (base == QStringLiteral("xl2tpd") || base == QStringLiteral("pppd"))
            && command.contains(QStringLiteral("/run/vpngate-l2tp"))) {
            productProcess = true;
        }
        if (productProcess) {
            matches.append(QStringLiteral("%1\t%2").arg(pid).arg(command));
        }
    }
    return matches;
}

void stopProductProcesses(const Options &options, QStringList *output) {
    const QStringList processes = productProcesses();
    if (processes.isEmpty()) {
        output->append(QStringLiteral("[ok] No matching orphaned VPN Gate processes were found."));
        return;
    }
    for (const QString &record : processes) {
        const QStringList fields = record.split(QLatin1Char('\t'), Qt::KeepEmptyParts);
        if (fields.size() < 2) {
            continue;
        }
        const qint64 pid = fields[0].toLongLong();
        if (options.dryRun) {
            output->append(QStringLiteral("[plan] Stop product-specific process PID %1: %2").arg(pid).arg(fields.mid(1).join(QLatin1Char('\t'))));
            continue;
        }
        if (::kill(static_cast<pid_t>(pid), SIGTERM) == 0) {
            output->append(QStringLiteral("[ok] Sent TERM to VPN Gate process PID %1.").arg(pid));
        }
    }
    if (options.dryRun) {
        return;
    }
    QProcess::execute(QStringLiteral("/bin/sleep"), {QStringLiteral("1")});
    for (const QString &record : processes) {
        const QStringList fields = record.split(QLatin1Char('\t'), Qt::KeepEmptyParts);
        if (fields.size() < 2) {
            continue;
        }
        const qint64 pid = fields[0].toLongLong();
        QFile commandFile(QStringLiteral("/proc/%1/cmdline").arg(pid));
        if (!commandFile.open(QIODevice::ReadOnly)) {
            continue;
        }
        QByteArray raw = commandFile.readAll();
        raw.replace('\0', ' ');
        const QString currentCommand = QString::fromLocal8Bit(raw).trimmed();
        if (currentCommand != fields.mid(1).join(QLatin1Char('\t'))) {
            continue; // PID exited or was reused; do not signal an unrelated process.
        }
        if (::kill(static_cast<pid_t>(pid), SIGKILL) == 0) {
            output->append(QStringLiteral("[ok] Force-stopped remaining VPN Gate process PID %1.").arg(pid));
        }
    }
}

QString decodeNmcliField(const QString &value) {
    QString decoded;
    bool escaped = false;
    for (const QChar ch : value) {
        if (escaped) {
            decoded.append(ch);
            escaped = false;
        } else if (ch == QLatin1Char('\\')) {
            escaped = true;
        } else {
            decoded.append(ch);
        }
    }
    if (escaped) {
        decoded.append(QLatin1Char('\\'));
    }
    return decoded;
}

void removeNetworkManagerProfiles(const Options &options, QStringList *output) {
    if (options.dryRun) {
        output->append(QStringLiteral("[plan] Find NetworkManager profiles named vpngate-*; disconnect and delete only those profiles."));
        return;
    }
    const QString nmcli = QStandardPaths::findExecutable(QStringLiteral("nmcli"));
    if (nmcli.isEmpty()) {
        return;
    }
    const CommandResult listed = runCommand(nmcli, {QStringLiteral("-t"), QStringLiteral("-f"),
        QStringLiteral("UUID,NAME,TYPE"), QStringLiteral("connection"), QStringLiteral("show")});
    if (!listed.started || listed.exitCode != 0) {
        return;
    }
    const QStringList lines = listed.output.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    for (const QString &line : lines) {
        QStringList fields;
        QString current;
        bool escaped = false;
        for (const QChar ch : line) {
            if (escaped) {
                current.append(QLatin1Char('\\'));
                current.append(ch);
                escaped = false;
            } else if (ch == QLatin1Char('\\')) {
                escaped = true;
            } else if (ch == QLatin1Char(':')) {
                fields.append(decodeNmcliField(current));
                current.clear();
            } else {
                current.append(ch);
            }
        }
        fields.append(decodeNmcliField(current));
        if (fields.size() < 2 || !fields[1].startsWith(QStringLiteral("vpngate-"))) {
            continue;
        }
        const QString uuid = fields[0];
        runOptional(options, QStringLiteral("nmcli"),
                    {QStringLiteral("--wait"), QStringLiteral("5"), QStringLiteral("connection"), QStringLiteral("down"),
                     QStringLiteral("uuid"), uuid}, output,
                    QStringLiteral("Disconnect NetworkManager profile %1").arg(fields[1]));
        runOptional(options, QStringLiteral("nmcli"),
                    {QStringLiteral("connection"), QStringLiteral("delete"), QStringLiteral("uuid"), uuid}, output,
                    QStringLiteral("Remove NetworkManager profile %1").arg(fields[1]));
    }
}

void clearXfrmAndNftables(const Options &options, QStringList *output) {
    if (options.dryRun) {
        output->append(QStringLiteral("[plan] If present, delete Linux XFRM policies with priority 1701 and ESP states with reqid 17010."));
        output->append(QStringLiteral("[plan] Remove only nftables input rules tagged vpngate-l2tp."));
        return;
    }
    const QString ip = QStandardPaths::findExecutable(QStringLiteral("ip"));
    if (!ip.isEmpty()) {
        const CommandResult policies = runCommand(ip, {QStringLiteral("xfrm"), QStringLiteral("policy")});
        if (policies.output.contains(QStringLiteral("priority 1701"))) {
            runOptional(options, QStringLiteral("ip"),
                        {QStringLiteral("xfrm"), QStringLiteral("policy"), QStringLiteral("deleteall"),
                         QStringLiteral("priority"), QStringLiteral("1701")}, output,
                        QStringLiteral("Clear VPN Gate XFRM policies (priority 1701)"));
        }
        const CommandResult states = runCommand(ip, {QStringLiteral("xfrm"), QStringLiteral("state")});
        if (states.output.contains(QStringLiteral("reqid 17010"))) {
            runOptional(options, QStringLiteral("ip"),
                        {QStringLiteral("xfrm"), QStringLiteral("state"), QStringLiteral("deleteall"),
                         QStringLiteral("reqid"), QStringLiteral("17010")}, output,
                        QStringLiteral("Clear VPN Gate ESP states (reqid 17010)"));
        }
    }
    const QString nft = QStandardPaths::findExecutable(QStringLiteral("nft"));
    if (!nft.isEmpty()) {
        const CommandResult rules = runCommand(nft, {QStringLiteral("-a"), QStringLiteral("list"),
            QStringLiteral("chain"), QStringLiteral("inet"), QStringLiteral("filter"), QStringLiteral("input")});
        const QRegularExpression handleRe(QStringLiteral("vpngate-l2tp[^\\n]*?handle\\s+(\\d+)"));
        auto matches = handleRe.globalMatch(rules.output);
        while (matches.hasNext()) {
            const QString handle = matches.next().captured(1);
            runOptional(options, QStringLiteral("nft"),
                        {QStringLiteral("delete"), QStringLiteral("rule"), QStringLiteral("inet"),
                         QStringLiteral("filter"), QStringLiteral("input"), QStringLiteral("handle"), handle},
                        output, QStringLiteral("Remove VPN Gate nftables rule handle %1").arg(handle));
        }
    }
}
#endif // Q_OS_LINUX

void cleanKnownResidues(const Options &options, QStringList *output) {
#if defined(Q_OS_LINUX)
    const QString cache = cacheDirectory(options);
    const QString rootCache = QStringLiteral("/root/.cache/vpngate");
    const QString cli = QStringLiteral("/usr/local/bin/vpngate");
    if (QFileInfo(cli).isExecutable() && !QFileInfo(cli).isSymLink()) {
        QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
        environment.insert(QStringLiteral("VPNGATE_CACHE_DIR"), cache);
        if (options.dryRun) {
            output->append(QStringLiteral("[plan] Disconnect active/stale VPN Gate session using %1 disconnect (cache %2).")
                               .arg(cli, cache));
        } else {
            QProcess process;
            process.setProgram(cli);
            process.setArguments({QStringLiteral("disconnect")});
            process.setProcessEnvironment(environment);
            process.setProcessChannelMode(QProcess::MergedChannels);
            process.start();
            if (process.waitForStarted(5000)) {
                process.waitForFinished(-1);
                output->append(QStringLiteral("[ok] Asked the installed VPN Gate CLI to disconnect any active session."));
            }
        }
    }
    stopProductProcesses(options, output);
    removeNetworkManagerProfiles(options, output);
    clearXfrmAndNftables(options, output);
    const QStringList legacyFiles{
        QStringLiteral("/usr/local/bin/vpngate.py"), QStringLiteral("/usr/local/bin/vpngate-launcher"),
        QStringLiteral("/usr/local/bin/vpngate-launcher.py"), QStringLiteral("/usr/share/applications/vpngate.desktop"),
        QStringLiteral("/usr/share/applications/vpngate-gui.desktop"),
        QStringLiteral("/root/.local/bin/vpngate"), QStringLiteral("/root/.local/bin/vpngate-gui"),
        QStringLiteral("/root/.local/bin/vpngate.py"), QStringLiteral("/root/.local/bin/vpngate-launcher"),
        QStringLiteral("/root/.local/bin/vpngate-launcher.py"),
        QStringLiteral("/root/.local/share/applications/vpngate.desktop"),
        QStringLiteral("/root/.local/share/applications/vpngate-gui.desktop"),
        QDir(targetHome(options)).filePath(QStringLiteral(".local/bin/vpngate")),
        QDir(targetHome(options)).filePath(QStringLiteral(".local/bin/vpngate-gui")),
        QDir(targetHome(options)).filePath(QStringLiteral(".local/bin/vpngate.py")),
        QDir(targetHome(options)).filePath(QStringLiteral(".local/bin/vpngate-launcher")),
        QDir(targetHome(options)).filePath(QStringLiteral(".local/bin/vpngate-launcher.py")),
        QDir(targetHome(options)).filePath(QStringLiteral(".local/share/applications/vpngate.desktop")),
        QDir(targetHome(options)).filePath(QStringLiteral(".local/share/applications/vpngate-gui.desktop")),
    };
    for (const QString &path : legacyFiles) {
        removeKnownPath(options, path, output, QStringLiteral("legacy VPN Gate artifact"));
    }
    removeKnownPath(options, QStringLiteral("/usr/share/icons/hicolor/scalable/apps/vpngate.svg"), output,
                    QStringLiteral("legacy VPN Gate icon"));
    removeKnownPath(options, QStringLiteral("/usr/share/pixmaps/vpngate.png"), output,
                    QStringLiteral("legacy VPN Gate icon"));
    for (const int size : {16, 24, 32, 48, 64, 128, 256, 512}) {
        removeKnownPath(options, QStringLiteral("/usr/share/icons/hicolor/%1x%1/apps/vpngate.png").arg(size),
                        output, QStringLiteral("legacy VPN Gate icon"));
    }
    if (options.action == Action::Install) {
        const QString prefix = options.prefix.isEmpty() ? systemInstallPrefix() : QDir::cleanPath(options.prefix);
        const QString manifest = manifestPathForPrefix(prefix);
        const QFileInfo manifestInfo(manifest);
        if (!manifestInfo.exists() && !manifestInfo.isSymLink()) {
            QStringList unmanagedProductFiles{
                QDir(prefix).filePath(QStringLiteral("bin/vpngate")),
                QDir(prefix).filePath(QStringLiteral("bin/vpngate-gui")),
                QDir(prefix).filePath(QStringLiteral("share/icons/hicolor/scalable/apps/vpngate.svg")),
                QDir(prefix).filePath(QStringLiteral("share/applications/vpngate-gui.desktop")),
                QDir(prefix).filePath(QStringLiteral("share/vpngate/LICENSE")),
            };
            for (const int size : {16, 24, 32, 48, 64, 128, 256, 512}) {
                unmanagedProductFiles.append(QDir(prefix).filePath(
                    QStringLiteral("share/icons/hicolor/%1x%1/apps/vpngate.png").arg(size)));
            }
            for (const QString &path : unmanagedProductFiles) {
                removeKnownPath(options, path, output, QStringLiteral("untracked legacy VPN Gate file"));
            }
        }
    }
    removeKnownPath(options, QStringLiteral("/usr/local/bin/__pycache__"), output,
                    QStringLiteral("legacy Python cache"), true);
    removeKnownPath(options, QStringLiteral("/run/vpngate-l2tp"), output,
                    QStringLiteral("stale VPN Gate runtime directory"), true);
    cleanupTransientCache(options, cache, output);
    cleanupTransientCache(options, rootCache, output);
#else
    Q_UNUSED(options);
    Q_UNUSED(output);
#endif
}

#if defined(Q_OS_MACOS)
void cleanMacOSResidues(const Options &options, QStringList *output) {
    const QString cache = cacheDirectory(options);
    const QString rootCache = QStringLiteral("/root/.cache/vpngate");
    const QString cli = QStringLiteral("/usr/local/bin/vpngate");
    const QStringList sessionMarkers{
        QStringLiteral("active_state.json"), QStringLiteral("openvpn.pid"),
        QStringLiteral("monitor.pid"), QStringLiteral("ikev1.pid"),
    };
    bool hasSession = QFileInfo(QStringLiteral("/run/vpngate-l2tp")).isDir();
    for (const QString &candidate : {cache, rootCache}) {
        for (const QString &marker : sessionMarkers) {
            if (QFileInfo(QDir(candidate).filePath(marker)).exists()) {
                hasSession = true;
            }
        }
    }
    const QFileInfo cliInfo(cli);
    if (cliInfo.isExecutable() && !cliInfo.isSymLink() && hasSession) {
        if (options.dryRun) {
            output->append(QStringLiteral("[plan] Disconnect active/stale VPN Gate session using %1 --cache-dir %2 disconnect.")
                               .arg(cli, cache));
        } else {
            const CommandResult disconnected = runForTargetUser(
                options, cli, {QStringLiteral("--cache-dir"), cache, QStringLiteral("disconnect")},
                {QStringLiteral("VPNGATE_CACHE_DIR=%1").arg(cache)});
            if (disconnected.started && disconnected.exitCode == 0) {
                output->append(QStringLiteral("[ok] Asked the installed VPN Gate CLI to disconnect any active session."));
            } else {
                output->append(QStringLiteral("[warn] VPN Gate disconnect command did not complete: %1")
                                   .arg(disconnected.error));
            }
        }
    } else if (options.dryRun) {
        output->append(QStringLiteral("[plan] Check for an active VPN Gate session and disconnect it before changing installed files."));
    }

    QStringList legacyFiles{
        QStringLiteral("/usr/local/bin/vpngate.py"), QStringLiteral("/usr/local/bin/vpngate.ps1"),
        QStringLiteral("/usr/local/bin/vpngate-launcher"), QStringLiteral("/usr/local/bin/vpngate-launcher.py"),
        QStringLiteral("/root/.local/bin/vpngate"), QStringLiteral("/root/.local/bin/vpngate-gui"),
        QStringLiteral("/root/.local/bin/vpngate.py"), QStringLiteral("/root/.local/bin/vpngate-launcher"),
        QStringLiteral("/root/.local/bin/vpngate-launcher.py"),
        QStringLiteral("/root/.local/share/applications/vpngate.desktop"),
        QStringLiteral("/root/.local/share/applications/vpngate-gui.desktop"),
        QDir(targetHome(options)).filePath(QStringLiteral(".local/bin/vpngate")),
        QDir(targetHome(options)).filePath(QStringLiteral(".local/bin/vpngate-gui")),
        QDir(targetHome(options)).filePath(QStringLiteral(".local/bin/vpngate.py")),
        QDir(targetHome(options)).filePath(QStringLiteral(".local/bin/vpngate-launcher")),
        QDir(targetHome(options)).filePath(QStringLiteral(".local/bin/vpngate-launcher.py")),
        QDir(targetHome(options)).filePath(QStringLiteral(".local/share/applications/vpngate.desktop")),
        QDir(targetHome(options)).filePath(QStringLiteral(".local/share/applications/vpngate-gui.desktop")),
    };
    if (options.action == Action::Install) {
        legacyFiles.append(QDir(targetHome(options)).filePath(QStringLiteral(".cargo/bin/vpngate")));
    }
    for (const QString &path : legacyFiles) {
        removeKnownPath(options, path, output, QStringLiteral("legacy VPN Gate artifact"));
    }

    const QString prefix = options.prefix.isEmpty() ? systemInstallPrefix() : QDir::cleanPath(options.prefix);
    const QFileInfo manifestInfo(manifestPathForPrefix(prefix));
    if ((options.action == Action::Install || options.action == Action::Uninstall)
        && !manifestInfo.exists() && !manifestInfo.isSymLink()) {
        const QStringList unmanagedProductFiles{
            QDir(prefix).filePath(QStringLiteral("bin/vpngate")),
            QDir(prefix).filePath(QStringLiteral("bin/vpngate-gui")),
            QDir(prefix).filePath(QStringLiteral("share/vpngate/LICENSE")),
            QStringLiteral("/usr/local/bin/vpngate.py"),
            QStringLiteral("/usr/local/bin/vpngate-launcher"),
        };
        for (const QString &path : unmanagedProductFiles) {
            removeKnownPath(options, path, output, QStringLiteral("untracked legacy VPN Gate file"));
        }
    }

    if (options.action == Action::Uninstall) {
        const QStringList stateDirectories{
            cache, QDir(targetHome(options)).filePath(QStringLiteral("Library/Caches/vpngate")),
            QDir(targetHome(options)).filePath(QStringLiteral(".config/vpngate")),
            rootCache, QStringLiteral("/root/.config/vpngate"),
        };
        for (const QString &directory : stateDirectories) {
            removeKnownPath(options, directory, output, QStringLiteral("VPN Gate app state"), true);
        }
    } else {
        cleanupTransientCache(options, cache, output);
        cleanupTransientCache(options, rootCache, output);
    }
}
#endif

#if defined(Q_OS_WIN)
QString findOpenVpnExecutable() {
    const QStringList roots{
        qEnvironmentVariable("ProgramFiles"), qEnvironmentVariable("ProgramFiles(x86)"),
        qEnvironmentVariable("ProgramW6432"),
    };
    for (const QString &root : roots) {
        if (root.isEmpty()) {
            continue;
        }
        const QString candidate = QDir(root).filePath(QStringLiteral("OpenVPN/bin/openvpn.exe"));
        if (QFileInfo(candidate).isFile() && !QFileInfo(candidate).isSymLink()) {
            return candidate;
        }
    }
    return {};
}

void removeOpenVpnRunEntries(const Options &options, QStringList *output, bool machineWide) {
    const QString runKey = QStringLiteral("Software/Microsoft/Windows/CurrentVersion/Run");
    if (options.dryRun) {
        output->append(QStringLiteral("[plan] Remove the OPENVPN-GUI auto-start value from the current user's Run key."));
        if (machineWide) {
            output->append(QStringLiteral("[plan] Remove OPENVPN-GUI from the machine Run keys."));
        }
        return;
    }
    registryDeleteValue(HKEY_CURRENT_USER, runKey, QStringLiteral("OPENVPN-GUI"));
    if (machineWide) {
        registryDeleteValue(HKEY_LOCAL_MACHINE, runKey, QStringLiteral("OPENVPN-GUI"));
        registryDeleteValue(HKEY_LOCAL_MACHINE,
            QStringLiteral("Software/WOW6432Node/Microsoft/Windows/CurrentVersion/Run"),
            QStringLiteral("OPENVPN-GUI"));
    }
}

void removeWindowsFirewallRules(const Options &options, QStringList *output) {
    const QStringList rules{QStringLiteral("VPNGate-OpenVPN-In"),
                            QStringLiteral("VPNGate-OpenVPN-Out"),
                            QStringLiteral("VPNGate-IPv6-Guard")};
    for (const QString &rule : rules) {
        runOptional(options, QStringLiteral("netsh.exe"),
            {QStringLiteral("advfirewall"), QStringLiteral("firewall"), QStringLiteral("delete"),
             QStringLiteral("rule"), QStringLiteral("name=%1").arg(rule)},
            output, QStringLiteral("Remove VPN Gate firewall rule %1").arg(rule));
    }
}

void deleteWindowsVpnProfiles(const Options &options, QStringList *output) {
    const QString profile = QStringLiteral("VPNGate-L2TP");
    if (options.dryRun) {
        output->append(QStringLiteral("[plan] Disconnect and remove the per-user RAS profile VPNGate-L2TP."));
        if (!options.userOnly && isWindowsAdmin()) {
            output->append(QStringLiteral("[plan] Remove the all-user RAS profile VPNGate-L2TP."));
        }
        return;
    }
    const DWORD userResult = RasDeleteEntryW(nullptr, reinterpret_cast<LPCWSTR>(profile.utf16()));
    if (userResult == ERROR_SUCCESS) {
        output->append(QStringLiteral("[ok] Removed the per-user VPNGate-L2TP RAS profile."));
    }
    if (!options.userOnly && isWindowsAdmin()) {
        const QString globalPhonebook = QDir(qEnvironmentVariable("ProgramData"))
            .filePath(QStringLiteral("Microsoft/Network/Connections/Pbk/rasphone.pbk"));
        if (QFileInfo(globalPhonebook).isFile()) {
            const DWORD globalResult = RasDeleteEntryW(
                reinterpret_cast<LPCWSTR>(globalPhonebook.utf16()), reinterpret_cast<LPCWSTR>(profile.utf16()));
            if (globalResult == ERROR_SUCCESS) {
                output->append(QStringLiteral("[ok] Removed the all-user VPNGate-L2TP RAS profile."));
            }
        }
    }
}

void cleanWindowsResidues(const Options &options, QStringList *output) {
    const QString prefix = options.prefix.isEmpty() ? systemInstallPrefix() : QDir::cleanPath(options.prefix);
    const QString cache = cacheDirectory(options);
    const QString cli = QDir(prefix).filePath(QStringLiteral("vpngate.exe"));
    const QFileInfo cliInfo(cli);
    if (!options.userOnly && isWindowsAdmin() && cliInfo.isFile() && !cliInfo.isSymLink()) {
        const QStringList arguments{QStringLiteral("--uac-elevated"), QStringLiteral("--cache-dir"), cache,
                                    QStringLiteral("disconnect")};
        if (options.dryRun) {
            output->append(QStringLiteral("[plan] Disconnect any active VPN Gate session using %1 %2")
                               .arg(cli, arguments.join(QLatin1Char(' '))));
        } else {
            const CommandResult disconnected = runCommand(cli, arguments);
            if (disconnected.started && disconnected.exitCode == 0) {
                output->append(QStringLiteral("[ok] Asked the installed VPN Gate CLI to disconnect any active session."));
            }
        }
    } else if (options.dryRun) {
        output->append(QStringLiteral("[plan] Check for an existing VPN Gate CLI and disconnect its active session before cleanup."));
    }
    runOptional(options, QStringLiteral("rasdial.exe"),
        {QStringLiteral("VPNGate-L2TP"), QStringLiteral("/DISCONNECT")}, output,
        QStringLiteral("Disconnect the VPNGate-L2TP RAS connection"));

    const QString powershell = !QStandardPaths::findExecutable(QStringLiteral("powershell.exe")).isEmpty()
        ? QStringLiteral("powershell.exe") : QStringLiteral("pwsh.exe");
    const QString processScript = QStringLiteral(
        "$ErrorActionPreference='SilentlyContinue'; "
        "Get-CimInstance Win32_Process -Filter \"Name = 'openvpn.exe'\" | "
        "Where-Object { $_.CommandLine -and $_.CommandLine -match 'vpngate' } | "
        "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }; "
        "Get-Process -Name 'openvpn-gui' -ErrorAction SilentlyContinue | "
        "Stop-Process -Force -ErrorAction SilentlyContinue");
    if (!QStandardPaths::findExecutable(powershell).isEmpty()) {
        runOptional(options, powershell,
            {QStringLiteral("-NoProfile"), QStringLiteral("-NonInteractive"),
             QStringLiteral("-Command"), processScript}, output,
            QStringLiteral("Stop only VPN Gate-associated OpenVPN processes and the OpenVPN GUI"));
    } else {
        output->append(QStringLiteral("[warn] PowerShell was unavailable; orphaned OpenVPN process cleanup was skipped."));
    }

    for (const QString &name : {QStringLiteral("vpngate.py"), QStringLiteral("vpngate.ps1"),
                                QStringLiteral("vpngate.cmd")}) {
        removeKnownPath(options, QDir(prefix).filePath(name), output,
                        QStringLiteral("legacy VPN Gate shim"));
    }

    const QString manifest = manifestPathForPrefix(prefix);
    const QFileInfo manifestInfo(manifest);
    if ((options.action == Action::Install || options.action == Action::Uninstall)
        && !manifestInfo.exists() && !manifestInfo.isSymLink()) {
        for (const QString &name : {QStringLiteral("vpngate.exe"), QStringLiteral("vpngate-gui.exe"),
                                    QStringLiteral("vpngate.ico"), QStringLiteral("vpngate-256.png")}) {
            removeKnownPath(options, QDir(prefix).filePath(name), output,
                            QStringLiteral("untracked legacy VPN Gate file"));
        }
    }

    if (options.action == Action::Uninstall) {
        deleteWindowsVpnProfiles(options, output);
        if (!options.userOnly && isWindowsAdmin()) {
            removeWindowsFirewallRules(options, output);
        }
        removeKnownPath(options, cache, output, QStringLiteral("VPN Gate local app state"), true);
    } else {
        cleanupTransientCache(options, cache, output);
    }
}
#endif

bool packageIsInstalled(const QString &manager, const QString &package) {
    QString program;
    QStringList arguments;
    if (manager == QStringLiteral("apt")) {
        program = QStringLiteral("dpkg-query");
        arguments = {QStringLiteral("-W"), QStringLiteral("-f=${Status}"), package};
    } else if (manager == QStringLiteral("dnf")) {
        program = QStringLiteral("rpm");
        arguments = {QStringLiteral("-q"), package};
    } else if (manager == QStringLiteral("pacman")) {
        program = QStringLiteral("pacman");
        arguments = {QStringLiteral("-Q"), package};
    } else {
        return false;
    }
    const CommandResult result = runCommand(program, arguments);
    if (!result.started || result.exitCode != 0) {
        return false;
    }
    return manager != QStringLiteral("apt") || result.output.contains(QStringLiteral("install ok installed"));
}

void rememberCompilePackages(Options &options, const QString &manager, const QStringList &packages) {
    for (const QString &package : packages) {
        if (!packageIsInstalled(manager, package) && !options.compilePackagesInstalled.contains(package)) {
            options.compilePackagesInstalled.append(package);
        }
    }
    if (!options.compilePackagesInstalled.isEmpty()) {
        options.compilePackageManager = manager;
    }
}

void installCompilePackages(Options &options, const QString &manager, QStringList *output) {
    if (options.skipDependencies || options.noBuild) {
        return;
    }
    const bool hasCompiler = !QStandardPaths::findExecutable(QStringLiteral("cc")).isEmpty()
        || !QStandardPaths::findExecutable(QStringLiteral("gcc")).isEmpty()
        || !QStandardPaths::findExecutable(QStringLiteral("clang")).isEmpty();
    QStringList packages;
    if (!hasCompiler) {
        if (manager == QStringLiteral("apt")) {
            packages = {QStringLiteral("gcc"), QStringLiteral("libc6-dev")};
        } else if (manager == QStringLiteral("dnf")) {
            packages = {QStringLiteral("gcc"), QStringLiteral("glibc-devel")};
        } else if (manager == QStringLiteral("pacman")) {
            packages = {QStringLiteral("gcc")};
        }
    }
    if (manager == QStringLiteral("apt")) {
        packages.append({QStringLiteral("pkg-config"), QStringLiteral("libwayland-dev"),
            QStringLiteral("libxkbcommon-dev"), QStringLiteral("libxkbcommon-x11-dev"),
            QStringLiteral("libx11-dev"), QStringLiteral("libxrandr-dev"), QStringLiteral("libxi-dev"),
            QStringLiteral("libxcursor-dev"), QStringLiteral("libxinerama-dev"),
            QStringLiteral("libegl1-mesa-dev"), QStringLiteral("libgl1-mesa-dev"),
            QStringLiteral("libfontconfig1-dev")});
    } else if (manager == QStringLiteral("dnf")) {
        packages.append({QStringLiteral("pkgconf-pkg-config"), QStringLiteral("wayland-devel"),
            QStringLiteral("libxkbcommon-devel"), QStringLiteral("libxkbcommon-x11-devel"),
            QStringLiteral("libX11-devel"), QStringLiteral("libXrandr-devel"), QStringLiteral("libXi-devel"),
            QStringLiteral("libXcursor-devel"), QStringLiteral("libXinerama-devel"),
            QStringLiteral("mesa-libEGL-devel"), QStringLiteral("mesa-libGL-devel"),
            QStringLiteral("fontconfig-devel")});
    } else if (manager == QStringLiteral("pacman")) {
        packages.append({QStringLiteral("pkgconf"), QStringLiteral("wayland"), QStringLiteral("libxkbcommon"),
            QStringLiteral("libx11"), QStringLiteral("libxrandr"), QStringLiteral("libxi"),
            QStringLiteral("libxcursor"), QStringLiteral("libxinerama"), QStringLiteral("mesa"),
            QStringLiteral("fontconfig")});
    }
    if (packages.isEmpty()) {
        return;
    }
    rememberCompilePackages(options, manager, packages);
    if (manager == QStringLiteral("apt")) {
        QStringList args{QStringLiteral("install"), QStringLiteral("-y"), QStringLiteral("-o"),
                         QStringLiteral("APT::Keep-Downloaded-Packages=false")};
        args.append(packages);
        runRequired(options, QStringLiteral("apt-get"), args, output,
                    QStringLiteral("Install compile-only native C linker and GUI build headers"));
    } else if (manager == QStringLiteral("dnf")) {
        QStringList args{QStringLiteral("install"), QStringLiteral("-y")};
        args.append(packages);
        runOptional(options, QStringLiteral("dnf"), args, output,
                    QStringLiteral("Install compile-only native C linker and GUI build headers"));
    } else if (manager == QStringLiteral("pacman")) {
        QStringList args{QStringLiteral("-S"), QStringLiteral("--needed"), QStringLiteral("--noconfirm")};
        args.append(packages);
        runOptional(options, QStringLiteral("pacman"), args, output,
                    QStringLiteral("Install compile-only native C linker and GUI build headers"));
    }
}

void releaseCompilePackages(const Options &options, QStringList *output) {
    if (options.compilePackagesInstalled.isEmpty()) {
        return;
    }
    if (options.keepToolchain && !options.removeToolchain) {
        output->append(QStringLiteral("[ok] Compile-only packages kept as requested: %1")
                           .arg(options.compilePackagesInstalled.join(QLatin1Char(' '))));
        return;
    }
    if (options.dryRun) {
        output->append(QStringLiteral("[plan] Remove only compile packages this installer found missing before setup: %1")
                           .arg(options.compilePackagesInstalled.join(QLatin1Char(' '))));
        return;
    }
    QString program;
    QStringList arguments;
    if (options.compilePackageManager == QStringLiteral("apt")) {
        program = QStringLiteral("apt-get");
        arguments = {QStringLiteral("remove"), QStringLiteral("-y")};
        arguments.append(options.compilePackagesInstalled);
    } else if (options.compilePackageManager == QStringLiteral("dnf")) {
        program = QStringLiteral("dnf");
        arguments = {QStringLiteral("remove"), QStringLiteral("-y")};
        arguments.append(options.compilePackagesInstalled);
    } else if (options.compilePackageManager == QStringLiteral("pacman")) {
        program = QStringLiteral("pacman");
        arguments = {QStringLiteral("-R"), QStringLiteral("--noconfirm")};
        arguments.append(options.compilePackagesInstalled);
    } else if (options.compilePackageManager == QStringLiteral("winget")) {
        program = QStringLiteral("winget.exe");
        arguments = {QStringLiteral("uninstall"), QStringLiteral("-e"), QStringLiteral("--id"),
                     options.compilePackagesInstalled.first(), QStringLiteral("--silent"),
                     QStringLiteral("--accept-source-agreements")};
    } else {
        return;
    }
    runOptional(options, program, arguments, output,
                QStringLiteral("Remove compile-only packages added by this installer"));
    if (options.compilePackageManager == QStringLiteral("apt")) {
        runOptional(options, QStringLiteral("apt-get"), {QStringLiteral("autoremove"), QStringLiteral("-y")},
                    output, QStringLiteral("Remove unneeded dependencies after compiler cleanup"));
    }
}

void installRuntimePackages(Options &options, QStringList *output) {
    if (options.skipDependencies) {
        output->append(QStringLiteral("[skip] System runtime package installation was requested to be skipped."));
        return;
    }
#if defined(Q_OS_LINUX)
    if (!QStandardPaths::findExecutable(QStringLiteral("apt-get")).isEmpty()) {
        if (!runRequired(options, QStringLiteral("apt-get"), {QStringLiteral("update"), QStringLiteral("-qq")},
                         output, QStringLiteral("Refresh apt package indexes"))) {
            return;
        }
        const QStringList packages{
            QStringLiteral("openvpn"), QStringLiteral("xl2tpd"), QStringLiteral("ppp"),
            QStringLiteral("iproute2"), QStringLiteral("curl"), QStringLiteral("ca-certificates"),
            QStringLiteral("tar"),
        };
        QStringList args{QStringLiteral("install"), QStringLiteral("-y"),
                         QStringLiteral("-o"), QStringLiteral("APT::Keep-Downloaded-Packages=false")};
        args.append(packages);
        if (!runRequired(options, QStringLiteral("apt-get"), args, output,
                         QStringLiteral("Install VPN runtime and native build dependencies"))) {
            return;
        }
        runOptional(options, QStringLiteral("apt-get"),
                    {QStringLiteral("install"), QStringLiteral("-y"), QStringLiteral("--no-install-recommends"),
                     QStringLiteral("network-manager-openvpn"), QStringLiteral("network-manager-openvpn-gnome"),
                     QStringLiteral("libnotify-bin")}, output,
                    QStringLiteral("Install optional NetworkManager OpenVPN and desktop notification integration"));
        installCompilePackages(options, QStringLiteral("apt"), output);
    } else if (!QStandardPaths::findExecutable(QStringLiteral("dnf")).isEmpty()) {
        runRequired(options, QStringLiteral("dnf"),
                    {QStringLiteral("install"), QStringLiteral("-y"), QStringLiteral("openvpn"), QStringLiteral("xl2tpd"),
                     QStringLiteral("ppp"), QStringLiteral("iproute"), QStringLiteral("curl"),
                     QStringLiteral("ca-certificates"), QStringLiteral("tar")}, output,
                    QStringLiteral("Install VPN runtime and native build dependencies"));
        runOptional(options, QStringLiteral("dnf"),
                    {QStringLiteral("install"), QStringLiteral("-y"), QStringLiteral("NetworkManager-openvpn"),
                     QStringLiteral("NetworkManager-openvpn-gnome"), QStringLiteral("libnotify")}, output,
                    QStringLiteral("Install optional NetworkManager OpenVPN and desktop notification integration"));
        installCompilePackages(options, QStringLiteral("dnf"), output);
    } else if (!QStandardPaths::findExecutable(QStringLiteral("pacman")).isEmpty()) {
        runRequired(options, QStringLiteral("pacman"),
                    {QStringLiteral("-Sy"), QStringLiteral("--needed"), QStringLiteral("--noconfirm"),
                     QStringLiteral("openvpn"), QStringLiteral("xl2tpd"), QStringLiteral("ppp"),
                     QStringLiteral("iproute2"), QStringLiteral("curl"), QStringLiteral("ca-certificates"),
                     QStringLiteral("tar")}, output,
                    QStringLiteral("Install VPN runtime and native build dependencies"));
        runOptional(options, QStringLiteral("pacman"),
                    {QStringLiteral("-S"), QStringLiteral("--needed"), QStringLiteral("--noconfirm"),
                     QStringLiteral("networkmanager-openvpn"), QStringLiteral("libnotify")}, output,
                    QStringLiteral("Install optional NetworkManager OpenVPN and desktop notification integration"));
        installCompilePackages(options, QStringLiteral("pacman"), output);
    } else {
        output->append(QStringLiteral("[warn] No supported Linux package manager was detected; install OpenVPN, xl2tpd, PPP, curl, CA certificates, and build dependencies manually."));
    }
#elif defined(Q_OS_MACOS)
    const QString xcodeSelect = QStandardPaths::findExecutable(QStringLiteral("xcode-select"));
    if (!xcodeSelect.isEmpty()) {
        const CommandResult selected = runCommand(xcodeSelect, {QStringLiteral("-p")});
        if (!selected.started || selected.exitCode != 0) {
            runOptional(options, xcodeSelect, {QStringLiteral("--install")}, output,
                        QStringLiteral("Request Apple Command Line Tools installation"));
            output->append(QStringLiteral("[warn] Complete the Apple Command Line Tools installation, then rerun if the compiler is still unavailable."));
        }
    } else {
        output->append(QStringLiteral("[warn] xcode-select was not found; install Apple Command Line Tools before compiling from source."));
    }

    QString brew = QStandardPaths::findExecutable(QStringLiteral("brew"));
    if (brew.isEmpty()) {
        for (const QString &candidate : {QStringLiteral("/opt/homebrew/bin/brew"),
                                         QStringLiteral("/usr/local/bin/brew")}) {
            if (QFileInfo(candidate).isExecutable() && !QFileInfo(candidate).isSymLink()) {
                brew = candidate;
                break;
            }
        }
    }
    if (brew.isEmpty()) {
        output->append(QStringLiteral("[skip] Homebrew was not detected; install OpenVPN manually if the client needs it."));
    } else if (options.dryRun) {
        output->append(QStringLiteral("[plan] As the target user, check Homebrew for OpenVPN and install it with: %1 install openvpn").arg(brew));
    } else {
        const CommandResult installed = runForTargetUser(options, brew,
            {QStringLiteral("list"), QStringLiteral("openvpn")});
        if (installed.started && installed.exitCode == 0) {
            output->append(QStringLiteral("[ok] OpenVPN is already installed via Homebrew."));
        } else {
            output->append(QStringLiteral("[*] Install OpenVPN with Homebrew as the target user."));
            const CommandResult install = runForTargetUser(options, brew,
                {QStringLiteral("install"), QStringLiteral("openvpn")});
            if (!install.output.isEmpty()) {
                output->append(install.output.split(QLatin1Char('\n')));
            }
            if (!install.started || install.exitCode != 0) {
                output->append(QStringLiteral("[error] Homebrew OpenVPN installation failed: %1").arg(install.error));
            }
        }
    }
#elif defined(Q_OS_WIN)
    if (options.skipOpenVPN) {
        output->append(QStringLiteral("[skip] OpenVPN installation was disabled with --skip-openvpn."));
        return;
    }
    QString openvpn = findOpenVpnExecutable();
    if (!openvpn.isEmpty() && !options.installOpenVPN) {
        output->append(QStringLiteral("[ok] OpenVPN is already installed: %1").arg(openvpn));
        return;
    }
    const QString winget = QStandardPaths::findExecutable(QStringLiteral("winget.exe"));
    if (winget.isEmpty()) {
        output->append(openvpn.isEmpty()
            ? QStringLiteral("[warn] WinGet is unavailable; OpenVPN Community was not installed automatically.")
            : QStringLiteral("[warn] WinGet is unavailable; existing OpenVPN installation was left unchanged."));
        return;
    }
    QStringList arguments{QStringLiteral("install"), QStringLiteral("-e"), QStringLiteral("--id"),
                          QStringLiteral("OpenVPNTechnologies.OpenVPN"), QStringLiteral("--silent"),
                          QStringLiteral("--accept-package-agreements"), QStringLiteral("--accept-source-agreements")};
    if (!options.userOnly && isWindowsAdmin()) {
        arguments.append({QStringLiteral("--override"),
            QStringLiteral("/qn /norestart ADDLOCAL=OpenVPN,OpenVPN.Service,Drivers,Drivers.OvpnDco,Drivers.TAPWindows6 REMOVE=OpenVPN.GUI,OpenVPN.GUI.OnLogon")});
    }
    runOptional(options, winget, arguments, output,
                options.installOpenVPN ? QStringLiteral("Install or repair headless OpenVPN Community")
                                       : QStringLiteral("Install missing OpenVPN Community runtime"));
    openvpn = findOpenVpnExecutable();
    if (!options.dryRun && openvpn.isEmpty()) {
        output->append(QStringLiteral("[warn] OpenVPN was not detected after the WinGet operation; the installer will continue."));
    }
#endif
}

} // namespace

QString systemInstallPrefix() {
#if defined(Q_OS_WIN)
    return defaultPrefix();
#else
    return QStringLiteral("/usr/local");
#endif
}

QString hostTargetHome(const Options &options) {
    return targetHome(options);
}

QString hostCacheDirectory(const Options &options) {
    return cacheDirectory(options);
}

bool windowsAdministratorAvailable() {
#if defined(Q_OS_WIN)
    return isWindowsAdmin();
#else
    return false;
#endif
}

bool validateSourceArchiveEntries(const QStringList &paths, const QStringList &verboseEntries,
                                  QString *error) {
    if (paths.isEmpty() || paths.size() != verboseEntries.size()) {
        if (error) {
            *error = QStringLiteral("Source archive path/type listings are empty or inconsistent.");
        }
        return false;
    }
    static const QRegularExpression drivePrefix(QStringLiteral("^[A-Za-z]:"));
    for (const QString &entry : paths) {
        const bool hasBackslash = entry.contains(QLatin1Char('\\'));
        QString normalized = entry;
        normalized.replace(QLatin1Char('\\'), QLatin1Char('/'));
        const QStringList parts = normalized.split(QLatin1Char('/'), Qt::SkipEmptyParts);
        if (hasBackslash || QDir::isAbsolutePath(normalized)
            || drivePrefix.match(normalized).hasMatch()
            || std::any_of(parts.cbegin(), parts.cend(), [](const QString &part) {
                   return part == QStringLiteral("..") || part == QStringLiteral(".");
               })) {
            if (error) {
                *error = QStringLiteral("Refusing an unsafe path in the downloaded source archive: %1").arg(entry);
            }
            return false;
        }
    }
    for (const QString &entry : verboseEntries) {
        if (entry.isEmpty() || (entry[0] != QLatin1Char('-') && entry[0] != QLatin1Char('d'))) {
            if (error) {
                *error = QStringLiteral("Refusing a symlink, hardlink, or special file in the source archive: %1")
                             .arg(entry);
            }
            return false;
        }
    }
    return true;
}

bool downloadSourceArchive(const Options &options, const QString &stagingRoot,
                           QString *sourceRoot, QStringList *output, QString *error) {
    const QString repo = options.repoSlug.trimmed();
    QString branch = options.branchName.trimmed();
    if (branch.isEmpty()) {
        branch = qEnvironmentVariable("VPNGATE_BRANCH", QStringLiteral("main"));
    }
    static const QRegularExpression repoRe(QStringLiteral("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"));
    static const QRegularExpression branchRe(QStringLiteral("^[A-Za-z0-9._/+@-]+$"));
    if (!repoRe.match(repo).hasMatch() || repo.contains(QStringLiteral(".."))) {
        if (error) {
            *error = QStringLiteral("Invalid GitHub repository slug: %1").arg(repo);
        }
        return false;
    }
    if (!branchRe.match(branch).hasMatch() || branch.contains(QStringLiteral(".."))
        || branch.startsWith(QLatin1Char('/')) || branch.endsWith(QLatin1Char('/'))
        || branch.contains(QStringLiteral("//"))) {
        if (error) {
            *error = QStringLiteral("Invalid source branch name: %1").arg(branch);
        }
        return false;
    }
    if (!QDir().mkpath(stagingRoot)) {
        if (error) {
            *error = QStringLiteral("Could not create temporary source staging directory: %1").arg(stagingRoot);
        }
        return false;
    }
    const QString curl = QStandardPaths::findExecutable(QStringLiteral("curl"));
    const QString tar = QStandardPaths::findExecutable(QStringLiteral("tar"));
    if (curl.isEmpty() || tar.isEmpty()) {
        if (error) {
            *error = QStringLiteral("Downloading source requires curl and tar. Use a local checkout or install those runtime tools first.");
        }
        return false;
    }
    const QString archive = QDir(stagingRoot).filePath(QStringLiteral("source.tar.gz"));
    const QString url = QStringLiteral("https://codeload.github.com/%1/tar.gz/refs/heads/%2").arg(repo, branch);
    output->append(QStringLiteral("[*] Downloading source archive from %1").arg(url));
    const CommandResult download = runCommand(curl, {QStringLiteral("--fail"), QStringLiteral("--location"),
        QStringLiteral("--silent"), QStringLiteral("--show-error"), QStringLiteral("--proto"), QStringLiteral("=https"),
        QStringLiteral("--tlsv1.2"), url, QStringLiteral("--output"), archive});
    if (!download.started || download.exitCode != 0) {
        if (error) {
            *error = QStringLiteral("Could not download source archive: %1").arg(download.error);
        }
        return false;
    }
    const CommandResult listing = runCommand(tar, {QStringLiteral("-tzf"), archive});
    if (!listing.started || listing.exitCode != 0) {
        if (error) {
            *error = QStringLiteral("Downloaded source archive is not a readable tar.gz: %1").arg(listing.error);
        }
        return false;
    }
    const QStringList pathEntries = listing.output.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    const CommandResult verboseListing = runCommand(tar, {QStringLiteral("-tvzf"), archive});
    if (!verboseListing.started || verboseListing.exitCode != 0) {
        if (error) {
            *error = QStringLiteral("Could not inspect source archive entry types: %1").arg(verboseListing.error);
        }
        return false;
    }
    const QStringList verboseEntries = verboseListing.output.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    if (!validateSourceArchiveEntries(pathEntries, verboseEntries, error)) {
        return false;
    }
    const CommandResult extract = runCommand(tar, {QStringLiteral("-xzf"), archive,
        QStringLiteral("--no-same-owner"), QStringLiteral("--no-same-permissions"), QStringLiteral("-C"), stagingRoot});
    if (!extract.started || extract.exitCode != 0) {
        if (error) {
            *error = QStringLiteral("Could not extract source archive: %1").arg(extract.error);
        }
        return false;
    }
    const QFileInfoList directories = QDir(stagingRoot).entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (const QFileInfo &directory : directories) {
        if (directory.fileName() == QStringLiteral("src") || directory.isSymLink()) {
            continue;
        }
        const QString cargo = QDir(directory.filePath()).filePath(QStringLiteral("Cargo.toml"));
        if (QFileInfo(cargo).isFile() && !QFileInfo(cargo).isSymLink()) {
            *sourceRoot = directory.filePath();
            output->append(QStringLiteral("[ok] Extracted source checkout to temporary storage: %1").arg(*sourceRoot));
            return true;
        }
    }
    if (error) {
        *error = QStringLiteral("Downloaded archive did not contain a top-level Cargo.toml.");
    }
    return false;
}

bool prepareBuildToolchain(Options &options, const QString &stagingRoot,
                           QStringList *output, QString *cargoHome,
                           QString *rustupHome, QString *error) {
#if defined(Q_OS_WIN)
    const QString target = hostTargetHome(options);
    const QString environmentCargo = qEnvironmentVariable("CARGO_HOME");
    QString cargo = QStandardPaths::findExecutable(QStringLiteral("cargo.exe"));
    QString selectedCargoHome = environmentCargo;
    if (cargo.isEmpty() && !environmentCargo.isEmpty()) {
        const QString candidate = QDir(environmentCargo).filePath(QStringLiteral("bin/cargo.exe"));
        if (QFileInfo(candidate).isFile() && !QFileInfo(candidate).isSymLink()) {
            cargo = candidate;
        }
    }
    if (cargo.isEmpty()) {
        const QString userCargo = QDir(target).filePath(QStringLiteral(".cargo/bin/cargo.exe"));
        if (QFileInfo(userCargo).isFile() && !QFileInfo(userCargo).isSymLink()) {
            cargo = userCargo;
            selectedCargoHome = QDir(target).filePath(QStringLiteral(".cargo"));
        }
    }

    SYSTEM_INFO systemInfo{};
    GetNativeSystemInfo(&systemInfo);
    const bool arm64 = systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64;
    const QString archName = arm64 ? QStringLiteral("arm64") : QStringLiteral("x64");
    const QString msvcTriple = arm64 ? QStringLiteral("aarch64-pc-windows-msvc")
                                     : QStringLiteral("x86_64-pc-windows-msvc");
    const QString gnuTriple = QStringLiteral("x86_64-pc-windows-gnu");

    auto ensureGcc = [&]() -> bool {
        QString gcc = findWindowsGcc();
        if (gcc.isEmpty() && !options.skipDependencies) {
            const QString winget = QStandardPaths::findExecutable(QStringLiteral("winget.exe"));
            if (!winget.isEmpty()) {
                const QString package = QStringLiteral("BrechtSanders.WinLibs.POSIX.UCRT");
                output->append(QStringLiteral("[*] Install MinGW-w64 from WinGet for the native GNU Rust linker."));
                const CommandResult installed = runCommand(winget,
                    {QStringLiteral("install"), QStringLiteral("-e"), QStringLiteral("--id"), package,
                     QStringLiteral("--silent"), QStringLiteral("--accept-package-agreements"),
                     QStringLiteral("--accept-source-agreements")});
                if (!installed.output.isEmpty()) {
                    output->append(installed.output.split(QLatin1Char('\n')));
                }
                if (!installed.started || installed.exitCode != 0) {
                    if (error) {
                        *error = QStringLiteral("WinGet could not install MinGW-w64: %1").arg(installed.error);
                    }
                    return false;
                }
                options.compilePackageManager = QStringLiteral("winget");
                if (!options.compilePackagesInstalled.contains(package)) {
                    options.compilePackagesInstalled.append(package);
                }
                gcc = findWindowsGcc();
            }
        }
        if (gcc.isEmpty()) {
            if (error) {
                *error = options.skipDependencies
                    ? QStringLiteral("A native GNU Windows build needs gcc.exe; --skip-deps prevented the MinGW-w64 bootstrap.")
                    : QStringLiteral("A native GNU Windows build needs MinGW-w64 gcc.exe. Install WinLibs or Visual Studio C++ Build Tools, then retry.");
            }
            return false;
        }
        const QString gccDir = QFileInfo(gcc).absolutePath();
        const QString oldPath = qEnvironmentVariable("PATH");
        if (!oldPath.split(QDir::listSeparator(), Qt::SkipEmptyParts).contains(gccDir, Qt::CaseInsensitive)) {
            qputenv("PATH", (gccDir + QDir::listSeparator() + oldPath).toLocal8Bit());
        }
        output->append(QStringLiteral("[ok] Using native MinGW linker: %1").arg(gcc));
        return true;
    };

    if (!cargo.isEmpty()) {
        *cargoHome = selectedCargoHome;
        *rustupHome = qEnvironmentVariable("RUSTUP_HOME");
        QString rustc = QStandardPaths::findExecutable(QStringLiteral("rustc.exe"));
        if (rustc.isEmpty()) {
            rustc = QDir(QFileInfo(cargo).absolutePath()).filePath(QStringLiteral("rustc.exe"));
        }
        const CommandResult hostInfo = rustc.isEmpty()
            ? CommandResult{} : runCommand(rustc, {QStringLiteral("-vV")});
        if (hostInfo.output.contains(QStringLiteral("windows-gnu"), Qt::CaseInsensitive)) {
            if (!ensureGcc()) {
                return false;
            }
        } else if (!prepareWindowsMsvcEnvironment(archName, output)) {
            if (error) {
                *error = QStringLiteral("The existing Rust toolchain targets MSVC but Visual Studio C++ build tools could not be activated. Start from a Visual Studio Developer PowerShell or install the native C++ workload.");
            }
            return false;
        }
        output->append(QStringLiteral("[ok] Using existing Rust/Cargo toolchain: %1").arg(cargo));
        return true;
    }

    QString defaultHost;
    if (arm64) {
        if (!prepareWindowsMsvcEnvironment(archName, output)) {
            if (error) {
                *error = QStringLiteral("Windows ARM64 builds require native Visual Studio C++ ARM64 tools; MinGW x86_64 cannot link this target.");
            }
            return false;
        }
        defaultHost = msvcTriple;
    } else if (prepareWindowsMsvcEnvironment(archName, output)) {
        defaultHost = msvcTriple;
    } else {
        if (!ensureGcc()) {
            return false;
        }
        defaultHost = gnuTriple;
    }

    const QString curl = QStandardPaths::findExecutable(QStringLiteral("curl.exe"));
    if (curl.isEmpty()) {
        if (error) {
            *error = QStringLiteral("Rust is not installed and curl.exe is unavailable for the temporary rustup bootstrap.");
        }
        return false;
    }
    if (!QDir().mkpath(stagingRoot)) {
        if (error) {
            *error = QStringLiteral("Could not create temporary toolchain staging directory: %1").arg(stagingRoot);
        }
        return false;
    }
    const QString rustupInit = QDir(stagingRoot).filePath(QStringLiteral("rustup-init.exe"));
    const QString rustupUrl = QStringLiteral("https://win.rustup.rs/%1").arg(arm64 ? QStringLiteral("aarch64") : QStringLiteral("x86_64"));
    const CommandResult downloaded = runCommand(curl,
        {QStringLiteral("--fail"), QStringLiteral("--location"), QStringLiteral("--silent"),
         QStringLiteral("--show-error"), QStringLiteral("--proto"), QStringLiteral("=https"),
         QStringLiteral("--tlsv1.2"), rustupUrl, QStringLiteral("--output"), rustupInit});
    if (!downloaded.started || downloaded.exitCode != 0 || !QFileInfo(rustupInit).isFile()) {
        if (error) {
            *error = QStringLiteral("Could not download rustup-init.exe over HTTPS: %1").arg(downloaded.error);
        }
        return false;
    }
    const bool keep = options.keepToolchain && !options.removeToolchain;
    if (keep) {
        *cargoHome = QDir(target).filePath(QStringLiteral(".cargo"));
        *rustupHome = QDir(target).filePath(QStringLiteral(".rustup"));
    } else {
        *cargoHome = QDir(stagingRoot).filePath(QStringLiteral("cargo"));
        *rustupHome = QDir(stagingRoot).filePath(QStringLiteral("rustup"));
    }
    for (const QString &directory : {*cargoHome, *rustupHome}) {
        const QFileInfo existing(directory);
        if (existing.isSymLink() || (existing.exists() && !existing.isDir())) {
            if (error) {
                *error = QStringLiteral("Refusing to use an unsafe Rust toolchain path: %1").arg(directory);
            }
            return false;
        }
        if (!QDir().mkpath(directory)) {
            if (error) {
                *error = QStringLiteral("Could not create Rust toolchain path: %1").arg(directory);
            }
            return false;
        }
    }
    QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
    environment.insert(QStringLiteral("CARGO_HOME"), *cargoHome);
    environment.insert(QStringLiteral("RUSTUP_HOME"), *rustupHome);
    output->append(QStringLiteral("[*] Bootstrap a minimal Rust toolchain for %1 (%2).")
                       .arg(archName, defaultHost));
    const CommandResult installed = runCommand(rustupInit,
        {QStringLiteral("-y"), QStringLiteral("--profile"), QStringLiteral("minimal"),
         QStringLiteral("--no-modify-path"), QStringLiteral("--default-host"), defaultHost}, environment);
    if (!installed.output.isEmpty()) {
        output->append(installed.output.split(QLatin1Char('\n')));
    }
    if (!installed.started || installed.exitCode != 0) {
        if (error) {
            *error = QStringLiteral("rustup bootstrap failed: %1").arg(installed.error);
        }
        return false;
    }
    if (keep) {
        output->append(QStringLiteral("[ok] Installed Rust/Cargo persistently under %1 as requested.").arg(*cargoHome));
    } else {
        output->append(QStringLiteral("[ok] Installed an isolated minimal Rust toolchain; temporary toolchain data will be removed after the build."));
    }
    return true;
#else
    const QString target = hostTargetHome(options);
    const QString environmentCargo = qEnvironmentVariable("CARGO_HOME");
    QString cargo = QStandardPaths::findExecutable(QStringLiteral("cargo"));
    QString selectedCargoHome = environmentCargo;
    if (cargo.isEmpty() && !environmentCargo.isEmpty()) {
        const QString candidate = QDir(environmentCargo).filePath(QStringLiteral("bin/cargo"));
        if (QFileInfo(candidate).isExecutable() && !QFileInfo(candidate).isSymLink()) {
            cargo = candidate;
        }
    }
    if (cargo.isEmpty()) {
        const QString userCargo = QDir(target).filePath(QStringLiteral(".cargo/bin/cargo"));
        if (QFileInfo(userCargo).isExecutable() && !QFileInfo(userCargo).isSymLink()) {
            cargo = userCargo;
            selectedCargoHome = QDir(target).filePath(QStringLiteral(".cargo"));
        }
    }
    if (!cargo.isEmpty()) {
        *cargoHome = selectedCargoHome;
        *rustupHome = qEnvironmentVariable("RUSTUP_HOME");
        output->append(QStringLiteral("[ok] Using existing Rust/Cargo toolchain: %1").arg(cargo));
        return true;
    }
    const QString curl = QStandardPaths::findExecutable(QStringLiteral("curl"));
    if (curl.isEmpty()) {
        if (error) {
            *error = QStringLiteral("Rust is not installed and curl is unavailable for the temporary rustup bootstrap.");
        }
        return false;
    }
    if (!QDir().mkpath(stagingRoot)) {
        if (error) {
            *error = QStringLiteral("Could not create temporary toolchain staging directory: %1").arg(stagingRoot);
        }
        return false;
    }
    const QString script = QDir(stagingRoot).filePath(QStringLiteral("rustup-init.sh"));
    const CommandResult downloaded = runCommand(curl, {QStringLiteral("--fail"), QStringLiteral("--location"),
        QStringLiteral("--silent"), QStringLiteral("--show-error"), QStringLiteral("--proto"), QStringLiteral("=https"),
        QStringLiteral("--tlsv1.2"), QStringLiteral("https://sh.rustup.rs"), QStringLiteral("--output"), script});
    if (!downloaded.started || downloaded.exitCode != 0 || !QFileInfo(script).isFile()) {
        if (error) {
            *error = QStringLiteral("Could not fetch rustup-init.sh over HTTPS: %1").arg(downloaded.error);
        }
        return false;
    }

    const bool keep = options.keepToolchain && !options.removeToolchain;
    if (keep) {
        *cargoHome = QDir(target).filePath(QStringLiteral(".cargo"));
        *rustupHome = QDir(target).filePath(QStringLiteral(".rustup"));
    } else {
        *cargoHome = QDir(stagingRoot).filePath(QStringLiteral("cargo"));
        *rustupHome = QDir(stagingRoot).filePath(QStringLiteral("rustup"));
    }
    QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
    environment.insert(QStringLiteral("CARGO_HOME"), *cargoHome);
    environment.insert(QStringLiteral("RUSTUP_HOME"), *rustupHome);
    const QStringList rustupArgs{script, QStringLiteral("-y"), QStringLiteral("--profile"), QStringLiteral("minimal"),
                                 QStringLiteral("--no-modify-path")};
    CommandResult installed;
    QString sudoUser = qEnvironmentVariable("SUDO_USER");
    bool installForInvokingUser = false;
#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
    installForInvokingUser = keep && ::geteuid() == 0 && !sudoUser.isEmpty() && sudoUser != QStringLiteral("root");
#endif
    if (installForInvokingUser) {
        const QByteArray userName = sudoUser.toLocal8Bit();
        const passwd *entry = getpwnam(userName.constData());
        if (!entry) {
            if (error) {
                *error = QStringLiteral("Could not resolve invoking account %1 for a persistent Rust toolchain.").arg(sudoUser);
            }
            return false;
        }
        if (::chown(QFile::encodeName(stagingRoot).constData(), entry->pw_uid, entry->pw_gid) != 0
            || ::chown(QFile::encodeName(script).constData(), entry->pw_uid, entry->pw_gid) != 0) {
            if (error) {
                *error = QStringLiteral("Could not hand temporary rustup files to invoking user %1.").arg(sudoUser);
            }
            return false;
        }
        QFile::setPermissions(stagingRoot, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
        QFile::setPermissions(script, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
        for (const QString &directory : {*cargoHome, *rustupHome}) {
            const QFileInfo existing(directory);
            if (existing.isSymLink()) {
                if (error) {
                    *error = QStringLiteral("Refusing to install Rust through a symbolic-link toolchain directory: %1").arg(directory);
                }
                return false;
            }
            if (existing.exists() && existing.ownerId() != entry->pw_uid) {
                if (error) {
                    *error = QStringLiteral("Rust toolchain directory is not owned by invoking user %1: %2").arg(sudoUser, directory);
                }
                return false;
            }
            const QString runner = QStandardPaths::findExecutable(
#if defined(Q_OS_LINUX)
                QStringLiteral("runuser")
#else
                QStringLiteral("sudo")
#endif
            );
            QStringList mkdirArgs;
#if defined(Q_OS_LINUX)
            mkdirArgs = {QStringLiteral("-u"), sudoUser, QStringLiteral("--"), QStringLiteral("/bin/mkdir"), QStringLiteral("-p"), directory};
#else
            mkdirArgs = {QStringLiteral("-u"), sudoUser, QStringLiteral("/bin/mkdir"), QStringLiteral("-p"), directory};
#endif
            const CommandResult made = runCommand(runner, mkdirArgs);
            if (!made.started || made.exitCode != 0) {
                if (error) {
                    *error = QStringLiteral("Could not create Rust toolchain directory for %1: %2").arg(sudoUser, made.error);
                }
                return false;
            }
        }
        installed = runAsUser(sudoUser, QStringLiteral("/bin/sh"), rustupArgs,
                              {QStringLiteral("CARGO_HOME=%1").arg(*cargoHome),
                               QStringLiteral("RUSTUP_HOME=%1").arg(*rustupHome)});
    } else {
        QDir().mkpath(*cargoHome);
        QDir().mkpath(*rustupHome);
        installed = runCommand(QStringLiteral("/bin/sh"), rustupArgs, environment);
    }
    if (!installed.started || installed.exitCode != 0) {
        if (error) {
            *error = QStringLiteral("rustup bootstrap failed: %1").arg(installed.error);
        }
        return false;
    }
    if (keep) {
        output->append(QStringLiteral("[ok] Installed a minimal stable Rust toolchain for the target user at %1 (as requested).")
                           .arg(*cargoHome));
    } else {
        output->append(QStringLiteral("[ok] Bootstrapped an isolated minimal Rust toolchain; temporary rustup/cargo data will be removed after the build."));
    }
    return true;
#endif
}

Result cleanupLegacyInstall(const Options &options) {
    Result result;
#if defined(Q_OS_LINUX)
    cleanKnownResidues(options, &result.output);
    if (options.action == Action::Uninstall) {
        const QString prefix = options.prefix.isEmpty() ? systemInstallPrefix() : QDir::cleanPath(options.prefix);
        const QString manifest = manifestPathForPrefix(prefix);
        const QFileInfo manifestInfo(manifest);
        if (!manifestInfo.exists() && !manifestInfo.isSymLink()) {
            QStringList unmanagedProductFiles{
                QDir(prefix).filePath(QStringLiteral("bin/vpngate")),
                QDir(prefix).filePath(QStringLiteral("bin/vpngate-gui")),
                QDir(prefix).filePath(QStringLiteral("share/icons/hicolor/scalable/apps/vpngate.svg")),
                QDir(prefix).filePath(QStringLiteral("share/applications/vpngate-gui.desktop")),
                QDir(prefix).filePath(QStringLiteral("share/vpngate/LICENSE")),
            };
            for (const int size : {16, 24, 32, 48, 64, 128, 256, 512}) {
                unmanagedProductFiles.append(QDir(prefix).filePath(
                    QStringLiteral("share/icons/hicolor/%1x%1/apps/vpngate.png").arg(size)));
            }
            for (const QString &path : unmanagedProductFiles) {
                removeKnownPath(options, path, &result.output, QStringLiteral("untracked legacy VPN Gate file"));
            }
        }
        const QStringList legacySystemFiles{
            QStringLiteral("/usr/local/bin/vpngate"), QStringLiteral("/usr/local/bin/vpngate-gui"),
            QStringLiteral("/usr/local/bin/vpngate.py"), QStringLiteral("/usr/local/bin/vpngate-launcher"),
            QStringLiteral("/usr/local/bin/vpngate-launcher.py"),
            QStringLiteral("/usr/share/applications/vpngate.desktop"),
            QStringLiteral("/usr/share/applications/vpngate-gui.desktop"),
            QStringLiteral("/usr/share/icons/hicolor/scalable/apps/vpngate.svg"),
            QStringLiteral("/usr/share/pixmaps/vpngate.png"),
        };
        for (const QString &path : legacySystemFiles) {
            removeKnownPath(options, path, &result.output, QStringLiteral("legacy VPN Gate installation file"));
        }
        for (const int size : {16, 24, 32, 48, 64, 128, 256, 512}) {
            removeKnownPath(options,
                QStringLiteral("/usr/share/icons/hicolor/%1x%1/apps/vpngate.png").arg(size),
                &result.output, QStringLiteral("legacy VPN Gate icon"));
        }
        const QStringList stateDirs{
            cacheDirectory(options), QDir(targetHome(options)).filePath(QStringLiteral(".config/vpngate")),
            QStringLiteral("/root/.cache/vpngate"), QStringLiteral("/root/.config/vpngate"),
        };
        for (const QString &directory : stateDirs) {
            removeKnownPath(options, directory, &result.output, QStringLiteral("VPN Gate app state"), true);
        }
        if (options.purgePackages) {
            if (!QStandardPaths::findExecutable(QStringLiteral("apt-get")).isEmpty()) {
                runOptional(options, QStringLiteral("apt-get"), {QStringLiteral("purge"), QStringLiteral("-y"), QStringLiteral("xl2tpd")},
                            &result.output, QStringLiteral("Purge xl2tpd as requested"));
                runOptional(options, QStringLiteral("apt-get"), {QStringLiteral("autoremove"), QStringLiteral("-y")},
                            &result.output, QStringLiteral("Remove unused dependencies"));
            } else if (!QStandardPaths::findExecutable(QStringLiteral("dnf")).isEmpty()) {
                runOptional(options, QStringLiteral("dnf"), {QStringLiteral("remove"), QStringLiteral("-y"), QStringLiteral("xl2tpd")},
                            &result.output, QStringLiteral("Purge xl2tpd as requested"));
            } else if (!QStandardPaths::findExecutable(QStringLiteral("pacman")).isEmpty()) {
                runOptional(options, QStringLiteral("pacman"), {QStringLiteral("-Rns"), QStringLiteral("--noconfirm"), QStringLiteral("xl2tpd")},
                            &result.output, QStringLiteral("Purge xl2tpd as requested"));
            }
        }
    }
#elif defined(Q_OS_MACOS)
    cleanMacOSResidues(options, &result.output);
    if (options.action == Action::Uninstall && options.purgePackages) {
        result.output.append(QStringLiteral("[skip] --purge-packages applies to Linux xl2tpd only; macOS Homebrew packages are left installed."));
    }
#elif defined(Q_OS_WIN)
    cleanWindowsResidues(options, &result.output);
#else
    result.exitCode = 1;
    result.output.append(QStringLiteral("[error] Full host integration is not available on this operating system."));
#endif
    return result;
}

Result prepareHostInstall(Options &options) {
    Result result = cleanupLegacyInstall(options);
    if (result.exitCode != 0) {
        return result;
    }
#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS) || defined(Q_OS_WIN)
    installRuntimePackages(options, &result.output);
    const bool hasError = std::any_of(result.output.cbegin(), result.output.cend(),
        [](const QString &line) { return line.startsWith(QStringLiteral("[error]")); });
    if (hasError) {
        result.exitCode = 1;
    }
#endif
    return result;
}

Result finishHostUninstall(const Options &options) {
    Result result;
#if defined(Q_OS_LINUX)
    runOptional(options, QStringLiteral("update-desktop-database"),
                {QStringLiteral("/usr/share/applications")}, &result.output,
                QStringLiteral("Refresh system desktop application database after uninstall"));
    runOptional(options, QStringLiteral("update-desktop-database"),
                {QStringLiteral("/usr/local/share/applications")}, &result.output,
                QStringLiteral("Refresh local desktop application database after uninstall"));
    const QString iconCacheTool = !QStandardPaths::findExecutable(QStringLiteral("gtk-update-icon-cache")).isEmpty()
        ? QStringLiteral("gtk-update-icon-cache") : QStringLiteral("update-icon-caches");
    if (iconCacheTool == QStringLiteral("gtk-update-icon-cache")) {
        runOptional(options, iconCacheTool,
                    {QStringLiteral("-f"), QStringLiteral("/usr/share/icons/hicolor")}, &result.output,
                    QStringLiteral("Refresh system hicolor icon cache after uninstall"));
        runOptional(options, iconCacheTool,
                    {QStringLiteral("-f"), QStringLiteral("/usr/local/share/icons/hicolor")}, &result.output,
                    QStringLiteral("Refresh local hicolor icon cache after uninstall"));
    } else {
        runOptional(options, iconCacheTool, {QStringLiteral("/usr/share/icons/hicolor")}, &result.output,
                    QStringLiteral("Refresh system hicolor icon cache after uninstall"));
        runOptional(options, iconCacheTool, {QStringLiteral("/usr/local/share/icons/hicolor")}, &result.output,
                    QStringLiteral("Refresh local hicolor icon cache after uninstall"));
    }
    if (options.dryRun) {
        result.output.append(QStringLiteral("[plan] Verify zero remaining VPN Gate binaries, launchers, desktop entries, icons, runtime state, and standard cache/config directories."));
        return result;
    }
    QStringList checks{
        QStringLiteral("/usr/local/bin/vpngate"), QStringLiteral("/usr/local/bin/vpngate-gui"),
        QStringLiteral("/usr/local/bin/vpngate.py"), QStringLiteral("/usr/local/bin/vpngate-launcher"),
        QStringLiteral("/usr/local/bin/vpngate-launcher.py"),
        QStringLiteral("/usr/share/applications/vpngate.desktop"),
        QStringLiteral("/usr/share/applications/vpngate-gui.desktop"),
        QStringLiteral("/usr/share/icons/hicolor/scalable/apps/vpngate.svg"),
        QStringLiteral("/usr/share/pixmaps/vpngate.png"), QStringLiteral("/run/vpngate-l2tp"),
        cacheDirectory(options), QDir(targetHome(options)).filePath(QStringLiteral(".config/vpngate")),
        QStringLiteral("/root/.cache/vpngate"), QStringLiteral("/root/.config/vpngate"),
        QStringLiteral("/usr/local/share/icons/hicolor/scalable/apps/vpngate.svg"),
        QStringLiteral("/usr/local/share/applications/vpngate-gui.desktop"),
        QStringLiteral("/usr/local/share/vpngate/installer-manifest.json"),
    };
    for (const int size : {16, 24, 32, 48, 64, 128, 256, 512}) {
        checks.append(QStringLiteral("/usr/share/icons/hicolor/%1x%1/apps/vpngate.png").arg(size));
        checks.append(QStringLiteral("/usr/local/share/icons/hicolor/%1x%1/apps/vpngate.png").arg(size));
    }
    QStringList leftovers;
    for (const QString &path : checks) {
        const QFileInfo info(path);
        if (info.exists() || info.isSymLink()) {
            leftovers.append(path);
        }
    }
    if (leftovers.isEmpty()) {
        result.output.append(QStringLiteral("[ok] Verification passed: no standard VPN Gate files or app-state residues remain."));
    } else {
        result.exitCode = 1;
        result.output.append(QStringLiteral("[error] Verification found remaining VPN Gate paths:"));
        for (const QString &path : leftovers) {
            result.output.append(QStringLiteral("  - %1").arg(path));
        }
    }
#elif defined(Q_OS_MACOS)
    const QString prefix = options.prefix.isEmpty() ? systemInstallPrefix() : QDir::cleanPath(options.prefix);
    const QStringList checks{
        QDir(prefix).filePath(QStringLiteral("bin/vpngate")),
        QDir(prefix).filePath(QStringLiteral("bin/vpngate-gui")),
        QDir(prefix).filePath(QStringLiteral("share/vpngate/LICENSE")),
        manifestPathForPrefix(prefix), cacheDirectory(options),
        QDir(targetHome(options)).filePath(QStringLiteral("Library/Caches/vpngate")),
        QDir(targetHome(options)).filePath(QStringLiteral(".config/vpngate")),
        QStringLiteral("/root/.cache/vpngate"), QStringLiteral("/root/.config/vpngate"),
        QStringLiteral("/usr/local/bin/vpngate.py"), QStringLiteral("/usr/local/bin/vpngate-launcher"),
    };
    if (options.dryRun) {
        result.output.append(QStringLiteral("[plan] Verify zero remaining VPN Gate binaries, legacy launchers, installer inventory, and standard cache/config directories."));
        return result;
    }
    QStringList leftovers;
    for (const QString &path : checks) {
        const QFileInfo info(path);
        if (info.exists() || info.isSymLink()) {
            leftovers.append(path);
        }
    }
    if (leftovers.isEmpty()) {
        result.output.append(QStringLiteral("[ok] Verification passed: no standard VPN Gate files or app-state residues remain."));
    } else {
        result.exitCode = 1;
        result.output.append(QStringLiteral("[error] Verification found remaining VPN Gate paths:"));
        for (const QString &path : leftovers) {
            result.output.append(QStringLiteral("  - %1").arg(path));
        }
    }
#elif defined(Q_OS_WIN)
    const QString prefix = options.prefix.isEmpty() ? systemInstallPrefix() : QDir::cleanPath(options.prefix);
    removeWindowsShortcuts(options, &result.output);
    updateWindowsUserPath(prefix, false, options.dryRun, &result.output);
    if (options.restoreNatTRule && !options.userOnly) {
        const QString policyKey = QStringLiteral("SYSTEM/CurrentControlSet/Services/PolicyAgent");
        const QString valueName = QStringLiteral("AssumeUDPEncapsulationContextOnSendRule");
        if (options.dryRun) {
            result.output.append(QStringLiteral("[plan] Restore the NAT-T policy by removing the PolicyAgent DWORD override."));
        } else if (!registryDeleteValue(HKEY_LOCAL_MACHINE, policyKey, valueName)) {
            result.exitCode = 1;
            result.output.append(QStringLiteral("[error] Could not restore the Windows NAT-T registry setting."));
        } else {
            result.output.append(QStringLiteral("[ok] Removed the PolicyAgent NAT-T override as requested."));
        }
    }
    if (options.dryRun) {
        result.output.append(QStringLiteral("[plan] Verify VPN Gate binaries, shims, shortcuts, app state, installer inventory, and User PATH residue."));
        return result;
    }
    QStringList checks{
        QDir(prefix).filePath(QStringLiteral("vpngate.exe")),
        QDir(prefix).filePath(QStringLiteral("vpngate-gui.exe")),
        QDir(prefix).filePath(QStringLiteral("vpngate.ico")),
        QDir(prefix).filePath(QStringLiteral("vpngate-256.png")),
        QDir(prefix).filePath(QStringLiteral("vpngate.py")),
        QDir(prefix).filePath(QStringLiteral("vpngate.ps1")),
        QDir(prefix).filePath(QStringLiteral("vpngate.cmd")),
        manifestPathForPrefix(prefix), cacheDirectory(options),
    };
    const QString primaryShortcut = windowsStartMenuLink(options);
    if (!primaryShortcut.isEmpty()) {
        checks.append(primaryShortcut);
        checks.append(QDir(QFileInfo(primaryShortcut).path()).filePath(QStringLiteral("VPN Gate Connect GUI.lnk")));
        checks.append(QDir(QFileInfo(primaryShortcut).path()).filePath(QStringLiteral("VPN Gate.lnk")));
    }
    QString userPath;
    bool userPathExists = false;
    if (!registryReadString(HKEY_CURRENT_USER, QStringLiteral("Environment"), QStringLiteral("Path"),
                            &userPath, nullptr, &userPathExists)) {
        checks.append(QStringLiteral("<current-user PATH registry value unreadable>"));
    } else {
        for (const QString &entry : userPath.split(QLatin1Char(';'), Qt::SkipEmptyParts)) {
            if (normalizeWindowsPathEntry(entry).compare(normalizeWindowsPathEntry(prefix), Qt::CaseInsensitive) == 0) {
                checks.append(QStringLiteral("<current-user PATH contains %1>").arg(prefix));
                break;
            }
        }
    }
    QStringList leftovers;
    for (const QString &path : checks) {
        if (path.startsWith(QLatin1Char('<'))) {
            leftovers.append(path);
            continue;
        }
        const QFileInfo info(path);
        if (info.exists() || info.isSymLink()) {
            leftovers.append(path);
        }
    }
    if (options.restoreNatTRule && !options.userOnly) {
        DWORD value = 0;
        bool exists = false;
        if (!registryReadDword(HKEY_LOCAL_MACHINE,
                QStringLiteral("SYSTEM/CurrentControlSet/Services/PolicyAgent"),
                QStringLiteral("AssumeUDPEncapsulationContextOnSendRule"), &value, &exists)) {
            leftovers.append(QStringLiteral("<PolicyAgent NAT-T registry value unreadable>"));
        } else if (exists) {
            leftovers.append(QStringLiteral("<PolicyAgent NAT-T override still present: %1>").arg(value));
        }
    }
    if (leftovers.isEmpty()) {
        result.output.append(QStringLiteral("[ok] Verification passed: no standard VPN Gate files, shortcuts, app state, PATH, or requested NAT-T override remain."));
    } else {
        result.exitCode = 1;
        result.output.append(QStringLiteral("[error] Verification found remaining VPN Gate state:"));
        for (const QString &path : leftovers) {
            result.output.append(QStringLiteral("  - %1").arg(path));
        }
    }
#endif
    return result;
}

Result finishHostInstall(const Options &options) {
    Result result;
    releaseCompilePackages(options, &result.output);
#if defined(Q_OS_LINUX)
    for (const QString &service : {QStringLiteral("xl2tpd.service"), QStringLiteral("kl2tpd.service"),
                                   QStringLiteral("strongswan.service"), QStringLiteral("strongswan-starter.service"),
                                   QStringLiteral("ipsec.service")}) {
        runOptional(options, QStringLiteral("systemctl"),
                    {QStringLiteral("disable"), QStringLiteral("--now"), service}, &result.output,
                    QStringLiteral("Disable conflicting system L2TP/IPsec service %1").arg(service));
    }
    for (const QString &applications : {QStringLiteral("/usr/share/applications"),
                                        QStringLiteral("/usr/local/share/applications")}) {
        runOptional(options, QStringLiteral("update-desktop-database"), {applications}, &result.output,
                    QStringLiteral("Refresh desktop application database: %1").arg(applications));
    }
    const QString iconCacheTool = !QStandardPaths::findExecutable(QStringLiteral("gtk-update-icon-cache")).isEmpty()
        ? QStringLiteral("gtk-update-icon-cache") : QStringLiteral("update-icon-caches");
    for (const QString &icons : {QStringLiteral("/usr/share/icons/hicolor"),
                                 QStringLiteral("/usr/local/share/icons/hicolor")}) {
        QStringList arguments;
        if (iconCacheTool == QStringLiteral("gtk-update-icon-cache")) {
            arguments = {QStringLiteral("-f"), icons};
        } else {
            arguments = {icons};
        }
        runOptional(options, iconCacheTool, arguments, &result.output,
                    QStringLiteral("Refresh hicolor icon cache: %1").arg(icons));
    }
    if (!options.dryRun) {
        QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
        environment.insert(QStringLiteral("VPNGATE_CACHE_DIR"), cacheDirectory(options));
        const QString cli = QStringLiteral("/usr/local/bin/vpngate");
        if (QFileInfo(cli).isExecutable()) {
            const CommandResult doctor = [&] {
                QProcess process;
                process.setProgram(cli);
                process.setArguments({QStringLiteral("doctor")});
                process.setProcessEnvironment(environment);
                process.setProcessChannelMode(QProcess::MergedChannels);
                process.start();
                if (!process.waitForStarted(5000)) {
                    return CommandResult{false, -1, {}, process.errorString()};
                }
                process.waitForFinished(-1);
                const QByteArray bytes = process.readAll();
                return CommandResult{true, process.exitCode(), QString::fromLocal8Bit(bytes).trimmed(), {}};
            }();
            if (!doctor.output.isEmpty()) {
                result.output.append(doctor.output.split(QLatin1Char('\n')));
            }
            if (!doctor.started || doctor.exitCode != 0) {
                result.output.append(QStringLiteral("[warn] The installed vpngate doctor readiness check did not pass."));
            }
        }
    } else {
        result.output.append(QStringLiteral("[plan] Run /usr/local/bin/vpngate doctor with the target user's VPNGATE_CACHE_DIR after installation."));
    }
#elif defined(Q_OS_MACOS)
    const QString cli = QDir(systemInstallPrefix()).filePath(QStringLiteral("bin/vpngate"));
    const QString cache = cacheDirectory(options);
    if (options.dryRun) {
        result.output.append(QStringLiteral("[plan] Run %1 doctor as the target user with VPNGATE_CACHE_DIR=%2 after installation.")
                                 .arg(cli, cache));
    } else if (QFileInfo(cli).isExecutable() && !QFileInfo(cli).isSymLink()) {
        const CommandResult doctor = runForTargetUser(options, cli, {QStringLiteral("doctor")},
            {QStringLiteral("VPNGATE_CACHE_DIR=%1").arg(cache)});
        if (!doctor.output.isEmpty()) {
            result.output.append(doctor.output.split(QLatin1Char('\n')));
        }
        if (!doctor.started || doctor.exitCode != 0) {
            result.output.append(QStringLiteral("[warn] The installed vpngate doctor readiness check did not pass: %1")
                                     .arg(doctor.error));
        }
    } else {
        result.output.append(QStringLiteral("[warn] The installed vpngate CLI was not found for the post-install doctor check."));
    }
#elif defined(Q_OS_WIN)
    const QString prefix = options.prefix.isEmpty() ? systemInstallPrefix() : QDir::cleanPath(options.prefix);
    const QString cache = cacheDirectory(options);
    updateWindowsUserPath(prefix, true, options.dryRun, &result.output);
    removeOpenVpnRunEntries(options, &result.output, !options.userOnly && isWindowsAdmin());

    if (!options.userOnly) {
        const QString policyKey = QStringLiteral("SYSTEM/CurrentControlSet/Services/PolicyAgent");
        const QString valueName = QStringLiteral("AssumeUDPEncapsulationContextOnSendRule");
        if (options.dryRun) {
            result.output.append(QStringLiteral("[plan] Set HKLM PolicyAgent AssumeUDPEncapsulationContextOnSendRule to DWORD 2 when NAT-T is not already enabled."));
            for (const QString &service : {QStringLiteral("PolicyAgent"), QStringLiteral("IKEEXT")}) {
                runOptional(options, QStringLiteral("sc.exe"), {QStringLiteral("stop"), service},
                            &result.output, QStringLiteral("Restart the Windows %1 service").arg(service));
                runOptional(options, QStringLiteral("sc.exe"), {QStringLiteral("start"), service},
                            &result.output, QStringLiteral("Restart the Windows %1 service").arg(service));
            }
            runOptional(options, QStringLiteral("sc.exe"), {QStringLiteral("start"), QStringLiteral("RasMan")},
                        &result.output, QStringLiteral("Start the Windows Remote Access Connection Manager"));
            result.output.append(QStringLiteral("[plan] Create HKLM Control/Network/NewNetworkWindowOff and configure OpenVPN firewall rules/TAP adapter if OpenVPN is available."));
        } else {
            DWORD natt = 0;
            bool nattExists = false;
            if (!registryReadDword(HKEY_LOCAL_MACHINE, policyKey, valueName, &natt, &nattExists)) {
                result.exitCode = 1;
                result.output.append(QStringLiteral("[error] Could not read the Windows NAT-T registry setting."));
            } else if (!nattExists || natt != 2) {
                if (!registrySetDword(HKEY_LOCAL_MACHINE, policyKey, valueName, 2)) {
                    result.exitCode = 1;
                    result.output.append(QStringLiteral("[error] Could not set the Windows NAT-T registry DWORD to 2."));
                } else {
                    result.output.append(QStringLiteral("[ok] Configured Windows L2TP/IPsec NAT-T registry value to DWORD 2."));
                    for (const QString &service : {QStringLiteral("PolicyAgent"), QStringLiteral("IKEEXT")}) {
                        runOptional(options, QStringLiteral("sc.exe"), {QStringLiteral("stop"), service},
                                    &result.output, QStringLiteral("Restart the Windows %1 service").arg(service));
                        runOptional(options, QStringLiteral("sc.exe"), {QStringLiteral("start"), service},
                                    &result.output, QStringLiteral("Restart the Windows %1 service").arg(service));
                    }
                    runOptional(options, QStringLiteral("sc.exe"), {QStringLiteral("start"), QStringLiteral("RasMan")},
                                &result.output, QStringLiteral("Start the Windows Remote Access Connection Manager"));
                }
            } else {
                result.output.append(QStringLiteral("[ok] Windows L2TP/IPsec NAT-T registry value is already DWORD 2."));
            }
            if (!registryCreateKey(HKEY_LOCAL_MACHINE,
                    QStringLiteral("SYSTEM/CurrentControlSet/Control/Network/NewNetworkWindowOff"))) {
                result.output.append(QStringLiteral("[warn] Could not create the Windows NewNetworkWindowOff key."));
            }

            const QString openvpn = findOpenVpnExecutable();
            if (openvpn.isEmpty()) {
                result.output.append(QStringLiteral("[warn] OpenVPN was not found; its firewall and TAP settings were skipped."));
            } else {
                for (const QString &rule : {QStringLiteral("VPNGate-OpenVPN-In"), QStringLiteral("VPNGate-OpenVPN-Out")}) {
                    runOptional(options, QStringLiteral("netsh.exe"),
                        {QStringLiteral("advfirewall"), QStringLiteral("firewall"), QStringLiteral("delete"),
                         QStringLiteral("rule"), QStringLiteral("name=%1").arg(rule)},
                        &result.output, QStringLiteral("Replace existing OpenVPN firewall rule %1").arg(rule));
                }
                runOptional(options, QStringLiteral("netsh.exe"),
                    {QStringLiteral("advfirewall"), QStringLiteral("firewall"), QStringLiteral("add"),
                     QStringLiteral("rule"), QStringLiteral("name=VPNGate-OpenVPN-In"),
                     QStringLiteral("dir=in"), QStringLiteral("action=allow"),
                     QStringLiteral("program=%1").arg(openvpn), QStringLiteral("enable=yes"),
                     QStringLiteral("profile=any")},
                    &result.output, QStringLiteral("Allow inbound OpenVPN traffic in Windows Firewall"));
                runOptional(options, QStringLiteral("netsh.exe"),
                    {QStringLiteral("advfirewall"), QStringLiteral("firewall"), QStringLiteral("add"),
                     QStringLiteral("rule"), QStringLiteral("name=VPNGate-OpenVPN-Out"),
                     QStringLiteral("dir=out"), QStringLiteral("action=allow"),
                     QStringLiteral("program=%1").arg(openvpn), QStringLiteral("enable=yes"),
                     QStringLiteral("profile=any")},
                    &result.output, QStringLiteral("Allow outbound OpenVPN traffic in Windows Firewall"));
                const CommandResult adapters = runCommand(openvpn, {QStringLiteral("--show-adapters")});
                const QString tapCtl = QDir(QFileInfo(openvpn).absolutePath()).filePath(QStringLiteral("tapctl.exe"));
                if (QFileInfo(tapCtl).isFile()
                    && !adapters.output.contains(QRegularExpression(QStringLiteral("\\btap-windows6\\b"),
                                                                     QRegularExpression::CaseInsensitiveOption))) {
                    runOptional(options, tapCtl,
                        {QStringLiteral("create"), QStringLiteral("--hwid"), QStringLiteral("root\\tap0901"),
                         QStringLiteral("--name"), QStringLiteral("VPNGate TAP")},
                        &result.output, QStringLiteral("Create the VPNGate TAP adapter required by OpenVPN"));
                }
            }
        }
    } else {
        result.output.append(QStringLiteral("[skip] User-only mode skipped machine NAT-T, service, firewall, and TAP changes."));
    }

    removeWindowsShortcuts(options, &result.output);
    createWindowsShortcut(options, &result.output);
    const QString cli = QDir(prefix).filePath(QStringLiteral("vpngate.exe"));
    if (options.dryRun) {
        result.output.append(QStringLiteral("[plan] Run %1 --cache-dir %2 doctor after installation.").arg(cli, cache));
    } else if (QFileInfo(cli).isExecutable() && !QFileInfo(cli).isSymLink()) {
        const CommandResult doctor = runCommand(cli,
            {QStringLiteral("--cache-dir"), cache, QStringLiteral("doctor")});
        if (!doctor.output.isEmpty()) {
            result.output.append(doctor.output.split(QLatin1Char('\n')));
        }
        if (!doctor.started || doctor.exitCode != 0) {
            result.output.append(QStringLiteral("[warn] The installed vpngate doctor readiness check did not pass: %1")
                                     .arg(doctor.error));
        }
    } else {
        result.output.append(QStringLiteral("[warn] The installed vpngate CLI was not found for the post-install doctor check."));
    }
#endif
    return result;
}

} // namespace vpngate::installer
