/*
 * Copyright (C) by Claudio Cambra <claudio.cambra@nextcloud.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 */

#include "editlocallyjob.h"

#include <QMessageBox>
#include <QDesktopServices>
#include <QtConcurrent>

#include "editlocallymanager.h"
#include "folder.h"
#include "folderman.h"
#include "syncengine.h"
#include "systray.h"

namespace OCC {

Q_LOGGING_CATEGORY(lcEditLocallyJob, "nextcloud.gui.editlocallyjob", QtInfoMsg)

EditLocallyJob::EditLocallyJob(const QString &userId,
                                       const QString &relPath,
                                       const QString &token,
                                       QObject *parent)
    : QObject{parent}
    , _userId(userId)
    , _relPath(relPath)
    , _token(token)
{
}

void EditLocallyJob::startSetup()
{
    if (_token.isEmpty() || _relPath.isEmpty() || _userId.isEmpty()) {
        qCWarning(lcEditLocallyJob) << "Could not start setup."
                                        << "token:" << _token
                                        << "relPath:" << _relPath
                                        << "userId" << _userId;
        return;
    }

    // Show the loading dialog but don't show the filename until we have
    // verified the token
    Systray::instance()->createEditFileLocallyLoadingDialog({});

    // We check the input data locally first, without modifying any state or
    // showing any potentially misleading data to the user
    if (!isTokenValid(_token)) {
        qCWarning(lcEditLocallyJob) << "Edit locally request is missing a valid token, will not open file. "
                                        << "Token received was:" << _token;
        showError(tr("Invalid token received."), tr("Please try again."));
        return;
    }

    if (!isRelPathValid(_relPath)) {
        qCWarning(lcEditLocallyJob) << "Provided relPath was:" << _relPath << "which is not canonical.";
        showError(tr("Invalid file path was provided."), tr("Please try again."));
        return;
    }

    _accountState = AccountManager::instance()->accountFromUserId(_userId);

    if (!_accountState) {
        qCWarning(lcEditLocallyJob) << "Could not find an account " << _userId << " to edit file " << _relPath << " locally.";
        showError(tr("Could not find an account for local editing."), tr("Please try again."));
        return;
    }

    // We now ask the server to verify the token, before we again modify any
    // state or look at local files
    startTokenRemoteCheck();
}

void EditLocallyJob::startTokenRemoteCheck()
{
    if (!_accountState || _relPath.isEmpty() || _token.isEmpty()) {
        qCWarning(lcEditLocallyJob) << "Could not start token check."
                                        << "accountState:" << _accountState
                                        << "relPath:" << _relPath
                                        << "token:" << _token;
        return;
    }

    const auto encodedToken = QString::fromUtf8(QUrl::toPercentEncoding(_token)); // Sanitise the token
    const auto encodedRelPath = QUrl::toPercentEncoding(_relPath); // Sanitise the relPath

    _checkTokenJob.reset(new SimpleApiJob(_accountState->account(),
                                          QStringLiteral("/ocs/v2.php/apps/files/api/v1/openlocaleditor/%1").arg(encodedToken)));

    QUrlQuery params;
    params.addQueryItem(QStringLiteral("path"), prefixSlashToPath(encodedRelPath));
    _checkTokenJob->addQueryParams(params);
    _checkTokenJob->setVerb(SimpleApiJob::Verb::Post);
    connect(_checkTokenJob.get(), &SimpleApiJob::resultReceived, this, &EditLocallyJob::remoteTokenCheckResultReceived);

    _checkTokenJob->start();
}

void EditLocallyJob::remoteTokenCheckResultReceived(const int statusCode)
{
    qCInfo(lcEditLocallyJob) << "token check result" << statusCode;

    constexpr auto HTTP_OK_CODE = 200;
    _tokenVerified = statusCode == HTTP_OK_CODE;

    if (!_tokenVerified) {
        showError(tr("Could not validate the request to open a file from server."), tr("Please try again."));
        return;
    }

    QString remoteParentPath = QStringLiteral("/");

    auto relPathSplit = _relPath.split(QLatin1Char('/'));
    if (relPathSplit.size() > 1) {
        relPathSplit.removeLast();
        remoteParentPath = relPathSplit.join(QLatin1Char('/'));
    }

    QVariantMap items;

    const auto job = new LsColJob(_accountState->account(), remoteParentPath, this);
    QList<QByteArray> props;
    props << "resourcetype"
          << "getlastmodified"
          << "getcontentlength"
          << "getetag"
          << "http://owncloud.org/ns:size"
          << "http://owncloud.org/ns:id"
          << "http://owncloud.org/ns:fileid"
          << "http://owncloud.org/ns:dDC"
          << "http://owncloud.org/ns:permissions"
          << "http://owncloud.org/ns:checksums";

    job->setProperties(props);
    connect(job, &LsColJob::directoryListingIterated, this, [&items, this](const QString &name, const QMap<QString, QString> &properties) {
        if (name.endsWith(_relPath)) {
            SyncFileItemPtr item(new SyncFileItem);
            item->_file = _relPath;
            item->_size = properties.value(QStringLiteral("size")).toInt();
            item->_fileId = properties.value(QStringLiteral("fileId")).toUtf8();
            const auto isDirectory = properties.value(QStringLiteral("resourcetype")).contains(QStringLiteral("collection"));
            item->_type = isDirectory ? ItemTypeDirectory : ItemTypeFile;

            if (properties.contains(QStringLiteral("permissions"))) {
                item->_remotePerm = RemotePermissions::fromServerString(properties.value("permissions"));
                item->_isShared = item->_remotePerm.hasPermission(RemotePermissions::IsShared);
                item->_lastShareStateFetchedTimestmap = QDateTime::currentMSecsSinceEpoch();
            }

            if (!properties.value(QStringLiteral("share-types")).isEmpty()) {
                item->_remotePerm.setPermission(RemotePermissions::IsShared);
                item->_isShared = true;
                item->_lastShareStateFetchedTimestmap = QDateTime::currentMSecsSinceEpoch();
            }

            item->_isEncrypted = properties.value(QStringLiteral("is-encrypted")) == QStringLiteral("1");
            item->_locked = properties.value(QStringLiteral("lock")) == QStringLiteral("1")
                ? SyncFileItem::LockStatus::LockedItem
                : SyncFileItem::LockStatus::UnlockedItem;
            item->_lockOwnerDisplayName = properties.value(QStringLiteral("lock-owner-displayname"));
            item->_lockOwnerId = properties.value(QStringLiteral("lock-owner"));
            item->_lockEditorApp = properties.value(QStringLiteral("lock-owner-editor"));

            {
                auto ok = false;
                const auto intConvertedValue = properties.value(QStringLiteral("lock-owner-type")).toULongLong(&ok);
                if (ok) {
                    item->_lockOwnerType = static_cast<SyncFileItem::LockOwnerType>(intConvertedValue);
                } else {
                    item->_lockOwnerType = SyncFileItem::LockOwnerType::UserLock;
                }
            }

            {
                auto ok = false;
                const auto intConvertedValue = properties.value(QStringLiteral("lock-time")).toULongLong(&ok);
                if (ok) {
                    item->_lockTime = intConvertedValue;
                } else {
                    item->_lockTime = 0;
                }
            }

            {
                auto ok = false;
                const auto intConvertedValue = properties.value(QStringLiteral("lock-timeout")).toULongLong(&ok);
                if (ok) {
                    item->_lockTimeout = intConvertedValue;
                } else {
                    item->_lockTimeout = 0;
                }
            }

            const auto date = QDateTime::fromString(properties.value(QStringLiteral("getlastmodified")), Qt::RFC2822Date);
            Q_ASSERT(date.isValid());
            if (date.toSecsSinceEpoch() > 0) {
                item->_modtime = date.toSecsSinceEpoch();
            }

            if (properties.contains(QStringLiteral("getetag"))) {
                item->_etag = parseEtag(properties.value(QStringLiteral("getetag")).toUtf8());
            }

            if (properties.contains(QStringLiteral("checksums"))) {
                item->_checksumHeader = findBestChecksum(properties.value("checksums").toUtf8());
            }

            _item = item;
        }
    });
    connect(job, &LsColJob::finishedWithoutError, this, [this]() {
        proceedWithSetup();
    });
    job->start();
}

void EditLocallyJob::proceedWithSetup()
{
    if (!_tokenVerified) {
        qCWarning(lcEditLocallyJob) << "Could not proceed with setup as token is not verified.";
        return;
    }

    if (!_item || _item->isEmpty()) {
        showError(tr("Could not find a file for local editing. Make sure its path is valid and it is synced locally."), _relPath);
        return;
    }

    const auto relPathSplit = _relPath.split(QLatin1Char('/'));
    if (relPathSplit.isEmpty()) {
        showError(tr("Could not find a file for local editing. Make sure its path is valid and it is synced locally."), _relPath);
        return;
    }

    _fileName = relPathSplit.last();

    _folderForFile = findFolderForFile(_relPath, _userId);

    if (!_folderForFile) {
        showError(tr("Could not find a file for local editing. Make sure it is not excluded via selective sync."), _relPath);
        return;
    }

    _localFilePath = _folderForFile->path() + _relPath;

    Systray::instance()->destroyEditFileLocallyLoadingDialog();
    Q_EMIT setupFinished();
}

QString EditLocallyJob::prefixSlashToPath(const QString &path)
{
    return path.startsWith('/') ? path : QChar::fromLatin1('/') + path;
}

bool EditLocallyJob::isTokenValid(const QString &token)
{
    if (token.isEmpty()) {
        return false;
    }

    // Token is an alphanumeric string 128 chars long.
    // Ensure that is what we received and what we are sending to the server.
    const QRegularExpression tokenRegex("^[a-zA-Z0-9]{128}$");
    const auto regexMatch = tokenRegex.match(token);

    return regexMatch.hasMatch();
}

bool EditLocallyJob::isRelPathValid(const QString &relPath)
{
    if (relPath.isEmpty()) {
        return false;
    }

    // We want to check that the path is canonical and not relative
    // (i.e. that it doesn't contain ../../) but we always receive
    // a relative path, so let's make it absolute by prepending a
    // slash
    const auto slashPrefixedPath = prefixSlashToPath(relPath);

    // Let's check that the filepath is canonical, and that the request
    // contains no funny behaviour regarding paths
    const auto cleanedPath = QDir::cleanPath(slashPrefixedPath);

    if (cleanedPath != slashPrefixedPath) {
        return false;
    }

    return true;
}

OCC::Folder *EditLocallyJob::findFolderForFile(const QString &relPath, const QString &userId)
{
    if (relPath.isEmpty()) {
        return nullptr;
    }

    const auto folderMap = FolderMan::instance()->map();

    const auto relPathSplit = relPath.split(QLatin1Char('/'));

    if (relPathSplit.size() == 1) {
        const auto foundIt = std::find_if(std::begin(folderMap), std::end(folderMap), [&userId](const OCC::Folder *folder) {
            return folder->remotePath() == QStringLiteral("/") && folder->accountState()->account()->userIdAtHostWithPort() == userId;
        });

        return foundIt != std::end(folderMap) ? foundIt.value() : nullptr;
    }

    for (const auto &folder : folderMap) {
        if (relPathSplit.size() > 1 && folder->remotePath() != QStringLiteral("/") && !relPath.startsWith(folder->remotePath())) {
            continue;
        }
        if (folder->accountState()->account()->userIdAtHostWithPort() != userId) {
            continue;
        }
        bool result = false;
        const auto excludedThroughSelectiveSync = folder->journalDb()->getSelectiveSyncList(SyncJournalDb::SelectiveSyncBlackList, &result);
        for (const auto &excludedPath : excludedThroughSelectiveSync) {
            if (relPath.startsWith(excludedPath)) {
                return nullptr;
            }
        }
        return folder;
    }

    return nullptr;
}

void EditLocallyJob::showError(const QString &message, const QString &informativeText)
{
    Systray::instance()->destroyEditFileLocallyLoadingDialog();
    showErrorNotification(message, informativeText);
    // to make sure the error is not missed, show a message box in addition
    showErrorMessageBox(message, informativeText);
    Q_EMIT error(message, informativeText);
}

void EditLocallyJob::showErrorNotification(const QString &message, const QString &informativeText) const
{
    if (!_accountState || !_accountState->account()) {
        return;
    }

    const auto folderMap = FolderMan::instance()->map();
    const auto foundFolder = std::find_if(folderMap.cbegin(), folderMap.cend(), [this](const auto &folder) {
        return _accountState->account()->davUrl() == folder->remoteUrl();
    });

    if (foundFolder != folderMap.cend()) {
        (*foundFolder)->syncEngine().addErrorToGui(SyncFileItem::SoftError, message, informativeText);
    }
}

void EditLocallyJob::showErrorMessageBox(const QString &message, const QString &informativeText) const
{
    const auto messageBox = new QMessageBox;
    messageBox->setAttribute(Qt::WA_DeleteOnClose);
    messageBox->setText(message);
    messageBox->setInformativeText(informativeText);
    messageBox->setIcon(QMessageBox::Warning);
    messageBox->addButton(QMessageBox::StandardButton::Ok);
    messageBox->show();
    messageBox->activateWindow();
    messageBox->raise();
}

void EditLocallyJob::startEditLocally()
{
    if (_fileName.isEmpty() || _localFilePath.isEmpty() || !_folderForFile) {
        qCWarning(lcEditLocallyJob) << "Could not start to edit locally."
                                        << "fileName:" << _fileName
                                        << "localFilePath:" << _localFilePath
                                        << "folderForFile:" << _folderForFile;
        return;
    }

    Systray::instance()->createEditFileLocallyLoadingDialog(_fileName);

    // try to subscribe for specific sync item's 'finished' signal
    if (_folderForFile->isSyncRunning()/* && !_folderForFile->vfs().isHydrating()*/) {
        const auto syncFinishedConnectionWaitTerminate = connect(_folderForFile, &Folder::syncFinished, this, [this]() {
            disconnectSyncFinished();

            const auto itemDiscoveredConnection = QObject::connect(&_folderForFile->syncEngine(), &SyncEngine::itemDiscovered, this, &EditLocallyJob::slotItemDiscovered);
            EditLocallyManager::instance()->folderItemDiscoveredConnections.insert(_localFilePath, itemDiscoveredConnection);

            _folderForFile->startSync(_relPath, _item);
        });

        EditLocallyManager::instance()->folderSyncFinishedConnections.insert(_localFilePath, syncFinishedConnectionWaitTerminate);
        _folderForFile->slotTerminateSync();

        return;
    }

    const auto itemDiscoveredConnection = QObject::connect(&_folderForFile->syncEngine(), &SyncEngine::itemDiscovered, this, &EditLocallyJob::slotItemDiscovered);
    EditLocallyManager::instance()->folderItemDiscoveredConnections.insert(_localFilePath, itemDiscoveredConnection);
    _folderForFile->startSync(_relPath, _item);
}

void EditLocallyJob::slotItemCompleted(const OCC::SyncFileItemPtr &item)
{
    if (item->_file == _relPath) {
        disconnectItemCompleted();
        disconnectItemDiscovered();
        disconnectSyncFinished();
        openFile();
    }
}

void EditLocallyJob::slotItemDiscovered(const OCC::SyncFileItemPtr &item)
{
    if (item->_file == _relPath) {
        disconnectItemDiscovered();
        if (item->_instruction == CSYNC_INSTRUCTION_NONE) {
            slotItemCompleted(item);
            return;
        }
        const auto itemCompletedConnection = QObject::connect(&_folderForFile->syncEngine(), &SyncEngine::itemCompleted, this, &EditLocallyJob::slotItemCompleted);
        EditLocallyManager::instance()->folderItemCompletedConnections.insert(_localFilePath, itemCompletedConnection);
    }
}

void EditLocallyJob::disconnectItemCompleted() const
{
    if (_localFilePath.isEmpty()) {
        return;
    }

    const auto manager = EditLocallyManager::instance();

    if (const auto existingConnection = manager->folderItemCompletedConnections.value(_localFilePath)) {
        disconnect(existingConnection);
        manager->folderItemCompletedConnections.remove(_localFilePath);
    }
}

void EditLocallyJob::disconnectItemDiscovered() const
{
    if (_localFilePath.isEmpty()) {
        return;
    }

    const auto manager = EditLocallyManager::instance();

    if (const auto existingConnection = manager->folderItemDiscoveredConnections.value(_localFilePath)) {
        disconnect(existingConnection);
        manager->folderItemDiscoveredConnections.remove(_localFilePath);
    }
}

void EditLocallyJob::disconnectSyncFinished() const
{
    if(_localFilePath.isEmpty()) {
        return;
    }

    const auto manager = EditLocallyManager::instance();

    if (const auto existingConnection = manager->folderSyncFinishedConnections.value(_localFilePath)) {
        disconnect(existingConnection);
        manager->folderSyncFinishedConnections.remove(_localFilePath);
    }
}

void EditLocallyJob::openFile()
{
    if(_localFilePath.isEmpty()) {
        qCWarning(lcEditLocallyJob) << "Could not edit locally. Invalid local file path.";
        return;
    }

    const auto localFilePath = _localFilePath;
    // In case the VFS mode is enabled and a file is not yet hydrated, we must call QDesktopServices::openUrl
    // from a separate thread, or, there will be a freeze. To avoid searching for a specific folder and checking
    // if the VFS is enabled - we just always call it from a separate thread.
    QtConcurrent::run([localFilePath]() {
        QDesktopServices::openUrl(QUrl::fromLocalFile(localFilePath));
        Systray::instance()->destroyEditFileLocallyLoadingDialog();
    });

    Q_EMIT fileOpened();
}

}
