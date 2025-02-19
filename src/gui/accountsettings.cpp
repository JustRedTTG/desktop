/*
 * Copyright (C) by Daniel Molkentin <danimo@owncloud.com>
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


#include "accountsettings.h"
#include "common/syncjournalfilerecord.h"
#include "qmessagebox.h"
#include "ui_accountsettings.h"

#include "theme.h"
#include "foldercreationdialog.h"
#include "folderman.h"
#include "folderwizard.h"
#include "folderstatusmodel.h"
#include "folderstatusdelegate.h"
#include "common/utility.h"
#include "guiutility.h"
#include "application.h"
#include "configfile.h"
#include "account.h"
#include "accountstate.h"
#include "userinfo.h"
#include "accountmanager.h"
#include "owncloudsetupwizard.h"
#include "creds/abstractcredentials.h"
#include "creds/httpcredentialsgui.h"
#include "tooltipupdater.h"
#include "filesystem.h"
#include "encryptfolderjob.h"
#include "syncresult.h"
#include "ignorelisttablewidget.h"
#include "wizard/owncloudwizard.h"
#include "ui_mnemonicdialog.h"

#include <cmath>

#include <QDesktopServices>
#include <QDialogButtonBox>
#include <QDir>
#include <QListWidgetItem>
#include <QMessageBox>
#include <QAction>
#include <QVBoxLayout>
#include <QTreeView>
#include <QKeySequence>
#include <QIcon>
#include <QVariant>
#include <QJsonDocument>
#include <QToolTip>

#include "account.h"

namespace {
constexpr auto propertyFolder = "folder";
constexpr auto propertyPath = "path";
constexpr auto e2eUiActionIdKey = "id";
constexpr auto e2EeUiActionEnableEncryptionId = "enable_encryption";
constexpr auto e2EeUiActionDisplayMnemonicId = "display_mnemonic";
}

namespace OCC {

class AccountSettings;

Q_LOGGING_CATEGORY(lcAccountSettings, "nextcloud.gui.account.settings", QtInfoMsg)

static const char progressBarStyleC[] =
    "QProgressBar {"
    "border: 1px solid grey;"
    "border-radius: 5px;"
    "text-align: center;"
    "}"
    "QProgressBar::chunk {"
    "background-color: %1; width: 1px;"
    "}";

void showEnableE2eeWithVirtualFilesWarningDialog(std::function<void(void)> onAccept)
{
    const auto messageBox = new QMessageBox;
    messageBox->setAttribute(Qt::WA_DeleteOnClose);
    messageBox->setText(AccountSettings::tr("End-to-End Encryption with Virtual Files"));
    messageBox->setInformativeText(AccountSettings::tr("You seem to have the Virtual Files feature enabled on this folder. "
                                                       "At the moment, it is not possible to implicitly download virtual files that are "
                                                       "End-to-End encrypted. To get the best experience with Virtual Files and "
                                                       "End-to-End Encryption, make sure the encrypted folder is marked with "
                                                       "\"Make always available locally\"."));
    messageBox->setIcon(QMessageBox::Warning);
    const auto dontEncryptButton = messageBox->addButton(QMessageBox::StandardButton::Cancel);
    Q_ASSERT(dontEncryptButton);
    dontEncryptButton->setText(AccountSettings::tr("Do not encrypt folder"));
    const auto encryptButton = messageBox->addButton(QMessageBox::StandardButton::Ok);
    Q_ASSERT(encryptButton);
    encryptButton->setText(AccountSettings::tr("Encrypt folder"));
    QObject::connect(messageBox, &QMessageBox::accepted, onAccept);

    messageBox->open();
}

/**
 * Adjusts the mouse cursor based on the region it is on over the folder tree view.
 *
 * Used to show that one can click the red error list box by changing the cursor
 * to the pointing hand.
 */
class MouseCursorChanger : public QObject
{
    Q_OBJECT
public:
    MouseCursorChanger(QObject *parent)
        : QObject(parent)
    {
    }

    QTreeView *folderList;
    FolderStatusModel *model;

protected:
    bool eventFilter(QObject *watched, QEvent *event) override
    {
        if (event->type() == QEvent::HoverMove) {
            Qt::CursorShape shape = Qt::ArrowCursor;
            const auto pos = folderList->mapFromGlobal(QCursor::pos());
            const auto index = folderList->indexAt(pos);
            if (model->classify(index) == FolderStatusModel::RootFolder &&
                (FolderStatusDelegate::errorsListRect(folderList->visualRect(index)).contains(pos) ||
                    FolderStatusDelegate::optionsButtonRect(folderList->visualRect(index),folderList->layoutDirection()).contains(pos))) {
                shape = Qt::PointingHandCursor;
            }
            folderList->setCursor(shape);
        }
        return QObject::eventFilter(watched, event);
    }
};

AccountSettings::AccountSettings(AccountState *accountState, QWidget *parent)
    : QWidget(parent)
    , _ui(new Ui::AccountSettings)
    , _wasDisabledBefore(false)
    , _accountState(accountState)
    , _userInfo(accountState, false, true)
    , _menuShown(false)
{
    _ui->setupUi(this);

    _model = new FolderStatusModel;
    _model->setAccountState(_accountState);
    _model->setParent(this);
    const auto delegate = new FolderStatusDelegate;
    delegate->setParent(this);

    // Connect styleChanged events to our widgets, so they can adapt (Dark-/Light-Mode switching)
    connect(this, &AccountSettings::styleChanged, delegate, &FolderStatusDelegate::slotStyleChanged);

    _ui->_folderList->header()->hide();
    _ui->_folderList->setItemDelegate(delegate);
    _ui->_folderList->setModel(_model);
#if defined(Q_OS_MAC)
    _ui->_folderList->setMinimumWidth(400);
#else
    _ui->_folderList->setMinimumWidth(300);
#endif
    new ToolTipUpdater(_ui->_folderList);

    const auto mouseCursorChanger = new MouseCursorChanger(this);
    mouseCursorChanger->folderList = _ui->_folderList;
    mouseCursorChanger->model = _model;
    _ui->_folderList->setMouseTracking(true);
    _ui->_folderList->setAttribute(Qt::WA_Hover, true);
    _ui->_folderList->installEventFilter(mouseCursorChanger);

    connect(this, &AccountSettings::removeAccountFolders,
            AccountManager::instance(), &AccountManager::removeAccountFolders);
    connect(_ui->_folderList, &QWidget::customContextMenuRequested,
        this, &AccountSettings::slotCustomContextMenuRequested);
    connect(_ui->_folderList, &QAbstractItemView::clicked,
        this, &AccountSettings::slotFolderListClicked);
    connect(_ui->_folderList, &QTreeView::expanded, this, &AccountSettings::refreshSelectiveSyncStatus);
    connect(_ui->_folderList, &QTreeView::collapsed, this, &AccountSettings::refreshSelectiveSyncStatus);
    connect(_ui->selectiveSyncNotification, &QLabel::linkActivated,
        this, &AccountSettings::slotLinkActivated);
    connect(_model, &FolderStatusModel::suggestExpand, _ui->_folderList, &QTreeView::expand);
    connect(_model, &FolderStatusModel::dirtyChanged, this, &AccountSettings::refreshSelectiveSyncStatus);
    refreshSelectiveSyncStatus();
    connect(_model, &QAbstractItemModel::rowsInserted,
        this, &AccountSettings::refreshSelectiveSyncStatus);

    auto *syncNowAction = new QAction(this);
    syncNowAction->setShortcut(QKeySequence(Qt::Key_F6));
    connect(syncNowAction, &QAction::triggered, this, &AccountSettings::slotScheduleCurrentFolder);
    addAction(syncNowAction);

    auto *syncNowWithRemoteDiscovery = new QAction(this);
    syncNowWithRemoteDiscovery->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_F6));
    connect(syncNowWithRemoteDiscovery, &QAction::triggered, this, &AccountSettings::slotScheduleCurrentFolderForceRemoteDiscovery);
    addAction(syncNowWithRemoteDiscovery);


    slotHideSelectiveSyncWidget();
    _ui->bigFolderUi->setVisible(false);
    connect(_model, &QAbstractItemModel::dataChanged, this, &AccountSettings::slotSelectiveSyncChanged);
    connect(_ui->selectiveSyncApply, &QAbstractButton::clicked, this, &AccountSettings::slotHideSelectiveSyncWidget);
    connect(_ui->selectiveSyncCancel, &QAbstractButton::clicked, this, &AccountSettings::slotHideSelectiveSyncWidget);

    connect(_ui->selectiveSyncApply, &QAbstractButton::clicked, _model, &FolderStatusModel::slotApplySelectiveSync);
    connect(_ui->selectiveSyncCancel, &QAbstractButton::clicked, _model, &FolderStatusModel::resetFolders);
    connect(_ui->bigFolderApply, &QAbstractButton::clicked, _model, &FolderStatusModel::slotApplySelectiveSync);
    connect(_ui->bigFolderSyncAll, &QAbstractButton::clicked, _model, &FolderStatusModel::slotSyncAllPendingBigFolders);
    connect(_ui->bigFolderSyncNone, &QAbstractButton::clicked, _model, &FolderStatusModel::slotSyncNoPendingBigFolders);

    connect(FolderMan::instance(), &FolderMan::folderListChanged, _model, &FolderStatusModel::resetFolders);
    connect(this, &AccountSettings::folderChanged, _model, &FolderStatusModel::resetFolders);


    // quotaProgressBar style now set in customizeStyle()
    /*QColor color = palette().highlight().color();
     _ui->quotaProgressBar->setStyleSheet(QString::fromLatin1(progressBarStyleC).arg(color.name()));*/

    // Connect E2E stuff
    initializeE2eEncryption();

    _ui->connectLabel->setText(tr("No account configured."));

    connect(_accountState, &AccountState::stateChanged, this, &AccountSettings::slotAccountStateChanged);
    slotAccountStateChanged();

    connect(&_userInfo, &UserInfo::quotaUpdated,
        this, &AccountSettings::slotUpdateQuota);

    customizeStyle();
}

void AccountSettings::slotE2eEncryptionMnemonicReady()
{
    auto *const actionDisplayMnemonic = addActionToEncryptionMessage(tr("Display mnemonic"), e2EeUiActionDisplayMnemonicId);
    connect(actionDisplayMnemonic, &QAction::triggered, this, [this]() {
        displayMnemonic(_accountState->account()->e2e()->_mnemonic);
    });
    _ui->encryptionMessage->setText(tr("This account supports End-to-End encryption"));
    _ui->encryptionMessage->show();
    
}

void AccountSettings::slotE2eEncryptionGenerateKeys()
{
    connect(_accountState->account()->e2e(), &ClientSideEncryption::initializationFinished, this, &AccountSettings::slotE2eEncryptionInitializationFinished);
    _accountState->account()->setE2eEncryptionKeysGenerationAllowed(true);
    _accountState->account()->e2e()->initialize(_accountState->account());
}

void AccountSettings::slotE2eEncryptionInitializationFinished(bool isNewMnemonicGenerated)
{
    disconnect(_accountState->account()->e2e(), &ClientSideEncryption::initializationFinished, this, &AccountSettings::slotE2eEncryptionInitializationFinished);
    if (!_accountState->account()->e2e()->_mnemonic.isEmpty()) {
        removeActionFromEncryptionMessage(e2EeUiActionEnableEncryptionId);
        slotE2eEncryptionMnemonicReady();
        if (isNewMnemonicGenerated) {
            displayMnemonic(_accountState->account()->e2e()->_mnemonic);
        }
    }
}

void AccountSettings::slotEncryptFolderFinished(int status)
{
    qCInfo(lcAccountSettings) << "Current folder encryption status code:" << status;
    auto job = qobject_cast<EncryptFolderJob*>(sender());
    Q_ASSERT(job);
    if (!job->errorString().isEmpty()) {
        QMessageBox::warning(nullptr, tr("Warning"), job->errorString());
    }

    const auto folder = job->property(propertyFolder).value<Folder *>();
    Q_ASSERT(folder);
    const auto path = job->property(propertyPath).toString();
    const auto index = _model->indexForPath(folder, path);
    Q_ASSERT(index.isValid());
    _model->resetAndFetch(index.parent());

    job->deleteLater();
}

QString AccountSettings::selectedFolderAlias() const
{
    const auto selected = _ui->_folderList->selectionModel()->currentIndex();
    if (!selected.isValid()) {
        return "";
    }
    return _model->data(selected, FolderStatusDelegate::FolderAliasRole).toString();
}

void AccountSettings::slotToggleSignInState()
{
    if (_accountState->isSignedOut()) {
        _accountState->account()->resetRejectedCertificates();
        _accountState->signIn();
    } else {
        _accountState->signOutByUi();
    }
}

void AccountSettings::doExpand()
{
    // Make sure at least the root items are expanded
    for (int i = 0; i < _model->rowCount(); ++i) {
        const auto idx = _model->index(i);
        if (!_ui->_folderList->isExpanded(idx)) {
            _ui->_folderList->setExpanded(idx, true);
        }
    }
}

bool AccountSettings::canEncryptOrDecrypt (const FolderStatusModel::SubFolderInfo* info) {
    if (info->_folder->syncResult().status() != SyncResult::Status::Success) {
        QMessageBox msgBox;
        msgBox.setText("Please wait for the folder to sync before trying to encrypt it.");
        msgBox.exec();
        return false;
    }

    // for some reason the actual folder in disk is info->_folder->path + info->_path.
    QDir folderPath(info->_folder->path() + info->_path);
    folderPath.setFilter( QDir::AllEntries | QDir::NoDotAndDotDot );

    if (folderPath.count() != 0) {
        QMessageBox msgBox;
        msgBox.setText(tr("You cannot encrypt a folder with contents, please remove the files.\n"
                       "Wait for the new sync, then encrypt it."));
        msgBox.exec();
        return false;
    }
    return true;
}

void AccountSettings::slotMarkSubfolderEncrypted(FolderStatusModel::SubFolderInfo* folderInfo)
{
    if (!canEncryptOrDecrypt(folderInfo)) {
        return;
    }

    const auto folder = folderInfo->_folder;
    Q_ASSERT(folder);

    const auto folderAlias = folder->alias();
    const auto path = folderInfo->_path;
    const auto fileId = folderInfo->_fileId;
    const auto encryptFolder = [this, fileId, path, folderAlias] {
        const auto folder = FolderMan::instance()->folder(folderAlias);
        if (!folder) {
            qCWarning(lcAccountSettings) << "Could not encrypt folder because folder" << folderAlias << "does not exist anymore";
            QMessageBox::warning(nullptr, tr("Encryption failed"), tr("Could not encrypt folder because the folder does not exist anymore"));
            return;
        }

        // Folder info have directory paths in Foo/Bar/ convention...
        Q_ASSERT(!path.startsWith('/') && path.endsWith('/'));
        // But EncryptFolderJob expects directory path Foo/Bar convention
        const auto choppedPath = path.chopped(1);
        auto job = new OCC::EncryptFolderJob(accountsState()->account(), folder->journalDb(), choppedPath, fileId, this);
        job->setProperty(propertyFolder, QVariant::fromValue(folder));
        job->setProperty(propertyPath, QVariant::fromValue(path));
        connect(job, &OCC::EncryptFolderJob::finished, this, &AccountSettings::slotEncryptFolderFinished);
        job->start();
    };

    if (folder->virtualFilesEnabled() && folder->vfs().mode() == Vfs::WindowsCfApi) {
        showEnableE2eeWithVirtualFilesWarningDialog(encryptFolder);
        return;
    }
    encryptFolder();
}

void AccountSettings::slotEditCurrentIgnoredFiles()
{
    const auto folder = FolderMan::instance()->folder(selectedFolderAlias());
    if (!folder) {
        return;
    }
    openIgnoredFilesDialog(folder->path());
}

void AccountSettings::slotOpenMakeFolderDialog()
{
    const auto &selected = _ui->_folderList->selectionModel()->currentIndex();

    if (!selected.isValid()) {
        qCWarning(lcAccountSettings) << "Selection model current folder index is not valid.";
        return;
    }

    const auto &classification = _model->classify(selected);

    if (classification != FolderStatusModel::SubFolder && classification != FolderStatusModel::RootFolder) {
        return;
    }

    const auto fileName = [this, &selected, &classification] {
        QString result;
        if (classification == FolderStatusModel::RootFolder) {
            const auto alias = _model->data(selected, FolderStatusDelegate::FolderAliasRole).toString();
            if (const auto folder = FolderMan::instance()->folder(alias)) {
                result = folder->path();
            }
        } else {
            result = _model->data(selected, FolderStatusDelegate::FolderPathRole).toString();
        }

        if (result.endsWith('/')) {
            result.chop(1);
        }

        return result;
    }();

    if (!fileName.isEmpty()) {
        const auto folderCreationDialog = new FolderCreationDialog(fileName, this);
        folderCreationDialog->setAttribute(Qt::WA_DeleteOnClose);
        folderCreationDialog->open();
    }
}

void AccountSettings::slotEditCurrentLocalIgnoredFiles()
{
    const auto selected = _ui->_folderList->selectionModel()->currentIndex();
    if (!selected.isValid() || _model->classify(selected) != FolderStatusModel::SubFolder) {
        return;
    }
    const auto fileName = _model->data(selected, FolderStatusDelegate::FolderPathRole).toString();
    openIgnoredFilesDialog(fileName);
}

void AccountSettings::openIgnoredFilesDialog(const QString & absFolderPath)
{
    Q_ASSERT(QFileInfo(absFolderPath).isAbsolute());

    const QString ignoreFile{absFolderPath + ".sync-exclude.lst"};
    const auto layout = new QVBoxLayout();
    const auto ignoreListWidget = new IgnoreListTableWidget(this);
    ignoreListWidget->readIgnoreFile(ignoreFile);
    layout->addWidget(ignoreListWidget);

    const auto buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    layout->addWidget(buttonBox);

    const auto dialog = new QDialog();
    dialog->setLayout(layout);

    connect(buttonBox, &QDialogButtonBox::clicked, [=](QAbstractButton * button) {
        if (buttonBox->buttonRole(button) == QDialogButtonBox::AcceptRole) {
            ignoreListWidget->slotWriteIgnoreFile(ignoreFile);
        }
        dialog->close();
    });
    connect(buttonBox, &QDialogButtonBox::rejected, dialog, &QDialog::close);

    dialog->open();
}

void AccountSettings::slotSubfolderContextMenuRequested(const QModelIndex& index, const QPoint& pos)
{
    Q_UNUSED(pos);

    QMenu menu;
    auto ac = menu.addAction(tr("Open folder"));
    connect(ac, &QAction::triggered, this, &AccountSettings::slotOpenCurrentLocalSubFolder);

    const auto fileName = _model->data(index, FolderStatusDelegate::FolderPathRole).toString();
    if (!QFile::exists(fileName)) {
        ac->setEnabled(false);
    }
    const auto info = _model->infoForIndex(index);
    const auto acc = _accountState->account();

    if (acc->capabilities().clientSideEncryptionAvailable()) {
        // Verify if the folder is empty before attempting to encrypt.

        const auto isEncrypted = info->_isEncrypted;
        const auto isParentEncrypted = _model->isAnyAncestorEncrypted(index);

        if (!isEncrypted && !isParentEncrypted) {
            ac = menu.addAction(tr("Encrypt"));
            connect(ac, &QAction::triggered, [this, info] { slotMarkSubfolderEncrypted(info); });
        } else {
            // Ingore decrypting for now since it only works with an empty folder
            // connect(ac, &QAction::triggered, [this, &info] { slotMarkSubfolderDecrypted(info); });
        }
    }

    ac = menu.addAction(tr("Edit Ignored Files"));
    connect(ac, &QAction::triggered, this, &AccountSettings::slotEditCurrentLocalIgnoredFiles);

    ac = menu.addAction(tr("Create new folder"));
    connect(ac, &QAction::triggered, this, &AccountSettings::slotOpenMakeFolderDialog);
    ac->setEnabled(QFile::exists(fileName));

    const auto folder = info->_folder;
    if (folder && folder->virtualFilesEnabled()) {
        auto availabilityMenu = menu.addMenu(tr("Availability"));

        // Has '/' suffix convention for paths here but VFS and
        // sync engine expects no such suffix
        Q_ASSERT(info->_path.endsWith('/'));
        const auto remotePath = info->_path.chopped(1);

        // It might be an E2EE mangled path, so let's try to demangle it
        const auto journal = folder->journalDb();
        SyncJournalFileRecord rec;
        if (!journal->getFileRecordByE2eMangledName(remotePath, &rec)) {
            qCWarning(lcFolderStatus) << "Could not get file record by E2E Mangled Name from local DB" << remotePath;
        }

        const auto path = rec.isValid() ? rec._path : remotePath;

        ac = availabilityMenu->addAction(Utility::vfsPinActionText());
        connect(ac, &QAction::triggered, this, [this, folder, path] { slotSetSubFolderAvailability(folder, path, PinState::AlwaysLocal); });

        ac = availabilityMenu->addAction(Utility::vfsFreeSpaceActionText());
        connect(ac, &QAction::triggered, this, [this, folder, path] { slotSetSubFolderAvailability(folder, path, PinState::OnlineOnly); });
    }

    menu.exec(QCursor::pos());
}

void AccountSettings::slotCustomContextMenuRequested(const QPoint &pos)
{
    const auto treeView = _ui->_folderList;
    const auto index = treeView->indexAt(pos);
    if (!index.isValid()) {
        return;
    }

    if (_model->classify(index) == FolderStatusModel::SubFolder) {
        slotSubfolderContextMenuRequested(index, pos);
        return;
    }

    if (_model->classify(index) != FolderStatusModel::RootFolder) {
        return;
    }

    treeView->setCurrentIndex(index);
    const auto alias = _model->data(index, FolderStatusDelegate::FolderAliasRole).toString();
    const auto folderPaused = _model->data(index, FolderStatusDelegate::FolderSyncPaused).toBool();
    const auto folderConnected = _model->data(index, FolderStatusDelegate::FolderAccountConnected).toBool();
    const auto folderMan = FolderMan::instance();
    const auto folder = folderMan->folder(alias);

    if (!folder) {
        return;
    }

    const auto menu = new QMenu(treeView);

    menu->setAttribute(Qt::WA_DeleteOnClose);

    auto ac = menu->addAction(tr("Open folder"));
    connect(ac, &QAction::triggered, this, &AccountSettings::slotOpenCurrentFolder);

    ac = menu->addAction(tr("Edit Ignored Files"));
    connect(ac, &QAction::triggered, this, &AccountSettings::slotEditCurrentIgnoredFiles);

    ac = menu->addAction(tr("Create new folder"));
    connect(ac, &QAction::triggered, this, &AccountSettings::slotOpenMakeFolderDialog);
    ac->setEnabled(QFile::exists(folder->path()));

    if (!_ui->_folderList->isExpanded(index) && folder->supportsSelectiveSync()) {
        ac = menu->addAction(tr("Choose what to sync"));
        ac->setEnabled(folderConnected);
        connect(ac, &QAction::triggered, this, &AccountSettings::doExpand);
    }

    if (!folderPaused) {
        ac = menu->addAction(tr("Force sync now"));
        if (folder && folder->isSyncRunning()) {
            ac->setText(tr("Restart sync"));
        }
        ac->setEnabled(folderConnected);
        connect(ac, &QAction::triggered, this, &AccountSettings::slotForceSyncCurrentFolder);
    }

    ac = menu->addAction(folderPaused ? tr("Resume sync") : tr("Pause sync"));
    connect(ac, &QAction::triggered, this, &AccountSettings::slotEnableCurrentFolder);

    ac = menu->addAction(tr("Remove folder sync connection"));
    connect(ac, &QAction::triggered, this, &AccountSettings::slotRemoveCurrentFolder);

    if (folder->virtualFilesEnabled()) {
        auto availabilityMenu = menu->addMenu(tr("Availability"));

        ac = availabilityMenu->addAction(Utility::vfsPinActionText());
        connect(ac, &QAction::triggered, this, [this]() { slotSetCurrentFolderAvailability(PinState::AlwaysLocal); });
        ac->setDisabled(Theme::instance()->enforceVirtualFilesSyncFolder());

        ac = availabilityMenu->addAction(Utility::vfsFreeSpaceActionText());
        connect(ac, &QAction::triggered, this, [this]() { slotSetCurrentFolderAvailability(PinState::OnlineOnly); });

        ac = menu->addAction(tr("Disable virtual file support …"));
        connect(ac, &QAction::triggered, this, &AccountSettings::slotDisableVfsCurrentFolder);
        ac->setDisabled(Theme::instance()->enforceVirtualFilesSyncFolder());
    }

    if (Theme::instance()->showVirtualFilesOption() && !folder->virtualFilesEnabled() && Vfs::checkAvailability(folder->path())) {
        const auto mode = bestAvailableVfsMode();
        if (mode == Vfs::WindowsCfApi || ConfigFile().showExperimentalOptions()) {
            ac = menu->addAction(tr("Enable virtual file support %1 …").arg(mode == Vfs::WindowsCfApi ? QString() : tr("(experimental)")));
            // TODO: remove when UX decision is made
            ac->setEnabled(!Utility::isPathWindowsDrivePartitionRoot(folder->path()));
            //
            connect(ac, &QAction::triggered, this, &AccountSettings::slotEnableVfsCurrentFolder);
        }
    }


    menu->popup(treeView->mapToGlobal(pos));
}

void AccountSettings::slotFolderListClicked(const QModelIndex &indx)
{
    if (indx.data(FolderStatusDelegate::AddButton).toBool()) {
        // "Add Folder Sync Connection"
        const auto treeView = _ui->_folderList;
        const auto pos = treeView->mapFromGlobal(QCursor::pos());
        QStyleOptionViewItem opt;
        opt.initFrom(treeView);
        const auto btnRect = treeView->visualRect(indx);
        const auto btnSize = treeView->itemDelegate(indx)->sizeHint(opt, indx);
        const auto actual = QStyle::visualRect(opt.direction, btnRect, QRect(btnRect.topLeft(), btnSize));
        if (!actual.contains(pos)) {
            return;
        }

        if (indx.flags() & Qt::ItemIsEnabled) {
            slotAddFolder();
        } else {
            QToolTip::showText(
                QCursor::pos(),
                _model->data(indx, Qt::ToolTipRole).toString(),
                this);
        }
        return;
    }
    if (_model->classify(indx) == FolderStatusModel::RootFolder) {
        // tries to find if we clicked on the '...' button.
        const auto treeView = _ui->_folderList;
        const auto pos = treeView->mapFromGlobal(QCursor::pos());
        if (FolderStatusDelegate::optionsButtonRect(treeView->visualRect(indx), layoutDirection()).contains(pos)) {
            slotCustomContextMenuRequested(pos);
            return;
        }
        if (FolderStatusDelegate::errorsListRect(treeView->visualRect(indx)).contains(pos)) {
            emit showIssuesList(_accountState);
            return;
        }

        // Expand root items on single click
        if (_accountState && _accountState->state() == AccountState::Connected) {
            const auto expanded = !(_ui->_folderList->isExpanded(indx));
            _ui->_folderList->setExpanded(indx, expanded);
        }
    }
}

void AccountSettings::slotAddFolder()
{
    const auto folderMan = FolderMan::instance();
    folderMan->setSyncEnabled(false); // do not start more syncs.

    const auto folderWizard = new FolderWizard(_accountState->account(), this);
    folderWizard->setAttribute(Qt::WA_DeleteOnClose);

    connect(folderWizard, &QDialog::accepted, this, &AccountSettings::slotFolderWizardAccepted);
    connect(folderWizard, &QDialog::rejected, this, &AccountSettings::slotFolderWizardRejected);
    folderWizard->open();
}


void AccountSettings::slotFolderWizardAccepted()
{
    const auto folderWizard = qobject_cast<FolderWizard *>(sender());
    const auto folderMan = FolderMan::instance();

    qCInfo(lcAccountSettings) << "Folder wizard completed";

    FolderDefinition definition;
    definition.localPath = FolderDefinition::prepareLocalPath(
        folderWizard->field(QLatin1String("sourceFolder")).toString());
    definition.targetPath = FolderDefinition::prepareTargetPath(
        folderWizard->property("targetPath").toString());

    if (folderWizard->property("useVirtualFiles").toBool()) {
        definition.virtualFilesMode = bestAvailableVfsMode();
    }

    {
        QDir dir(definition.localPath);
        if (!dir.exists()) {
            qCInfo(lcAccountSettings) << "Creating folder" << definition.localPath;
            if (!dir.mkpath(".")) {
                QMessageBox::warning(this, tr("Folder creation failed"),
                    tr("<p>Could not create local folder <i>%1</i>.</p>")
                        .arg(QDir::toNativeSeparators(definition.localPath)));
                return;
            }
        }
        FileSystem::setFolderMinimumPermissions(definition.localPath);
        Utility::setupFavLink(definition.localPath);
    }

    /* take the value from the definition of already existing folders. All folders have
     * the same setting so far.
     * The default is to sync hidden files
     */
    definition.ignoreHiddenFiles = folderMan->ignoreHiddenFiles();

    if (folderMan->navigationPaneHelper().showInExplorerNavigationPane()) {
        definition.navigationPaneClsid = QUuid::createUuid();
    }

    const auto selectiveSyncBlackList = folderWizard->property("selectiveSyncBlackList").toStringList();

    folderMan->setSyncEnabled(true);

    const auto folder = folderMan->addFolder(_accountState, definition);
    if (folder) {
        if (definition.virtualFilesMode != Vfs::Off && folderWizard->property("useVirtualFiles").toBool()) {
            folder->setRootPinState(PinState::OnlineOnly);
        }

        folder->journalDb()->setSelectiveSyncList(SyncJournalDb::SelectiveSyncBlackList, selectiveSyncBlackList);

        // The user already accepted the selective sync dialog. everything is in the white list
        folder->journalDb()->setSelectiveSyncList(SyncJournalDb::SelectiveSyncWhiteList,
            QStringList() << QLatin1String("/"));
        folderMan->scheduleAllFolders();
        emit folderChanged();
    }
}

void AccountSettings::slotFolderWizardRejected()
{
    qCInfo(lcAccountSettings) << "Folder wizard cancelled";
    const auto folderMan = FolderMan::instance();
    folderMan->setSyncEnabled(true);
}

void AccountSettings::slotRemoveCurrentFolder()
{
    const auto folder = FolderMan::instance()->folder(selectedFolderAlias());
    const auto selected = _ui->_folderList->selectionModel()->currentIndex();
    if (selected.isValid() && folder) {
        const auto row = selected.row();

        qCInfo(lcAccountSettings) << "Remove Folder alias " << folder->alias();
        const auto shortGuiLocalPath = folder->shortGuiLocalPath();

        auto messageBox = new QMessageBox(QMessageBox::Question,
            tr("Confirm Folder Sync Connection Removal"),
            tr("<p>Do you really want to stop syncing the folder <i>%1</i>?</p>"
               "<p><b>Note:</b> This will <b>not</b> delete any files.</p>")
                .arg(shortGuiLocalPath),
            QMessageBox::NoButton,
            this);
        messageBox->setAttribute(Qt::WA_DeleteOnClose);
        const auto yesButton = messageBox->addButton(tr("Remove Folder Sync Connection"), QMessageBox::YesRole);
        messageBox->addButton(tr("Cancel"), QMessageBox::NoRole);
        connect(messageBox, &QMessageBox::finished, this, [messageBox, yesButton, folder, row, this]{
            if (messageBox->clickedButton() == yesButton) {
                Utility::removeFavLink(folder->path());
                FolderMan::instance()->removeFolder(folder);
                _model->removeRow(row);

                // single folder fix to show add-button and hide remove-button
                emit folderChanged();
            }
        });
        messageBox->open();
    }
}

void AccountSettings::slotOpenCurrentFolder()
{
    const auto alias = selectedFolderAlias();
    if (!alias.isEmpty()) {
        emit openFolderAlias(alias);
    }
}

void AccountSettings::slotOpenCurrentLocalSubFolder()
{
    const auto selected = _ui->_folderList->selectionModel()->currentIndex();
    if (!selected.isValid() || _model->classify(selected) != FolderStatusModel::SubFolder) {
        return;
    }
    const auto fileName = _model->data(selected, FolderStatusDelegate::FolderPathRole).toString();
    const auto url = QUrl::fromLocalFile(fileName);
    QDesktopServices::openUrl(url);
}

void AccountSettings::slotEnableVfsCurrentFolder()
{
    const auto folderMan = FolderMan::instance();
    const auto folder = folderMan->folder(selectedFolderAlias());
    const auto selected = _ui->_folderList->selectionModel()->currentIndex();

    if (!selected.isValid() || !folder) {
        return;
    }

    OwncloudWizard::askExperimentalVirtualFilesFeature(this, [folder, this](bool enable) {
        if (!enable || !folder) {
            return;
        }

        // we might need to add or remove the panel entry as cfapi brings this feature out of the box
        FolderMan::instance()->navigationPaneHelper().scheduleUpdateCloudStorageRegistry();

        // It is unsafe to switch on vfs while a sync is running - wait if necessary.
        const auto connection = std::make_shared<QMetaObject::Connection>();
        const auto switchVfsOn = [folder, connection, this]() {
            if (*connection) {
                QObject::disconnect(*connection);
            }

            qCInfo(lcAccountSettings) << "Enabling vfs support for folder" << folder->path();

            // Wipe selective sync blacklist
            auto ok = false;
            const auto oldBlacklist = folder->journalDb()->getSelectiveSyncList(SyncJournalDb::SelectiveSyncBlackList, &ok);
            folder->journalDb()->setSelectiveSyncList(SyncJournalDb::SelectiveSyncBlackList, {});

            // Change the folder vfs mode and load the plugin
            folder->setVirtualFilesEnabled(true);
            folder->setVfsOnOffSwitchPending(false);

            // Setting to Unspecified retains existing data.
            // Selective sync excluded folders become OnlineOnly.
            folder->setRootPinState(PinState::Unspecified);
            for (const auto &entry : oldBlacklist) {
                folder->journalDb()->schedulePathForRemoteDiscovery(entry);
                if (!folder->vfs().setPinState(entry, PinState::OnlineOnly)) {
                    qCWarning(lcAccountSettings) << "Could not set pin state of" << entry << "to online only";
                }
            }
            folder->slotNextSyncFullLocalDiscovery();

            FolderMan::instance()->scheduleFolder(folder);

            _ui->_folderList->doItemsLayout();
            _ui->selectiveSyncStatus->setVisible(false);
        };

        if (folder->isSyncRunning()) {
            *connection = connect(folder, &Folder::syncFinished, this, switchVfsOn);
            folder->setVfsOnOffSwitchPending(true);
            folder->slotTerminateSync();
            _ui->_folderList->doItemsLayout();
        } else {
            switchVfsOn();
        }
    });
}

void AccountSettings::slotDisableVfsCurrentFolder()
{
    const auto folderMan = FolderMan::instance();
    const auto folder = folderMan->folder(selectedFolderAlias());
    const auto selected = _ui->_folderList->selectionModel()->currentIndex();

    if (!selected.isValid() || !folder) {
        return;
    }

    const auto msgBox = new QMessageBox(
        QMessageBox::Question,
        tr("Disable virtual file support?"),
        tr("This action will disable virtual file support. As a consequence contents of folders that "
           "are currently marked as \"available online only\" will be downloaded."
           "\n\n"
           "The only advantage of disabling virtual file support is that the selective sync feature "
           "will become available again."
           "\n\n"
           "This action will abort any currently running synchronization."));
    const auto acceptButton = msgBox->addButton(tr("Disable support"), QMessageBox::AcceptRole);
    msgBox->addButton(tr("Cancel"), QMessageBox::RejectRole);
    connect(msgBox, &QMessageBox::finished, msgBox, [this, msgBox, folder, acceptButton] {
        msgBox->deleteLater();
        if (msgBox->clickedButton() != acceptButton|| !folder) {
            return;
        }

        // we might need to add or remove the panel entry as cfapi brings this feature out of the box
        FolderMan::instance()->navigationPaneHelper().scheduleUpdateCloudStorageRegistry();

        // It is unsafe to switch off vfs while a sync is running - wait if necessary.
        const auto connection = std::make_shared<QMetaObject::Connection>();
        const auto switchVfsOff = [folder, connection, this]() {
            if (*connection) {
                QObject::disconnect(*connection);
            }

            qCInfo(lcAccountSettings) << "Disabling vfs support for folder" << folder->path();

            // Also wipes virtual files, schedules remote discovery
            folder->setVirtualFilesEnabled(false);
            folder->setVfsOnOffSwitchPending(false);

            // Wipe pin states and selective sync db
            folder->setRootPinState(PinState::AlwaysLocal);
            folder->journalDb()->setSelectiveSyncList(SyncJournalDb::SelectiveSyncBlackList, {});

            // Prevent issues with missing local files
            folder->slotNextSyncFullLocalDiscovery();

            FolderMan::instance()->scheduleFolder(folder);

            _ui->_folderList->doItemsLayout();
        };

        if (folder->isSyncRunning()) {
            *connection = connect(folder, &Folder::syncFinished, this, switchVfsOff);
            folder->setVfsOnOffSwitchPending(true);
            folder->slotTerminateSync();
            _ui->_folderList->doItemsLayout();
        } else {
            switchVfsOff();
        }
    });
    msgBox->open();
}

void AccountSettings::slotSetCurrentFolderAvailability(PinState state)
{
    ASSERT(state == PinState::OnlineOnly || state == PinState::AlwaysLocal);

    const auto folderMan = FolderMan::instance();
    const auto folder = folderMan->folder(selectedFolderAlias());
    const auto selected = _ui->_folderList->selectionModel()->currentIndex();

    if (!selected.isValid() || !folder) {
        return;
    }

    // similar to socket api: sets pin state recursively and sync
    folder->setRootPinState(state);
    folder->scheduleThisFolderSoon();
}

void AccountSettings::slotSetSubFolderAvailability(Folder *folder, const QString &path, PinState state)
{
    Q_ASSERT(folder && folder->virtualFilesEnabled());
    Q_ASSERT(!path.endsWith('/'));

    // Update the pin state on all items
    if (!folder->vfs().setPinState(path, state)) {
        qCWarning(lcAccountSettings) << "Could not set pin state of" << path << "to" << state;
    }

    // Trigger sync
    folder->schedulePathForLocalDiscovery(path);
    folder->scheduleThisFolderSoon();
}

void AccountSettings::displayMnemonic(const QString &mnemonic)
{
    QDialog widget;
    Ui_Dialog ui;
    ui.setupUi(&widget);
    widget.setWindowTitle(tr("End-to-End encryption mnemonic"));
    ui.label->setText(
        tr("To protect your Cryptographic Identity, we encrypt it with a mnemonic of 12 dictionary words. "
           "Please note these down and keep them safe. "
           "They will be needed to add other devices to your account (like your mobile phone or laptop)."));
    QFont monoFont(QStringLiteral("Monospace"));
    monoFont.setStyleHint(QFont::TypeWriter);
    ui.lineEdit->setFont(monoFont);
    ui.lineEdit->setText(mnemonic);
    ui.lineEdit->setReadOnly(true);

    ui.lineEdit->setStyleSheet(QStringLiteral("QLineEdit{ color: black; background: lightgrey; border-style: inset;}"));

    ui.lineEdit->focusWidget();
    ui.lineEdit->selectAll();
    ui.lineEdit->setAlignment(Qt::AlignCenter);

    const QFont font(QStringLiteral(""), 0);
    QFontMetrics fm(font);
    ui.lineEdit->setFixedWidth(fm.horizontalAdvance(mnemonic));
    widget.resize(widget.sizeHint());
    widget.exec();
}

void AccountSettings::showConnectionLabel(const QString &message, QStringList errors)
{
    const auto errStyle = QLatin1String("color:#ffffff; background-color:#bb4d4d;padding:5px;"
                                        "border-width: 1px; border-style: solid; border-color: #aaaaaa;"
                                        "border-radius:5px;");
    if (errors.isEmpty()) {
        auto msg = message;
        Theme::replaceLinkColorStringBackgroundAware(msg);
        _ui->connectLabel->setText(msg);
        _ui->connectLabel->setToolTip({});
        _ui->connectLabel->setStyleSheet({});
    } else {
        errors.prepend(message);
        auto msg = errors.join(QLatin1String("\n"));
        qCDebug(lcAccountSettings) << msg;
        Theme::replaceLinkColorString(msg, QColor("#c1c8e6"));
        _ui->connectLabel->setText(msg);
        _ui->connectLabel->setToolTip({});
        _ui->connectLabel->setStyleSheet(errStyle);
    }
    _ui->accountStatus->setVisible(!message.isEmpty());
}

void AccountSettings::slotEnableCurrentFolder(bool terminate)
{
    const auto alias = selectedFolderAlias();

    if (!alias.isEmpty()) {
        const auto folderMan = FolderMan::instance();

        qCInfo(lcAccountSettings) << "Application: enable folder with alias " << alias;
        auto currentlyPaused = false;

        // this sets the folder status to disabled but does not interrupt it.
        const auto folder = folderMan->folder(alias);
        if (!folder) {
            return;
        }
        currentlyPaused = folder->syncPaused();
        if (!currentlyPaused && !terminate) {
            // check if a sync is still running and if so, ask if we should terminate.
            if (folder->isBusy()) { // its still running
                const auto msgbox = new QMessageBox(QMessageBox::Question, tr("Sync Running"),
                    tr("The syncing operation is running.<br/>Do you want to terminate it?"),
                    QMessageBox::Yes | QMessageBox::No, this);
                msgbox->setAttribute(Qt::WA_DeleteOnClose);
                msgbox->setDefaultButton(QMessageBox::Yes);
                connect(msgbox, &QMessageBox::accepted, this, [this]{
                    slotEnableCurrentFolder(true);
                });
                msgbox->open();
                return;
            }
        }

        // message box can return at any time while the thread keeps running,
        // so better check again after the user has responded.
        if (folder->isBusy() && terminate) {
            folder->slotTerminateSync();
        }
        folder->setSyncPaused(!currentlyPaused);

        // keep state for the icon setting.
        if (currentlyPaused) {
            _wasDisabledBefore = true;
        }

        _model->slotUpdateFolderState(folder);
    }
}

void AccountSettings::slotScheduleCurrentFolder()
{
    const auto folderMan = FolderMan::instance();
    if (auto folder = folderMan->folder(selectedFolderAlias())) {
        folderMan->scheduleFolder(folder);
    }
}

void AccountSettings::slotScheduleCurrentFolderForceRemoteDiscovery()
{
    const auto folderMan = FolderMan::instance();
    if (auto folder = folderMan->folder(selectedFolderAlias())) {
        folder->slotWipeErrorBlacklist();
        folder->journalDb()->forceRemoteDiscoveryNextSync();
        folderMan->scheduleFolder(folder);
    }
}

void AccountSettings::slotForceSyncCurrentFolder()
{
    FolderMan *folderMan = FolderMan::instance();
    auto selectedFolder = folderMan->folder(selectedFolderAlias());
    folderMan->forceSyncForFolder(selectedFolder);
}

void AccountSettings::slotOpenOC()
{
    if (_OCUrl.isValid()) {
        Utility::openBrowser(_OCUrl);
    }
}

void AccountSettings::slotUpdateQuota(qint64 total, qint64 used)
{
    if (total > 0) {
        _ui->quotaProgressBar->setVisible(true);
        _ui->quotaProgressBar->setEnabled(true);
        // workaround the label only accepting ints (which may be only 32 bit wide)
        const auto percent = used / (double)total * 100;
        const auto percentInt = qMin(qRound(percent), 100);
        _ui->quotaProgressBar->setValue(percentInt);
        const auto usedStr = Utility::octetsToString(used);
        const auto totalStr = Utility::octetsToString(total);
        const auto percentStr = Utility::compactFormatDouble(percent, 1);
        const auto toolTip = tr("%1 (%3%) of %2 in use. Some folders, including network mounted or shared folders, might have different limits.").arg(usedStr, totalStr, percentStr);
        _ui->quotaInfoLabel->setText(tr("%1 of %2 in use").arg(usedStr, totalStr));
        _ui->quotaInfoLabel->setToolTip(toolTip);
        _ui->quotaProgressBar->setToolTip(toolTip);
    } else {
        _ui->quotaProgressBar->setVisible(false);
        _ui->quotaInfoLabel->setToolTip({});

        /* -1 means not computed; -2 means unknown; -3 means unlimited  (#owncloud/client/issues/3940)*/
        if (total == 0 || total == -1) {
            _ui->quotaInfoLabel->setText(tr("Currently there is no storage usage information available."));
        } else {
            const auto usedStr = Utility::octetsToString(used);
            _ui->quotaInfoLabel->setText(tr("%1 in use").arg(usedStr));
        }
    }
}

void AccountSettings::slotAccountStateChanged()
{
    const auto state = _accountState ? _accountState->state() : AccountState::Disconnected;
    if (state != AccountState::Disconnected) {
        _ui->sslButton->updateAccountState(_accountState);
        const auto account = _accountState->account();
        auto safeUrl = account->url();
        safeUrl.setPassword({}); // Remove the password from the URL to avoid showing it in the UI
        const auto folders = FolderMan::instance()->map().values();
        for (const auto folder : folders) {
            _model->slotUpdateFolderState(folder);
        }

        const auto server = QString::fromLatin1("<a href=\"%1\">%2</a>")
                                .arg(Utility::escape(account->url().toString()),
                                    Utility::escape(safeUrl.toString()));
        auto serverWithUser = server;
        if (const auto cred = account->credentials()) {
            auto user = account->davDisplayName();
            if (user.isEmpty()) {
                user = cred->user();
            }
            serverWithUser = tr("%1 as %2").arg(server, Utility::escape(user));
        }

        switch (state) {
        case AccountState::Connected: {
            QStringList errors;
            if (account->serverVersionUnsupported()) {
                errors << tr("The server version %1 is unsupported! Proceed at your own risk.").arg(account->serverVersion());
            }
            showConnectionLabel(tr("Connected to %1.").arg(serverWithUser), errors);
            break;
        }
        case AccountState::ServiceUnavailable:
            showConnectionLabel(tr("Server %1 is temporarily unavailable.").arg(server));
            break;
        case AccountState::MaintenanceMode:
            showConnectionLabel(tr("Server %1 is currently in maintenance mode.").arg(server));
            break;
        case AccountState::SignedOut:
            showConnectionLabel(tr("Signed out from %1.").arg(serverWithUser));
            break;
        case AccountState::AskingCredentials: {
            QUrl url;
            if (const auto cred = qobject_cast<HttpCredentialsGui *>(account->credentials())) {
                connect(cred, &HttpCredentialsGui::authorisationLinkChanged,
                    this, &AccountSettings::slotAccountStateChanged, Qt::UniqueConnection);
                url = cred->authorisationLink();
            }
            if (url.isValid()) {
                showConnectionLabel(tr("Obtaining authorization from the browser. "
                                       "<a href='%1'>Click here</a> to re-open the browser.")
                                        .arg(url.toString(QUrl::FullyEncoded)));
            } else {
                showConnectionLabel(tr("Connecting to %1 …").arg(serverWithUser));
            }
            break;
        }
        case AccountState::NetworkError:
            showConnectionLabel(tr("No connection to %1 at %2.")
                                    .arg(Utility::escape(Theme::instance()->appNameGUI()), server),
                _accountState->connectionErrors());
            break;
        case AccountState::ConfigurationError:
            showConnectionLabel(tr("Server configuration error: %1 at %2.")
                                    .arg(Utility::escape(Theme::instance()->appNameGUI()), server),
                _accountState->connectionErrors());
            break;
        case AccountState::Disconnected:
            // we can't end up here as the whole block is ifdeffed
            Q_UNREACHABLE();
            break;
        }
    } else {
        // ownCloud is not yet configured.
        showConnectionLabel(tr("No %1 connection configured.")
                                .arg(Utility::escape(Theme::instance()->appNameGUI())));
    }

    /* Allow to expand the item if the account is connected. */
    _ui->_folderList->setItemsExpandable(state == AccountState::Connected);

    if (state != AccountState::Connected) {
        /* check if there are expanded root items, if so, close them */
        for (auto i = 0; i < _model->rowCount(); ++i) {
            if (_ui->_folderList->isExpanded(_model->index(i))) {
                _ui->_folderList->setExpanded(_model->index(i), false);
            }
        }
    } else if (_model->isDirty()) {
        // If we connect and have pending changes, show the list.
        doExpand();
    }

    // Disabling expansion of folders might require hiding the selective
    // sync user interface buttons.
    refreshSelectiveSyncStatus();

    if (state == AccountState::State::Connected) {
        /* TODO: We should probably do something better here.
         * Verify if the user has a private key already uploaded to the server,
         * if it has, do not offer to create one.
         */
        qCInfo(lcAccountSettings) << "Account" << accountsState()->account()->displayName()
            << "Client Side Encryption" << accountsState()->account()->capabilities().clientSideEncryptionAvailable();

        if (_accountState->account()->capabilities().clientSideEncryptionAvailable()) {
            _ui->encryptionMessage->show();
        }
    }
}

void AccountSettings::slotLinkActivated(const QString &link)
{
    // Parse folder alias and filename from the link, calculate the index
    // and select it if it exists.
    const auto li = link.split(QLatin1String("?folder="));
    if (li.count() > 1) {
        auto myFolder = li[0];
        const auto alias = li[1];
        if (myFolder.endsWith(QLatin1Char('/'))) {
            myFolder.chop(1);
        }

        // Make sure the folder itself is expanded
        const auto folder = FolderMan::instance()->folder(alias);
        const auto folderIndx = _model->indexForPath(folder, {});
        if (!_ui->_folderList->isExpanded(folderIndx)) {
            _ui->_folderList->setExpanded(folderIndx, true);
        }

        const auto indx = _model->indexForPath(folder, myFolder);
        if (indx.isValid()) {
            // make sure all the parents are expanded
            for (auto i = indx.parent(); i.isValid(); i = i.parent()) {
                if (!_ui->_folderList->isExpanded(i)) {
                    _ui->_folderList->setExpanded(i, true);
                }
            }
            _ui->_folderList->setSelectionMode(QAbstractItemView::SingleSelection);
            _ui->_folderList->setCurrentIndex(indx);
            _ui->_folderList->scrollTo(indx);
        } else {
            qCWarning(lcAccountSettings) << "Unable to find a valid index for " << myFolder;
        }
    }
}

AccountSettings::~AccountSettings()
{
    delete _ui;
}

void AccountSettings::slotHideSelectiveSyncWidget()
{
    _ui->selectiveSyncApply->setEnabled(false);
    _ui->selectiveSyncStatus->setVisible(false);
    _ui->selectiveSyncButtons->setVisible(false);
    _ui->selectiveSyncLabel->hide();
}

void AccountSettings::slotSelectiveSyncChanged(const QModelIndex &topLeft,
                                               const QModelIndex &bottomRight,
                                               const QVector<int> &roles)
{
    Q_UNUSED(bottomRight);
    if (!roles.contains(Qt::CheckStateRole)) {
        return;
    }

    const auto info = _model->infoForIndex(topLeft);
    if (!info) {
        return;
    }

    const auto showWarning = _model->isDirty() && _accountState->isConnected() && info->_checked == Qt::Unchecked;

    // FIXME: the model is not precise enough to handle extra cases
    // e.g. the user clicked on the same checkbox 2x without applying the change in between.
    // We don't know which checkbox changed to be able to toggle the selectiveSyncLabel display.
    if (showWarning) {
        _ui->selectiveSyncLabel->show();
    }

    const auto shouldBeVisible = _model->isDirty();
    const auto wasVisible = _ui->selectiveSyncStatus->isVisible();
    if (shouldBeVisible) {
        _ui->selectiveSyncStatus->setVisible(true);
    }

    _ui->selectiveSyncApply->setEnabled(true);
    _ui->selectiveSyncButtons->setVisible(true);

    if (shouldBeVisible != wasVisible) {
        const auto hint = _ui->selectiveSyncStatus->sizeHint();

        if (shouldBeVisible) {
            _ui->selectiveSyncStatus->setMaximumHeight(0);
        }

        const auto anim = new QPropertyAnimation(_ui->selectiveSyncStatus, "maximumHeight", _ui->selectiveSyncStatus);
        anim->setEndValue(_model->isDirty() ? hint.height() : 0);
        anim->start(QAbstractAnimation::DeleteWhenStopped);
        connect(anim, &QPropertyAnimation::finished, [this, shouldBeVisible]() {
            _ui->selectiveSyncStatus->setMaximumHeight(QWIDGETSIZE_MAX);
            if (!shouldBeVisible) {
                _ui->selectiveSyncStatus->hide();
            }
        });
    }
}

void AccountSettings::refreshSelectiveSyncStatus()
{
    QString msg;
    auto cnt = 0;
    const auto folders = FolderMan::instance()->map().values();
    _ui->bigFolderUi->setVisible(false);
    for (const auto folder : folders) {
        if (folder->accountState() != _accountState) {
            continue;
        }

        auto ok = false;
        const auto undecidedList = folder->journalDb()->getSelectiveSyncList(SyncJournalDb::SelectiveSyncUndecidedList, &ok);
        for (const auto &it : undecidedList) {
            // FIXME: add the folder alias in a hoover hint.
            // folder->alias() + QLatin1String("/")
            if (cnt++) {
                msg += QLatin1String(", ");
            }
            auto myFolder = (it);
            if (myFolder.endsWith('/')) {
                myFolder.chop(1);
            }
            const auto theIndx = _model->indexForPath(folder, myFolder);
            if (theIndx.isValid()) {
                msg += QString::fromLatin1("<a href=\"%1?folder=%2\">%1</a>")
                           .arg(Utility::escape(myFolder), Utility::escape(folder->alias()));
            } else {
                msg += myFolder; // no link because we do not know the index yet.
            }
        }
    }

    if (!msg.isEmpty()) {
        ConfigFile cfg;
        const auto info = !cfg.confirmExternalStorage() ?
                    tr("There are folders that were not synchronized because they are too big: ") :
                    !cfg.newBigFolderSizeLimit().first ?
                        tr("There are folders that were not synchronized because they are external storages: ") :
                        tr("There are folders that were not synchronized because they are too big or external storages: ");

        _ui->selectiveSyncNotification->setText(info + msg);
        _ui->bigFolderUi->setVisible(true);
    }
}

void AccountSettings::slotDeleteAccount()
{
    // Deleting the account potentially deletes 'this', so
    // the QMessageBox should be destroyed before that happens.
    const auto messageBox = new QMessageBox(QMessageBox::Question,
                                            tr("Confirm Account Removal"),
                                            tr("<p>Do you really want to remove the connection to the account <i>%1</i>?</p>"
                                               "<p><b>Note:</b> This will <b>not</b> delete any files.</p>")
                                            .arg(_accountState->account()->displayName()),
                                            QMessageBox::NoButton,
                                            this);
    const auto yesButton = messageBox->addButton(tr("Remove connection"), QMessageBox::YesRole);
    messageBox->addButton(tr("Cancel"), QMessageBox::NoRole);
    messageBox->setAttribute(Qt::WA_DeleteOnClose);
    connect(messageBox, &QMessageBox::finished, this, [this, messageBox, yesButton]{
        if (messageBox->clickedButton() == yesButton) {
            // Else it might access during destruction. This should be better handled by it having a QSharedPointer
            _model->setAccountState(nullptr);

            const auto manager = AccountManager::instance();
            manager->deleteAccount(_accountState);
            manager->save();
        }
    });
    messageBox->open();
}

bool AccountSettings::event(QEvent *e)
{
    if (e->type() == QEvent::Hide || e->type() == QEvent::Show) {
        _userInfo.setActive(isVisible());
    }
    if (e->type() == QEvent::Show) {
        // Expand the folder automatically only if there's only one, see #4283
        // The 2 is 1 folder + 1 'add folder' button
        if (_model->rowCount() <= 2) {
            _ui->_folderList->setExpanded(_model->index(0, 0), true);
        }
    }
    return QWidget::event(e);
}

void AccountSettings::slotStyleChanged()
{
    customizeStyle();

    // Notify the other widgets (Dark-/Light-Mode switching)
    emit styleChanged();
}

void AccountSettings::customizeStyle()
{
    auto msg = _ui->connectLabel->text();
    Theme::replaceLinkColorStringBackgroundAware(msg);
    _ui->connectLabel->setText(msg);

    const auto color = palette().highlight().color();
    _ui->quotaProgressBar->setStyleSheet(QString::fromLatin1(progressBarStyleC).arg(color.name()));
}

void AccountSettings::initializeE2eEncryption()
{
    if (!_accountState->account()->e2e()->_mnemonic.isEmpty()) {
        slotE2eEncryptionMnemonicReady();
    } else {
        _ui->encryptionMessage->setText(tr("This account supports End-to-End encryption"));
        _ui->encryptionMessage->hide();

        auto *const actionEnableE2e = addActionToEncryptionMessage(tr("Enable encryption"), e2EeUiActionEnableEncryptionId);
        connect(actionEnableE2e, &QAction::triggered, this, &AccountSettings::slotE2eEncryptionGenerateKeys);
    }
}

void AccountSettings::removeActionFromEncryptionMessage(const QString &actionId)
{
    const auto foundEnableEncryptionActionIt = std::find_if(std::cbegin(_ui->encryptionMessage->actions()), std::cend(_ui->encryptionMessage->actions()), [&actionId](const QAction *action) {
        return action->property(e2eUiActionIdKey).toString() == actionId;
    });
    if (foundEnableEncryptionActionIt != std::cend(_ui->encryptionMessage->actions())) {
        _ui->encryptionMessage->removeAction(*foundEnableEncryptionActionIt);
        (*foundEnableEncryptionActionIt)->deleteLater();
    }
}

QAction *AccountSettings::addActionToEncryptionMessage(const QString &actionTitle, const QString &actionId)
{
    const auto encryptionActions = _ui->encryptionMessage->actions();
    for (const auto &action : encryptionActions) {
        if (action->property(e2eUiActionIdKey) == actionId) {
            return action;
        }
    }

    auto *const action = new QAction(actionTitle, this);
    if (!actionId.isEmpty()) {
        action->setProperty(e2eUiActionIdKey, actionId);
    }
    _ui->encryptionMessage->addAction(action);
    return action;
}

} // namespace OCC

#include "accountsettings.moc"
