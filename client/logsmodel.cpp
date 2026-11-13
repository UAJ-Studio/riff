/*
Copyright (C) 2018 Srivats P.

This file is part of "Ostinato"

This is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
*/

#include "logsmodel.h"

#include "logtranslator.h"
#include "thememanager.h"

#include <QBrush>
#include <QFont>

// XXX: Keep the enum in sync with it's string
enum {
    kTimeStamp,
    kLogLevel,
    kPort,
    kMessage,
    kFieldCount
};
// Translated where used - these lists are built before the UI translator
// is installed
static QStringList columnTitles = QStringList()
    << QT_TRANSLATE_NOOP("LogsModel", "Timestamp")
    << QT_TRANSLATE_NOOP("LogsModel", "Level")
    << QT_TRANSLATE_NOOP("LogsModel", "Port")
    << QT_TRANSLATE_NOOP("LogsModel", "Message");

static QStringList levelTitles = QStringList()
    << QT_TRANSLATE_NOOP("LogsModel", "Info")
    << QT_TRANSLATE_NOOP("LogsModel", "Warning")
    << QT_TRANSLATE_NOOP("LogsModel", "Error");

static QString levelTitle(int level)
{
    return QCoreApplication::translate("LogsModel",
            levelTitles.at(level).toUtf8().constData());
}

LogsModel::LogsModel(QObject *parent)
    : QAbstractTableModel(parent)
{
}

int LogsModel::rowCount(const QModelIndex &/*parent*/) const
{
    return logs_.size();
}

int LogsModel::columnCount(const QModelIndex &/*parent*/) const
{
    return kFieldCount;
}

QVariant LogsModel::headerData(
        int section, Qt::Orientation orientation, int role) const
{
    if (role != Qt::DisplayRole)
        return QVariant();

    switch (orientation) {
    case Qt::Horizontal: // Column Header
        return QCoreApplication::translate("LogsModel",
                columnTitles.at(section).toUtf8().constData());
    case Qt::Vertical:   // Row Header
        return QVariant();
    default:
        break;
    }
    return QVariant();
}

QVariant LogsModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || (index.row() >= logs_.size()))
            return QVariant();

    // Errors/warnings: a tinted row with a high-contrast text colour that
    // suits the current theme (plain dark red text is hard to read on a
    // dark background)
    const int level = logs_.at(index.row()).logLevel;
    const bool dark = ThemeManager::instance()->isDark();
    if (role == Qt::ForegroundRole) {
        switch(level) {
        case kError:
            return QBrush(QColor(dark ? "#FFB4AB" : "#B3261E"));
        case kWarning:
            return QBrush(QColor(dark ? "#F2CC60" : "#8A5300"));
        case kInfo:
        default:
            return QVariant();
        }
    }
    if (role == Qt::BackgroundRole) {
        switch(level) {
        case kError:
            return QBrush(QColor(dark ? "#3D2326" : "#FDECEC"));
        case kWarning:
            return QBrush(QColor(dark ? "#3A3220" : "#FFF4D6"));
        default:
            return QVariant();
        }
    }
    if (role == Qt::FontRole && index.column() == kLogLevel
            && level != kInfo) {
        QFont bold;
        bold.setBold(true);
        return bold;
    }

    if (role != Qt::DisplayRole)
        return QVariant();

    switch (index.column()) {
    case kTimeStamp:
        return logs_.at(index.row()).timeStamp.toString("hh:mm:ss.zzz");
    case kLogLevel:
        return levelTitle(logs_.at(index.row()).logLevel);
    case kPort:
        return logs_.at(index.row()).port;
    case kMessage:
        return logs_.at(index.row()).message;
    default:
        break;
    }

    return QVariant();
}

Qt::DropActions LogsModel::supportedDropActions() const
{
    return Qt::IgnoreAction; // read-only model, doesn't accept any data
}

// --------------------------------------------- //
// Slots
// --------------------------------------------- //
void LogsModel::clear()
{
    beginResetModel();
    logs_.clear();
    endResetModel();
}

void LogsModel::setLogLevel(int level)
{
    currentLevel_ = static_cast<LogLevel>(level % kLevelCount);
    log(currentLevel_, QString("--"),
        tr("Log level changed to %1 or higher")
            .arg(levelTitle(currentLevel_)));
}

void LogsModel::log(int logLevel,QString port, QString message)
{
    if (logLevel < currentLevel_)
        return;

    // TODO: discard logs older than some threshold

    //qDebug("adding log %u %s", logs_.size(), qPrintable(message));
    beginInsertRows(QModelIndex(), logs_.size(), logs_.size());
    Log l;
    logs_.append(l);
    logs_.last().timeStamp = QTime::currentTime();
    logs_.last().logLevel = logLevel;
    logs_.last().port = port;
    // XXX: QTableView does not honour newline unless we increase the
    // row height, so we replace newlines with semicolon for now
    logs_.last().message = LogTranslator::translate(message.trimmed())
                                .replace("\n", "; ");
    endInsertRows();
}
