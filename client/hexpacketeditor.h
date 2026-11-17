/*
Copyright (C) 2026 Riff contributors

This file is part of "Riff"

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

#ifndef _HEX_PACKET_EDITOR_H
#define _HEX_PACKET_EDITOR_H

#include "packetdecoder.h"

#include <QDialog>

class QCheckBox;
class QComboBox;
class QHexEdit;
class QLabel;
class QMenu;
class QToolButton;
class QTreeWidget;
class QTreeWidgetItem;

/*
 * Edit a whole packet as raw bytes, with a live protocol decode next to
 * the hex view (select a field to highlight its bytes, double-click a
 * value to change it).
 */
class HexPacketEditor : public QDialog
{
    Q_OBJECT
public:
    // Largest packet we accept (frame length incl. 4 byte FCS <= 16384)
    static const int kMaxLength = 16380;

    explicit HexPacketEditor(const QByteArray &packet = QByteArray(),
                             QWidget *parent = nullptr);

    QByteArray packet() const;

    // Ready made example packets, also used for "New Stream from Hex"
    static QByteArray templatePacket(int index);
    static QStringList templateNames();
    static QString templateGroup(int index);
    // Makes button open menu just below itself. QToolButton::setMenu() can
    // open a long menu on another monitor when the monitors use different
    // scaling (Qt 5): the menu is placed on the button's own screen here.
    static void attachMenu(QToolButton *button, QMenu *menu);

    // Parse hex text in common formats (plain, spaced, 0x.., hex dumps
    // with offsets). Returns false with *error set if text isn't hex.
    static bool parseHexText(const QString &text, QByteArray *out,
                             QString *error);

public slots:
    void accept() override;

private slots:
    void onHexChanged();
    void onCursorMoved(qint64 address);
    void onTreeSelectionChanged();
    void onTreeItemDoubleClicked(QTreeWidgetItem *item, int column);
    void onTemplateChosen();
    void onPasteHex();
    void onCopyHex();
    void onFixChecksums();
    void onInsertModeToggled(bool insert);
    void onLinkTypeChanged(int index);

private:
    void setPacket(const QByteArray &pkt);
    void setLinkType(PacketDecoder::LinkType link);
    void rebuildTree();
    void addFields(QTreeWidgetItem *parent, const QList<DecodedField> &fields,
                   const QString &path);
    void updateStatus();
    QTreeWidgetItem* deepestItemAt(qint64 offset);

    QHexEdit *hexEdit_{nullptr};
    QTreeWidget *tree_{nullptr};
    QLabel *status_{nullptr};
    QCheckBox *autoChecksum_{nullptr};
    QCheckBox *insertMode_{nullptr};
    QComboBox *linkCombo_{nullptr};
    PacketDecoder::LinkType link_{PacketDecoder::LinkEthernet};

    QList<DecodedField> fieldsByItem_;  // indexed by item's UserRole data
    bool syncing_{false};
};

#endif
