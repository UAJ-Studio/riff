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

#include "hexpacketeditor.h"

#include "thememanager.h"

#include "qhexedit.h"

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QDialogButtonBox>
#include <QFontDatabase>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>
#include <QRegularExpression>
#include <QSet>
#include <QSplitter>
#include <QToolButton>
#include <QTreeWidget>
#include <QTreeWidgetItemIterator>
#include <QVBoxLayout>

namespace {

const int kFieldRole = Qt::UserRole;
const int kPathRole = Qt::UserRole + 1;

// ---- template builders ----

QByteArray mac(const char *text)
{
    return QByteArray::fromHex(QByteArray(text).replace(":", ""));
}

QByteArray be16(int v)
{
    QByteArray b(2, 0);
    b[0] = char((v >> 8) & 0xFF);
    b[1] = char(v & 0xFF);
    return b;
}

QByteArray ip4(int a, int b, int c, int d)
{
    QByteArray r;
    r.append(char(a)).append(char(b)).append(char(c)).append(char(d));
    return r;
}

QByteArray ethernet(const QByteArray &dst, const QByteArray &src, int type)
{
    return dst + src + be16(type);
}

QByteArray ipv4Header(int proto, const QByteArray &src, const QByteArray &dst,
                      int payloadLen)
{
    QByteArray h;
    h.append(char(0x45)).append(char(0));           // ver/ihl, dscp/ecn
    h.append(be16(20 + payloadLen));                // total length
    h.append(be16(0x1234));                         // identification
    h.append(be16(0x4000));                         // DF
    h.append(char(64)).append(char(proto));         // ttl, protocol
    h.append(be16(0));                              // checksum (fixed later)
    h.append(src).append(dst);
    return h;
}

const QByteArray kDstMac = mac("00:11:22:33:44:55");
const QByteArray kSrcMac = mac("00:aa:bb:cc:dd:ee");

} // namespace

// ------------------------------------------------------------------------

QStringList HexPacketEditor::templateNames()
{
    return QStringList()
        << tr("Ethernet + IPv4 + UDP")
        << tr("Ethernet + IPv4 + TCP SYN")
        << tr("ICMP Echo Request (ping)")
        << tr("ARP Request")
        << tr("Ethernet + IPv6 + UDP")
        << tr("Empty Ethernet frame (60 bytes)");
}

QByteArray HexPacketEditor::templatePacket(int index)
{
    QByteArray pkt;
    const QByteArray srcIp = ip4(192, 168, 0, 10);
    const QByteArray dstIp = ip4(192, 168, 0, 20);

    switch (index) {
    case 0: { // IPv4 + UDP
        QByteArray payload("Hello from Riff!..");
        QByteArray udp = be16(49152) + be16(5000) + be16(8 + payload.size())
                         + be16(0) + payload;
        pkt = ethernet(kDstMac, kSrcMac, 0x0800)
              + ipv4Header(17, srcIp, dstIp, udp.size()) + udp;
        break;
    }
    case 1: { // IPv4 + TCP SYN
        QByteArray tcp = be16(49152) + be16(80)
            + QByteArray::fromHex("00000001") + QByteArray::fromHex("00000000")
            + QByteArray::fromHex("5002") + be16(64240) + be16(0) + be16(0);
        pkt = ethernet(kDstMac, kSrcMac, 0x0800)
              + ipv4Header(6, srcIp, dstIp, tcp.size()) + tcp;
        break;
    }
    case 2: { // ICMP echo request
        QByteArray data("abcdefghijklmnopqrstuvwabcdefghi");
        QByteArray icmp = QByteArray::fromHex("0800") + be16(0) + be16(1)
                          + be16(1) + data;
        pkt = ethernet(kDstMac, kSrcMac, 0x0800)
              + ipv4Header(1, srcIp, ip4(192, 168, 0, 1), icmp.size()) + icmp;
        break;
    }
    case 3: { // ARP request
        QByteArray arp = be16(1) + be16(0x0800)
            + QByteArray::fromHex("0604") + be16(1)
            + kSrcMac + srcIp + QByteArray(6, 0) + ip4(192, 168, 0, 1);
        pkt = ethernet(QByteArray(6, char(0xFF)), kSrcMac, 0x0806) + arp
              + QByteArray(18, 0); // pad to 60
        break;
    }
    case 4: { // IPv6 + UDP
        QByteArray payload("Hello from Riff!");
        QByteArray udp = be16(49152) + be16(5000) + be16(8 + payload.size())
                         + be16(0) + payload;
        QByteArray ip6 = QByteArray::fromHex("60000000") + be16(udp.size())
            + QByteArray::fromHex("1140")      // next header UDP, hop limit 64
            + QByteArray::fromHex("20010db8000000000000000000000010")
            + QByteArray::fromHex("20010db8000000000000000000000020");
        pkt = ethernet(mac("33:33:00:00:00:01"), kSrcMac, 0x86DD) + ip6 + udp;
        break;
    }
    default: // empty frame with the IEEE "local experimental" EtherType
        pkt = ethernet(kDstMac, kSrcMac, 0x88B5) + QByteArray(46, 0);
        break;
    }
    PacketDecoder::fixChecksums(pkt);
    return pkt;
}

bool HexPacketEditor::parseHexText(const QString &text, QByteArray *out,
                                   QString *error)
{
    // Hex dump line: offset, 2+ spaces (or ':'), then 2-digit byte tokens,
    // optionally followed by an ASCII column which we ignore
    static const QRegularExpression dumpLine(
            "^\\s*(?:0x)?[0-9A-Fa-f]{4,8}(?::\\s*|\\s{2,})(.*)$");
    static const QRegularExpression byteToken("^[0-9A-Fa-f]{2}$");
    static const QRegularExpression separators("(0x|\\\\x|[\\s:,;\\-])",
            QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression hexOnly("^[0-9A-Fa-f]*$");

    QByteArray result;
    int lineNo = 0;
    for (QString line : text.split('\n')) {
        lineNo++;
        line = line.trimmed();
        if (line.isEmpty())
            continue;

        QRegularExpressionMatch m = dumpLine.match(line);
        if (m.hasMatch()) {
            QStringList tokens = m.captured(1).split(
                    QRegularExpression("\\s+"), Qt::SkipEmptyParts);
            QByteArray bytes;
            for (const QString &t : tokens) {
                if (!byteToken.match(t).hasMatch())
                    break; // start of the ASCII column
                bytes.append(char(t.toInt(nullptr, 16)));
            }
            if (!bytes.isEmpty()) {
                result.append(bytes);
                continue;
            }
        }

        QString digits = line;
        digits.remove(separators);
        if (!hexOnly.match(digits).hasMatch()) {
            *error = tr("Line %1 contains characters that are not hex "
                        "digits.").arg(lineNo);
            return false;
        }
        if (digits.size() % 2) {
            *error = tr("Line %1 has an odd number of hex digits.")
                         .arg(lineNo);
            return false;
        }
        result.append(QByteArray::fromHex(digits.toLatin1()));
    }

    if (result.size() > kMaxLength) {
        *error = tr("The packet is too long (%1 bytes, maximum %2).")
                     .arg(result.size()).arg(kMaxLength);
        return false;
    }
    *out = result;
    return true;
}

// ------------------------------------------------------------------------

HexPacketEditor::HexPacketEditor(const QByteArray &packet, QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("Hex Packet Editor"));
    setWindowFlags(windowFlags() | Qt::WindowMaximizeButtonHint);
    resize(1080, 640);

    QVBoxLayout *layout = new QVBoxLayout(this);

    QLabel *hint = new QLabel(tr(
        "Type hex digits in the right pane to edit the packet bytes. "
        "The decode on the left follows along: click a field to highlight "
        "its bytes, double-click a value to change it."), this);
    hint->setObjectName("hexEditorHint");
    hint->setWordWrap(true);
    layout->addWidget(hint);

    // Tool row
    QHBoxLayout *tools = new QHBoxLayout;
    QToolButton *tplButton = new QToolButton(this);
    tplButton->setText(tr("Start from Template"));
    tplButton->setToolTip(tr("Replace the packet with a ready-made example "
                             "that you can then modify"));
    tplButton->setPopupMode(QToolButton::InstantPopup);
    tplButton->setToolButtonStyle(Qt::ToolButtonTextOnly);
    QMenu *tplMenu = new QMenu(tplButton);
    QStringList names = templateNames();
    for (int i = 0; i < names.size(); i++) {
        QAction *a = tplMenu->addAction(names.at(i));
        a->setData(i);
        connect(a, SIGNAL(triggered()), SLOT(onTemplateChosen()));
    }
    tplButton->setMenu(tplMenu);
    tools->addWidget(tplButton);

    QPushButton *pasteButton = new QPushButton(tr("Paste Hex..."), this);
    pasteButton->setToolTip(tr("Replace the packet with bytes copied as "
                               "text, e.g. from Wireshark"));
    pasteButton->setAutoDefault(false);
    connect(pasteButton, SIGNAL(clicked()), SLOT(onPasteHex()));
    tools->addWidget(pasteButton);

    QPushButton *copyButton = new QPushButton(tr("Copy as Hex"), this);
    copyButton->setToolTip(tr("Copy the whole packet to the clipboard as "
                              "hex text"));
    copyButton->setAutoDefault(false);
    connect(copyButton, SIGNAL(clicked()), SLOT(onCopyHex()));
    tools->addWidget(copyButton);

    QPushButton *fixButton = new QPushButton(tr("Fix Checksums"), this);
    fixButton->setToolTip(tr("Recalculate the IPv4, TCP, UDP, ICMP and "
                             "ICMPv6 checksums"));
    fixButton->setAutoDefault(false);
    connect(fixButton, SIGNAL(clicked()), SLOT(onFixChecksums()));
    tools->addWidget(fixButton);

    tools->addStretch();

    autoChecksum_ = new QCheckBox(tr("Update checksums after field edits"),
                                  this);
    autoChecksum_->setToolTip(tr("When you change a value in the decode "
            "tree, recalculate checksums automatically. (Typing in the hex "
            "pane never changes other bytes.)"));
    autoChecksum_->setChecked(true);
    tools->addWidget(autoChecksum_);

    insertMode_ = new QCheckBox(tr("Insert mode"), this);
    insertMode_->setToolTip(tr("Off: typing overwrites bytes. On: typing "
            "inserts bytes and makes the packet longer. (Insert key)"));
    connect(insertMode_, SIGNAL(toggled(bool)),
            SLOT(onInsertModeToggled(bool)));
    tools->addWidget(insertMode_);
    layout->addLayout(tools);

    // Decode tree | hex view
    QSplitter *splitter = new QSplitter(Qt::Horizontal, this);

    tree_ = new QTreeWidget(splitter);
    tree_->setColumnCount(4);
    tree_->setHeaderLabels(QStringList() << tr("Field") << tr("Value")
                                         << tr("Offset") << tr("Length"));
    tree_->setAlternatingRowColors(true);
    tree_->setUniformRowHeights(true);
    tree_->header()->setStretchLastSection(false);
    tree_->header()->setSectionResizeMode(0, QHeaderView::Interactive);
    tree_->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    tree_->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    tree_->header()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    tree_->setColumnWidth(0, 190);
    connect(tree_, SIGNAL(itemSelectionChanged()),
            SLOT(onTreeSelectionChanged()));
    connect(tree_, SIGNAL(itemDoubleClicked(QTreeWidgetItem*, int)),
            SLOT(onTreeItemDoubleClicked(QTreeWidgetItem*, int)));

    hexEdit_ = new QHexEdit(splitter);
    QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    mono.setFamily("Consolas");
    mono.setPointSize(10);
    hexEdit_->setFont(mono);
    hexEdit_->setAddressWidth(4);
    hexEdit_->setBytesPerLine(16);
    hexEdit_->setAsciiArea(true);
    hexEdit_->setHexCaps(true);
    hexEdit_->setOverwriteMode(true);
    bool dark = ThemeManager::instance()->isDark();
    hexEdit_->setAddressAreaColor(dark ? QColor("#2B313A")
                                       : QColor("#EBEFF4"));
    hexEdit_->setHighlighting(true);
    hexEdit_->setHighlightingColor(dark ? QColor("#4A3F1E")
                                        : QColor("#FFF1C2"));
    hexEdit_->setSelectionColor(dark ? QColor("#2CB8AA")
                                     : QColor("#0F8B8D"));
    connect(hexEdit_, SIGNAL(dataChanged()), SLOT(onHexChanged()));
    connect(hexEdit_, SIGNAL(currentAddressChanged(qint64)),
            SLOT(onCursorMoved(qint64)));
    // Insert key toggles the mode inside QHexEdit - keep the checkbox in
    // sync (overwriteModeChanged(true) means overwrite, so invert)
    connect(hexEdit_, &QHexEdit::overwriteModeChanged, this,
            [this](bool overwrite) {
                QSignalBlocker block(insertMode_);
                insertMode_->setChecked(!overwrite);
            });

    splitter->addWidget(tree_);
    splitter->addWidget(hexEdit_);
    splitter->setStretchFactor(0, 5);
    splitter->setStretchFactor(1, 6);
    layout->addWidget(splitter, 1);

    status_ = new QLabel(this);
    status_->setObjectName("hexEditorStatus");
    layout->addWidget(status_);

    QDialogButtonBox *buttons = new QDialogButtonBox(
            QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(buttons, SIGNAL(accepted()), SLOT(accept()));
    connect(buttons, SIGNAL(rejected()), SLOT(reject()));
    layout->addWidget(buttons);

    setPacket(packet.left(kMaxLength));
    tree_->expandAll();
    hexEdit_->setFocus();
}

QByteArray HexPacketEditor::packet() const
{
    return hexEdit_->data();
}

void HexPacketEditor::accept()
{
    if (hexEdit_->data().isEmpty()) {
        QMessageBox::warning(this, tr("Hex Packet Editor"),
                tr("The packet is empty. Type some bytes or start from a "
                   "template."));
        return;
    }
    QDialog::accept();
}

void HexPacketEditor::setPacket(const QByteArray &pkt)
{
    // Go through replace() so that the change can be undone with Ctrl+Z
    QByteArray old = hexEdit_->data();
    if (old == pkt)
        return;

    if (old.size() == pkt.size()) {
        int first = 0, last = pkt.size() - 1;
        while (first < pkt.size() && old.at(first) == pkt.at(first))
            first++;
        while (last > first && old.at(last) == pkt.at(last))
            last--;
        hexEdit_->replace(first, last - first + 1,
                          pkt.mid(first, last - first + 1));
    }
    else if (old.isEmpty()) {
        hexEdit_->insert(0, pkt);
    }
    else {
        hexEdit_->replace(0, old.size(), pkt);
    }
    // dataChanged() -> onHexChanged() rebuilds the tree
}

void HexPacketEditor::onHexChanged()
{
    QByteArray pkt = hexEdit_->data();
    if (pkt.size() > kMaxLength) {
        hexEdit_->remove(kMaxLength, pkt.size() - kMaxLength);
        return; // we'll be called again
    }
    rebuildTree();
    updateStatus();
}

void HexPacketEditor::rebuildTree()
{
    // Remember what the user had expanded/selected, by field path
    QSet<QString> collapsed;
    QString selectedPath;
    for (QTreeWidgetItemIterator it(tree_); *it; ++it) {
        if ((*it)->childCount() && !(*it)->isExpanded())
            collapsed.insert((*it)->data(0, kPathRole).toString());
    }
    if (!tree_->selectedItems().isEmpty())
        selectedPath = tree_->selectedItems().first()
                           ->data(0, kPathRole).toString();

    syncing_ = true;
    tree_->clear();
    fieldsByItem_.clear();

    PacketDecoder decoder(hexEdit_->data());
    addFields(nullptr, decoder.fields(), QString());

    for (QTreeWidgetItemIterator it(tree_); *it; ++it) {
        QString path = (*it)->data(0, kPathRole).toString();
        if ((*it)->childCount())
            (*it)->setExpanded(!collapsed.contains(path));
        if (!selectedPath.isEmpty() && path == selectedPath)
            (*it)->setSelected(true);
    }
    syncing_ = false;
}

void HexPacketEditor::addFields(QTreeWidgetItem *parent,
                                const QList<DecodedField> &fields,
                                const QString &path)
{
    const QColor errorColor(ThemeManager::instance()->isDark()
                                ? "#FF8A8A" : "#C62828");
    int n = 0;
    for (const DecodedField &f : fields) {
        QString myPath = QString("%1/%2#%3").arg(path, f.name).arg(n++);
        QTreeWidgetItem *item = parent ? new QTreeWidgetItem(parent)
                                       : new QTreeWidgetItem(tree_);
        item->setText(0, f.name);
        item->setText(1, f.value);
        item->setText(2, QString("0x%1").arg(f.offset, 4, 16, QChar('0'))
                             .toUpper().replace("0X", "0x"));
        item->setText(3, QString::number(f.length));
        item->setTextAlignment(2, Qt::AlignRight | Qt::AlignVCenter);
        item->setTextAlignment(3, Qt::AlignRight | Qt::AlignVCenter);
        item->setData(0, kFieldRole, fieldsByItem_.size());
        item->setData(0, kPathRole, myPath);
        fieldsByItem_.append(f);

        if (f.kind == DecodedField::Header) {
            QFont bold = item->font(0);
            bold.setBold(true);
            item->setFont(0, bold);
        }
        if (f.isEditable())
            item->setToolTip(1, tr("Double-click to edit"));
        else if (f.kind == DecodedField::Bytes)
            item->setToolTip(1, tr("Edit these bytes in the hex pane"));
        if (f.error) {
            item->setForeground(1, errorColor);
            item->setForeground(0, errorColor);
        }

        addFields(item, f.children, myPath);
    }
}

QTreeWidgetItem* HexPacketEditor::deepestItemAt(qint64 offset)
{
    QTreeWidgetItem *best = nullptr;
    int bestLen = INT_MAX;
    for (QTreeWidgetItemIterator it(tree_); *it; ++it) {
        const DecodedField &f =
            fieldsByItem_.at((*it)->data(0, kFieldRole).toInt());
        if (offset >= f.offset && offset < f.offset + f.length
                && f.length <= bestLen) {
            best = *it;
            bestLen = f.length;
        }
    }
    return best;
}

void HexPacketEditor::onCursorMoved(qint64 address)
{
    updateStatus();
    if (syncing_)
        return;

    QTreeWidgetItem *item = deepestItemAt(address);
    syncing_ = true;
    tree_->clearSelection();
    if (item) {
        item->setSelected(true);
        tree_->scrollToItem(item);
    }
    syncing_ = false;
}

void HexPacketEditor::onTreeSelectionChanged()
{
    if (syncing_ || tree_->selectedItems().isEmpty())
        return;

    const DecodedField &f = fieldsByItem_.at(
            tree_->selectedItems().first()->data(0, kFieldRole).toInt());
    syncing_ = true;
    hexEdit_->selectRange(f.offset, f.length);
    syncing_ = false;
    updateStatus();
}

void HexPacketEditor::onTreeItemDoubleClicked(QTreeWidgetItem *item,
                                              int /*column*/)
{
    const DecodedField f = fieldsByItem_.at(item->data(0, kFieldRole).toInt());

    if (f.kind == DecodedField::Header) {
        return; // default double-click expands/collapses
    }
    if (!f.isEditable()) {
        hexEdit_->selectRange(f.offset, f.length);
        hexEdit_->setFocus();
        status_->setText(tr("These bytes have no fixed format - edit them "
                            "in the hex pane (they are selected)."));
        return;
    }

    QByteArray pkt = hexEdit_->data();
    QString text = PacketDecoder::editText(pkt, f);
    QString hint;
    switch (f.kind) {
    case DecodedField::UInt:
        hint = tr("Decimal, or hexadecimal starting with 0x "
                  "(0 - %1)").arg(PacketDecoder::maxValue(f));
        break;
    case DecodedField::Mac:
        hint = tr("e.g. 00:11:22:33:44:55");
        break;
    case DecodedField::Ipv4:
        hint = tr("e.g. 192.168.0.1");
        break;
    default:
        hint = tr("e.g. 2001:db8::1");
        break;
    }

    while (true) {
        bool ok = false;
        text = QInputDialog::getText(this, tr("Edit %1").arg(f.name),
                QString("%1\n%2").arg(f.name, hint), QLineEdit::Normal,
                text, &ok);
        if (!ok)
            return;

        QString error;
        QByteArray newPkt = pkt;
        if (PacketDecoder::writeText(newPkt, f, text, &error)) {
            if (autoChecksum_->isChecked())
                PacketDecoder::fixChecksums(newPkt);
            setPacket(newPkt);
            hexEdit_->selectRange(f.offset, f.length);
            return;
        }
        QMessageBox::warning(this, tr("Edit %1").arg(f.name), error);
    }
}

void HexPacketEditor::onTemplateChosen()
{
    QAction *action = qobject_cast<QAction*>(sender());
    if (!action)
        return;
    if (!hexEdit_->data().isEmpty()
            && QMessageBox::question(this, tr("Start from Template"),
                tr("Replace the current packet with the \"%1\" template?\n"
                   "(You can undo this with Ctrl+Z.)").arg(action->text()))
                != QMessageBox::Yes)
        return;
    setPacket(templatePacket(action->data().toInt()));
    tree_->expandAll();
}

void HexPacketEditor::onPasteHex()
{
    QString initial;
    QString clip = QApplication::clipboard()->text();
    QByteArray dummy;
    QString ignored;
    if (!clip.isEmpty() && clip.size() < 200000
            && parseHexText(clip, &dummy, &ignored) && !dummy.isEmpty())
        initial = clip; // clipboard already holds hex - offer it

    while (true) {
        bool ok = false;
        QString text = QInputDialog::getMultiLineText(this, tr("Paste Hex"),
                tr("Paste the packet bytes as hex. Spaces, colons, 0x "
                   "prefixes and hex dumps with offsets (e.g. Wireshark's "
                   "\"Copy as Hex Dump\") are accepted.\n"
                   "This replaces the whole packet."),
                initial, &ok);
        if (!ok)
            return;

        QByteArray bytes;
        QString error;
        if (parseHexText(text, &bytes, &error)) {
            if (bytes.isEmpty())
                return;
            setPacket(bytes);
            tree_->expandAll();
            return;
        }
        QMessageBox::warning(this, tr("Paste Hex"), error);
        initial = text;
    }
}

void HexPacketEditor::onCopyHex()
{
    QByteArray pkt = hexEdit_->data();
    QStringList lines;
    for (int i = 0; i < pkt.size(); i += 16) {
        QStringList bytes;
        for (int j = i; j < qMin(i + 16, pkt.size()); j++)
            bytes << QString("%1").arg(quint8(pkt.at(j)), 2, 16, QChar('0'));
        lines << bytes.join(' ');
    }
    QApplication::clipboard()->setText(lines.join('\n'));
    status_->setText(tr("Copied %n byte(s) to the clipboard.", "",
                        pkt.size()));
}

void HexPacketEditor::onFixChecksums()
{
    QByteArray pkt = hexEdit_->data();
    int n = PacketDecoder::fixChecksums(pkt);
    if (n)
        setPacket(pkt);
    updateStatus();
    status_->setText(n ? tr("Fixed %n checksum(s).", "", n)
                       : tr("All checksums are already correct."));
}

void HexPacketEditor::onInsertModeToggled(bool insert)
{
    hexEdit_->setOverwriteMode(!insert);
    hexEdit_->setFocus();
}

void HexPacketEditor::updateStatus()
{
    const int len = hexEdit_->data().size();
    qint64 pos = hexEdit_->cursorPosition() / 2;

    QStringList parts;
    parts << tr("%n byte(s)", "", len);
    if (len) {
        parts << tr("cursor at offset 0x%1 (%2)")
                     .arg(pos, 4, 16, QChar('0')).arg(pos);
    }
    if (len && len < 60)
        parts << tr("shorter than the 60-byte Ethernet minimum - zero "
                    "padding is added when sent");
    else if (len > 1514)
        parts << tr("longer than a standard 1514-byte frame (jumbo)");
    status_->setText(parts.join(QString::fromUtf8("  \xC2\xB7  ")));
}
