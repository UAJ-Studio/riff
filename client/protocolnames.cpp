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

#include "protocolnames.h"

#include <QCoreApplication>

// Listed only so that lupdate picks the names up for translation
static const char *kProtocolNames[] = {
    QT_TRANSLATE_NOOP("ProtocolName", "Media Access Protocol"),
    QT_TRANSLATE_NOOP("ProtocolName", "Ethernet II"),
    QT_TRANSLATE_NOOP("ProtocolName", "802.3"),
    QT_TRANSLATE_NOOP("ProtocolName", "802.3 Logical Link Control"),
    QT_TRANSLATE_NOOP("ProtocolName", "SubNetwork Access Protocol"),
    QT_TRANSLATE_NOOP("ProtocolName", "Vlan"),
    QT_TRANSLATE_NOOP("ProtocolName", "SVlan"),
    QT_TRANSLATE_NOOP("ProtocolName", "Spanning Tree Protocol"),
    QT_TRANSLATE_NOOP("ProtocolName", "Address Resolution Protocol"),
    QT_TRANSLATE_NOOP("ProtocolName", "Internet Protocol ver 4"),
    QT_TRANSLATE_NOOP("ProtocolName", "Internet Protocol ver 6"),
    QT_TRANSLATE_NOOP("ProtocolName", "Transmission Control Protocol (state less)"),
    QT_TRANSLATE_NOOP("ProtocolName", "User Datagram Protocol"),
    QT_TRANSLATE_NOOP("ProtocolName", "Internet Control Message Protocol"),
    QT_TRANSLATE_NOOP("ProtocolName", "Internet Group Management Protocol"),
    QT_TRANSLATE_NOOP("ProtocolName", "Multicast Listener Discovery"),
    QT_TRANSLATE_NOOP("ProtocolName", "General Routing Encapsulation Protocol"),
    QT_TRANSLATE_NOOP("ProtocolName", "EtherIP - Ethernet over IP (RFC 3378)"),
    QT_TRANSLATE_NOOP("ProtocolName", "CAPWAP - Control And Provisioning of Wireless Access Points (RFC 5415)"),
    QT_TRANSLATE_NOOP("ProtocolName", "Text Protocol"),
    QT_TRANSLATE_NOOP("ProtocolName", "Payload Data"),
    QT_TRANSLATE_NOOP("ProtocolName", "HexDump"),
    QT_TRANSLATE_NOOP("ProtocolName", "Signature"),
    QT_TRANSLATE_NOOP("ProtocolName", "Sample Protocol"),
};

QString translatedProtocolName(const QString &name)
{
    Q_UNUSED(kProtocolNames);
    return QCoreApplication::translate("ProtocolName",
                                       name.toUtf8().constData());
}
