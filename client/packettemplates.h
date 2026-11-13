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

#ifndef _PACKET_TEMPLATES_H
#define _PACKET_TEMPLATES_H

#include <QByteArray>

/*
 * Ready-made example packets for the hex packet editor. Names and groups
 * are untranslated source strings in the "HexPacketEditor" context -
 * translate with HexPacketEditor::tr().
 */
namespace PacketTemplates {
    int count();
    const char* name(int index);
    const char* group(int index);
    QByteArray build(int index);  // with correct checksums
}

#endif
