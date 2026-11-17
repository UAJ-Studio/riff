/*
Copyright (C) 2026 Riff contributors

This file is part of "Riff"

This is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
*/

#ifndef _TEMPLATE_STREAM_H
#define _TEMPLATE_STREAM_H

#include <QString>

namespace OstProto {
    class Stream;
}

/*
 * The hex editor's ready-made packets (PacketTemplates) as field-by-field
 * protocols for the normal stream editor: the Wi-Fi ones are built from the
 * 802.11 protocols, the wired ones are decoded with tshark (like a PCAP
 * import), falling back to a hex dump where no protocol fits.
 */
namespace TemplateStream {
    // replaces the protocols and the frame length of *stream
    bool apply(int index, OstProto::Stream *stream, QString *error);

    // One packet's bytes (e.g. from the hex editor) as protocols: Ethernet
    // through tshark, radiotap + 802.11 with the 802.11 protocols, a hex
    // dump for parts no protocol covers. Replaces the protocols and the
    // frame length of *stream only if the protocols give exactly these
    // bytes again; returns false (stream untouched) otherwise.
    bool fromBytes(const QByteArray &pkt, bool wifi,
                   OstProto::Stream *stream, QString *error = 0);

    // developer check (riff.exe --selftest-decode <file>): every template
    // through fromBytes(), report written to the file; true if all split
    bool selfTest(const QString &reportFile);
}

#endif
