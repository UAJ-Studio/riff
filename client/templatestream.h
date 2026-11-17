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
}

#endif
