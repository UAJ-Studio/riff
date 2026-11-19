# Riff

**Made by [UAJ-Studio](https://uaj-studio.com)** · [UAJ-Studio website](https://uaj-studio.com)
<!-- Add back " · [Support Riff on GitHub Sponsors](https://github.com/sponsors/UAJ-Studio)" once GitHub Sponsors for UAJ-Studio is approved. -->

Riff is a packet crafter and traffic generator for Windows, derived from
[Ostinato](https://ostinato.org) 1.3.0. Besides wired Ethernet ports it can
send raw 802.11 frames from USB Wi-Fi dongles and capture them live in
Wireshark — through Riff's own WSL distribution, without touching your other
WSL setups.

Riff はWindows用のパケット/トラフィックジェネレーターです（Ostinato 1.3.0 からの派生）。
有線 LAN に加えて、USB Wi-Fi ドングルから 802.11 の無線フレームを送信し、
Wireshark でライブキャプチャできます。

## Features

- Build streams field by field (Ethernet, VLAN, IPv4/IPv6, TCP/UDP, ARP,
  tunnels, …) or as raw hex — with ready-made templates in both editors.
  Hex-edited packets are split back into protocols where possible.
- Send from wired ports with set rates, counts and per-packet variation.
- USB Wi-Fi dongles (rtw89/rtw88/mt76/ath9k_htc and more): dongles appear as
  ports; 802.11 protocols (Radiotap TX, MAC header, management frames,
  information elements) with random or counting addresses.
- Live 802.11 capture in Wireshark, one or several dongles at once, with a
  channel per dongle.
- Japanese and English user interface.

## Download

Get `Riff-<version>-setup.exe` from
[Releases](https://github.com/UAJ-Studio/riff/releases). It installs Riff for
the current user (no administrator rights needed), and offers usbipd-win for
USB Wi-Fi dongles. Riff needs [Npcap](https://npcap.com/).

Requirements: Windows 10/11 64-bit, Npcap. For USB Wi-Fi dongles: WSL 2 and
usbipd-win (see [wireless/README.md](wireless/README.md)).

## Support

Riff is free and open source. Support through GitHub Sponsors is coming soon.

<!-- Once GitHub Sponsors for UAJ-Studio is approved, replace the line above with:
Riff is free and open source. If it is useful to you, you can support its
development on [GitHub Sponsors](https://github.com/sponsors/UAJ-Studio).
Donations are a thank-you only — there are no rewards — and supporters who
wish may be listed by name.
-->

Riff builds on years of work by Srivats P., the author of Ostinato. If you
use Ostinato itself, please consider supporting it as well:
[ostinato.org](https://ostinato.org) /
[GitHub Sponsors](https://github.com/sponsors/pstavirs).

## Code signing policy

The current release of Riff is not code-signed. Code signing is planned for a
future release.

- Windows SmartScreen shows a warning on first start. Choose **More info** →
  **Run anyway** to start Riff.
- On PCs with **Smart App Control** turned on, Riff does not start until a
  signed release is available.

The bundled usbipd-win installer is signed by its own publisher; Npcap is not
bundled.

## Privacy

This program will not transfer any information to other networked systems
unless specifically requested by the user or the person installing or
operating it.

## License

GPLv3 or later (see [COPYING](COPYING)). Riff is not affiliated with or
endorsed by the Ostinato project.

Building on Windows: see [win/README-windows.txt](win/README-windows.txt) and
[wireless/README.md](wireless/README.md).
