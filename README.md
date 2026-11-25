# Riff

**Made by [UAJ-Studio](https://uaj-studio.com)** · [Riff page](https://uaj-studio.com/riff)
<!-- Add back " · [Support Riff on GitHub Sponsors](https://github.com/sponsors/UAJ-Studio)" once GitHub Sponsors for UAJ-Studio is approved. -->

Riff is a packet crafter and traffic generator for Windows, derived from
[Ostinato](https://ostinato.org) 1.3.0. Besides wired Ethernet ports it can
send raw 802.11 frames from USB Wi-Fi dongles and capture them live in
Wireshark — through Riff's own WSL distribution, without touching your other
WSL setups.

Riff はWindows用のパケット/トラフィックジェネレーターです（Ostinato 1.3.0 からの派生）。
有線 LAN に加えて、USB Wi-Fi ドングルから 802.11 の無線フレームを送信し、
Wireshark でライブキャプチャできます。

**User manual / 使い方マニュアル:** [English](docs/manual-en.md) · [日本語](docs/manual-ja.md)

## Features

- Build streams field by field (Ethernet, VLAN, IPv4/IPv6, TCP/UDP, ARP,
  tunnels, …) or as raw hex — with ready-made templates in both editors.
  Hex-edited packets are split back into protocols where possible.
- Send from wired ports with set rates, counts and per-packet variation.
- USB Wi-Fi dongles (see [the supported chips](#supported-usb-wi-fi-dongles)):
  dongles appear as ports; 802.11 protocols (Radiotap TX, MAC header,
  management frames, information elements) with random or counting addresses.
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

## Supported USB Wi-Fi dongles

Riff drives USB Wi-Fi dongles with the Linux drivers below (inside its own
WSL environment). What matters is the **chip** inside the dongle: look up the
chip of a product, or plug it in and open **Tools > Wireless Dongle** in
Riff, which tells whether it is supported. The full list of USB IDs (932) is
`wireless\riff-wifi-usbids.txt` in the install folder.

対応はドングルの中の**チップ**で決まります。製品のチップを調べるか、挿してから
Riff の「ツール ＞ 無線ドングル」を開くと、対応しているかが表示されます。

| Vendor | Chip | Standard | Linux driver |
|---|---|---|---|
| Realtek | RTL8922AU | Wi-Fi 7 | rtw89_8922au |
| Realtek | RTL8852CU | Wi-Fi 6E | rtw89_8852cu |
| Realtek | RTL8852AU, RTL8852BU, RTL8851BU | Wi-Fi 6 | rtw89_8852au / 8852bu / 8851bu |
| Realtek | RTL8812AU, RTL8814AU, RTL8821AU, RTL8821CU, RTL8822BU, RTL8822CU | Wi-Fi 5 | rtw88_* |
| Realtek | RTL8723DU | Wi-Fi 4 | rtw88_8723du |
| Realtek | RTL8188CU/EU/FU, RTL8192CU/EU, RTL8723AU/BU and other older chips | Wi-Fi 4 | rtl8xxxu |
| MediaTek | MT7925U | Wi-Fi 7 | mt7925u |
| MediaTek | MT7921AU | Wi-Fi 6E | mt7921u |
| MediaTek | MT7612U, MT7610U | Wi-Fi 5 | mt76x2u / mt76x0u |
| MediaTek | MT7601U | Wi-Fi 4 | mt7601u |
| Qualcomm Atheros | AR9271, AR7010 | Wi-Fi 4 | ath9k_htc |
| Qualcomm Atheros | AR9170 | Wi-Fi 4 | carl9170 |
| Qualcomm Atheros | AR5523 | 802.11a/b/g | ar5523 |
| Ralink (MediaTek) | RT2770/RT2870/RT3070/RT3572/RT5370/RT5572 and others | Wi-Fi 4 | rt2800usb |
| Ralink (MediaTek) | RT2571W/RT2573, RT2570 | 802.11b/g | rt73usb / rt2500usb |

**Tested with Riff** (monitor mode, frame injection, live capture in
Wireshark): ASUS USB-AX56 (RTL8852AU). The others are supported by their
Linux drivers but not tested with Riff yet; how well a chip injects frames
or follows Wi-Fi 7 features (320 MHz, MLO) depends on the chip and driver.

動作を確かめた製品：ASUS USB-AX56（RTL8852AU）。ほかのチップは Linux のドライバーが
対応していますが、Riff での動作はまだ確認していません。

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
operating it, with these exceptions, which only download from GitHub:

- **Update check**: about once a day Riff asks GitHub for the version of the
  latest Riff release. Nothing about you or the PC is sent beyond what any
  web request carries (the IP address, and "Riff/&lt;version&gt;" as the user
  agent). Turn it off with **Help > Check for Updates at Start**. Pressing
  **Update** downloads the new setup from GitHub and runs it.
- **USB Wi-Fi dongle drivers**: when the WSL kernel has changed, Riff
  downloads the driver pack for that kernel from this repository's releases.

## License

GPLv3 or later (see [COPYING](COPYING)). Riff is not affiliated with or
endorsed by the Ostinato project.

Building on Windows: see [win/README-windows.txt](win/README-windows.txt) and
[wireless/README.md](wireless/README.md).
