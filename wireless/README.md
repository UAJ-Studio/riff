# Riff wireless pack (USB Wi-Fi dongles on Windows via WSL)

Lets Riff send/capture raw 802.11 frames through a USB Wi-Fi dongle with no
AP connection, **on Microsoft's stock WSL kernel** — no `.wslconfig`
`kernel=` override, so existing WSL setups are left untouched.

How: the dongle is passed into WSL with usbipd-win; Riff's own small distro
loads a *pack* of out-of-tree modules built for the exact running WSL kernel:

- cfg80211/mac80211 + drivers from OpenWrt backports 6.18 (newer than the
  stock 6.6 stack; replaces it, the stock one is never loaded),
- rtw89 from backports 7.2 for RTL8852AU/8852CU/8922AU USB,
- the firmware those modules declare, plus regulatory.db(+.p7s).

Supported dongle families: see `drivers.list` (Realtek rtw89/rtw88/rtl8xxxu,
MediaTek mt7601u/mt76x0u/mt76x2u/mt7921u/mt7925u, Atheros ath9k_htc/carl9170/
ar5523, Ralink rt2x00). Wi-Fi 7: RTL8922AU, MT7925U.

## Files
- `build-pack.sh <WSL kernel version>` — builds `packs/riff-wifi-<release>.tar.zst`
- `riff-wifi-load.sh <pack dir> [country]` — loader (inside the pack); exit 3
  means the pack is for another kernel (WSL was updated)
- `riff.defconfig`, `drivers.list` — what is built / loaded
- `compat/` — shims for building the 6.18/7.2 stack on older kernels; each
  is keyed on the kernel version that introduced the API

## WSL kernel updates
Modules only load into the kernel release they were built for. When WSL
updates its kernel (Store/`wsl --update`; offline PCs never update on their
own), run `build-pack.sh <new version>` (tag `linux-msft-wsl-<version>` of
microsoft/WSL2-Linux-Kernel) and ship the new pack. Riff bundles packs for
known kernels and only needs the network to fetch a pack for a newer one.

Country: the world regdomain forbids initiating radiation on 5 GHz, so
injected frames would be dropped; the loader sets the configured country.
