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

## Registered dongles (Windows crash avoidance)
Riff uses a dongle only after it is "registered" (`usbipd bind --force`):
the Windows Wi-Fi driver is unloaded from it once and never runs on it again
until the user gives it back to Windows. Dongles are registered when first
used (several at once, one administrator prompt).

Why: on a test PC with two ASUS USB-AX56 (RTL8832AU), Windows crashed with
BAD_POOL_HEADER (0x19, P1 0x22) in rtwlanu6.sys 5001.0.13.105, the Realtek
Windows driver. A full kernel dump showed the halt path
(wdiwifi!CMiniportHaltJob::PerformFreeAdapter -> rtwlanu6 -> NdisFreeMemory)
freeing a large buffer whose address is kept in a *global* variable of the
driver: with two adapters, both halting (shutdown, or a takeover by usbipd
after the other one was re-initialised) frees the same buffer twice. This is
independent of WSL and usbipd; any vendor driver may have similar
multi-adapter bugs, so Riff keeps its dongles off the Windows driver.

Rule (confirmed on a second PC with Device Manager only, no WSL/usbipd):
every adapter start allocates the shared buffer and overwrites the global,
every stop frees it - two stops in a row free it twice. So once two of
these dongles have run on the Windows driver at the same time, Windows
can crash when they go away - disabling, registering, shutdown, and
sometimes also unplugging (unplugging both once went through, another time
unplugging the second one crashed: a double free does not always bugcheck
at once). There is no reliably safe way out of that state with the old driver.

Fix: rtwlanu6 5001.0.15.110 (ASUS USB-AX56 driver, 2022-07) does not crash.
Tested with two running dongles: disabling them one after the other (second
PC once, dev PC 3 cycles), restarting the PC, and force-binding both back to
back - all went through, while 5001.0.13.105 crashed on each of these.
So Riff does not work around the old driver (no one-at-a-time rule): it
warns when an older rtwlanu6.sys is installed and a rtw89 dongle is plugged
in, and asks to install the fixed version
(WirelessManager::windowsDriverWarning).

Identity: two AX56 report the same serial (00E04C000001, Realtek default),
so Windows keys the second one by its USB port (instance ID 7&...&<port>).
usbipd registration follows the instance ID: moved to another port, that
dongle is a new, unregistered device. Keep registered dongles on the same
port.

Fast restart: captures started from Riff leave their dongle attached to WSL
(no "release"), and Riff keeps the distro alive while it runs, so the next
capture on the same channel starts in ~2-4 s instead of ~40 s (attach,
firmware upload, calibration over USB/IP). Riff detaches them on exit.
Riff also readies registered dongles ahead (on start, on registration and
when the dialog opens): riff-capture with the "prepare" option attaches,
loads the driver, sets monitor mode and the channel, so even the first
capture starts in seconds. riff-load.sh takes a lock (flock): two loaders at
once deleted each other's pack and left a mismatched cfg80211 loaded.

Registered ports: Riff remembers "vid:pid@busid" of registered dongles and
registers a dongle there again when it lost its registration through the
ID swap below (one UAC prompt per new ID).

Also: Linux rtw89 normally switches USB 2 connected dongles to USB 3 mode
(the chip re-enumerates and keeps the setting until power-off). The pack's
rtw89 has `switch_usb_mode` (default N) so a dongle keeps its identity and
registration. Crash lab scripts used for the analysis: see the project notes.
