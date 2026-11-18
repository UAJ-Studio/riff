Riff - packet/traffic generator for Windows
===========================================

Riff is a Windows-focused derivative of Ostinato 1.3.0
(https://ostinato.org, (c) 2007-2023 Srivats P.), with fixes and changes
of its own. It is not affiliated with or endorsed by the Ostinato project.

Install
  - Run Riff-<version>-setup.exe. Riff is installed for the current user
    in %LOCALAPPDATA%\Programs\Riff (no administrator rights needed), with
    Start menu / desktop shortcuts and an entry in Settings > Apps >
    Installed apps (uninstall from there).
  - Running the setup of a newer version updates Riff; settings are kept.
  - The setup offers to install usbipd-win (bundled, needs one
    administrator prompt) for USB Wi-Fi dongles, and points to Npcap if it
    is missing.
  - The folder itself also works without the setup: copy it anywhere and
    start riff.exe.

Requirements
  - Windows 10/11 64-bit
  - Npcap (https://npcap.com/). WinPcap API-compatible mode is optional;
    Riff also finds the DLLs in C:\Windows\System32\Npcap. Npcap may not be
    redistributed, so it is not bundled.
  - USB Wi-Fi dongles (802.11 frames, live capture in Wireshark): WSL 2
    and usbipd-win. Riff's own WSL distribution is set up from
    Tools > Wireless Dongle.

Run
  - Start riff.exe. It launches the local agent (riff-agent.exe)
    automatically.
  - Sending/receiving on real NICs may need riff-agent.exe to run as
    Administrator (or Npcap installed without "Restrict to Administrators").
  - Settings are stored in riff.ini / riff-agent.ini.

License: GPLv3 (see COPYING). usbipd-win (bundled with the setup) is
licensed under GPLv2, (c) Frans van Dorsselaer. Source code: the
windows-build branch of the Riff repository.
