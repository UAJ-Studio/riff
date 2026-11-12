Ostinato for Windows (community build from v1.3.0 source)
==========================================================

Requirements
  - Windows 10/11 64-bit
  - Npcap (https://npcap.com/) installed.
    Tick "Install Npcap in WinPcap API-compatible Mode" if you want the
    DLLs on the default search path; otherwise ostinato looks in
    C:\Windows\System32\Npcap.

Run
  - Start ostinato.exe. It launches the local drone.exe automatically.
  - Sending/receiving on real NICs usually needs drone.exe to run as
    Administrator (or Npcap installed without "Restrict to Administrators").

License: GPLv3 (see COPYING). Source: windows-build branch of this repo.
