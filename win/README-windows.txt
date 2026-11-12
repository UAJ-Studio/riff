Riff - packet/traffic generator for Windows
===========================================

Riff is a Windows-focused derivative of Ostinato 1.3.0
(https://ostinato.org, (c) 2007-2023 Srivats P.), with fixes and changes
of its own. It is not affiliated with or endorsed by the Ostinato project.

Requirements
  - Windows 10/11 64-bit
  - Npcap (https://npcap.com/). WinPcap API-compatible mode is optional;
    Riff also finds the DLLs in C:\Windows\System32\Npcap.

Run
  - Start riff.exe. It launches the local agent (riff-agent.exe)
    automatically.
  - Sending/receiving on real NICs may need riff-agent.exe to run as
    Administrator (or Npcap installed without "Restrict to Administrators").
  - Settings are stored in riff.ini / riff-agent.ini.

License: GPLv3 (see COPYING). Source code: the windows-build branch of the
Riff repository.
