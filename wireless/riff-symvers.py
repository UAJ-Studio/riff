#!/usr/bin/env python3
"""riff-symvers.py: write a Module.symvers for the RUNNING kernel.

Building modules for a MODVERSIONS kernel needs the CRC ("version") of every
symbol the kernel and its modules export. Building the whole kernel only to
get them takes most of an hour; the running kernel already has them:
  - vmlinux: the __ksymtab*/__kcrctab* tables, read through /proc/kcore at the
    addresses /proc/kallsyms gives (root only),
  - Microsoft's own modules: their __ksymtab*/__kcrctab* sections and
    __crc_* symbols, read from the .ko files in /lib/modules/<release>.
A symbol this misses only makes the kernel print "no symbol version" when
the module loads; it still loads.
usage: riff-symvers.py [output] (default: stdout)
"""
import os, struct, sys, subprocess

KSYM_SIZE = 12   # struct kernel_symbol with PREL32 offsets (x86_64)


# ---------------------------------------------------------------- vmlinux
def kallsyms():
    syms = {}
    with open('/proc/kallsyms') as f:
        for line in f:
            p = line.split()
            if len(p) >= 3 and len(p) < 4:      # vmlinux symbols only
                syms[p[2]] = int(p[0], 16)
    return syms


class KCore:
    def __init__(self, path='/proc/kcore'):
        self.f = open(path, 'rb')
        h = self.f.read(64)
        if h[:4] != b'\x7fELF' or h[4] != 2:
            raise RuntimeError('kcore is not ELF64')
        phoff, = struct.unpack_from('<Q', h, 32)
        phentsize, phnum = struct.unpack_from('<HH', h, 54)
        self.loads = []
        for i in range(phnum):
            self.f.seek(phoff + i * phentsize)
            ph = self.f.read(phentsize)
            ptype, _, off, vaddr, _, filesz = struct.unpack_from('<IIQQQQ', ph, 0)
            if ptype == 1:      # PT_LOAD
                self.loads.append((vaddr, filesz, off))

    def read(self, addr, n):
        for vaddr, size, off in self.loads:
            if vaddr <= addr and addr + n <= vaddr + size:
                self.f.seek(off + addr - vaddr)
                return self.f.read(n)
        raise KeyError(hex(addr))

    def cstr(self, addr, limit=256):
        b = self.read(addr, limit)
        return b.split(b'\0', 1)[0].decode()


def vmlinux_exports():
    ks = kallsyms()
    if not ks.get('__start___ksymtab'):
        raise RuntimeError('kernel addresses are hidden (run as root)')
    core = KCore()
    out = []
    for gpl, tab, crc in ((False, '__ksymtab', '__kcrctab'),
                          (True, '__ksymtab_gpl', '__kcrctab_gpl')):
        start, stop = ks.get('__start_' + tab), ks.get('__stop_' + tab)
        cstart = ks.get('__start_' + crc)
        if not start or not stop or not cstart:
            continue
        n = (stop - start) // KSYM_SIZE
        raw = core.read(start, n * KSYM_SIZE)
        crcs = core.read(cstart, n * 4)
        for i in range(n):
            base = start + i * KSYM_SIZE
            _, name_off, ns_off = struct.unpack_from('<iii', raw, i * KSYM_SIZE)
            name = core.cstr(base + 4 + name_off)
            ns = core.cstr(base + 8 + ns_off) if ns_off else ''
            c, = struct.unpack_from('<I', crcs, i * 4)
            out.append((c, name, 'vmlinux', gpl, ns))
    return out


# ---------------------------------------------------------------- modules
def ko_bytes(path):
    if path.endswith('.ko'):
        return open(path, 'rb').read()
    for ext, cmd in (('.xz', ['xz', '-dc']), ('.zst', ['zstd', '-dc']),
                     ('.gz', ['gzip', '-dc'])):
        if path.endswith('.ko' + ext):
            return subprocess.run(cmd + [path], capture_output=True).stdout
    return b''


def ko_exports(path, modname):
    d = ko_bytes(path)
    if d[:4] != b'\x7fELF' or d[4] != 2:
        return []
    shoff, = struct.unpack_from('<Q', d, 40)
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', d, 58)
    secs = []
    for i in range(shnum):
        s = struct.unpack_from('<IIQQQQIIQQ', d, shoff + i * shentsize)
        secs.append(s)      # name, type, flags, addr, offset, size, link, info, align, entsize
    sstr = secs[shstrndx]
    def secname(s):
        o = sstr[4] + s[0]
        return d[o:d.index(b'\0', o)].decode()
    byname = {secname(s): (i, s) for i, s in enumerate(secs)}
    symtab = next((s for s in secs if s[1] == 2), None)     # SHT_SYMTAB
    if not symtab:
        return []
    strtab = secs[symtab[6]]
    symlist = []        # by index: (name, shndx, value)
    for j in range(symtab[5] // 24):
        nm, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', d, symtab[4] + j * 24)
        o = strtab[4] + nm
        symlist.append((d[o:d.index(b'\0', o)].decode(), shndx, value))

    def cstr_in(shndx, off):
        s = secs[shndx]
        o = s[4] + off
        return d[o:d.index(b'\0', o)].decode()

    out = []
    for gpl, tab, crc in ((False, '__ksymtab', '__kcrctab'),
                          (True, '__ksymtab_gpl', '__kcrctab_gpl')):
        if tab not in byname or '.rela' + tab not in byname or crc not in byname:
            continue
        tsec = byname[tab][1]
        csec = byname[crc][1]
        # each struct kernel_symbol entry is filled by relocations: +4 points
        # at the name (__kstrtab_<sym>), +8 at the namespace (__kstrtabns_<sym>)
        rel = {}
        rs = byname['.rela' + tab][1]
        for k in range(rs[5] // 24):
            r_off, r_info, r_add = struct.unpack_from('<QQq', d, rs[4] + k * 24)
            rel[r_off] = (r_info >> 32, r_add)
        for i in range(tsec[5] // KSYM_SIZE):
            nrel = rel.get(i * KSYM_SIZE + 4)
            if not nrel:
                continue
            sname, sndx, sval = symlist[nrel[0]]
            name = sname[len('__kstrtab_'):] if sname.startswith('__kstrtab_') \
                else cstr_in(sndx, sval + nrel[1])
            ns = ''
            srel = rel.get(i * KSYM_SIZE + 8)
            if srel:
                _, nsndx, nsval = symlist[srel[0]]
                try:
                    ns = cstr_in(nsndx, nsval + srel[1])
                except Exception:
                    ns = ''
            c, = struct.unpack_from('<I', d, csec[4] + i * 4)
            out.append((c, name, modname, gpl, ns))
    return out


# Microsoft's own wireless stack and drivers: the pack brings newer ones with
# the same symbol names (their CRCs come from the pack's own build)
SKIP = ('/net/wireless/', '/net/mac80211/', '/drivers/net/wireless/')


def module_exports(release):
    out = []
    top = '/lib/modules/%s' % release
    for root, _, files in os.walk(top):
        if any(s in root + '/' for s in SKIP):
            continue
        for fn in files:
            if '.ko' not in fn:
                continue
            name = fn.split('.ko')[0]
            try:
                out += ko_exports(os.path.join(root, fn), name)
            except Exception:
                pass
    return out


def main():
    release = os.uname().release
    rows = vmlinux_exports()
    seen = {r[1] for r in rows}
    for r in module_exports(release):
        if r[1] not in seen:
            rows.append(r)
            seen.add(r[1])
    lines = ['0x%08x\t%s\t%s\t%s\t%s' % (c, n, m, 'EXPORT_SYMBOL_GPL' if g else 'EXPORT_SYMBOL', ns)
             for c, n, m, g, ns in rows]
    data = '\n'.join(lines) + '\n'
    if len(sys.argv) > 1:
        open(sys.argv[1], 'w').write(data)
    else:
        sys.stdout.write(data)
    sys.stderr.write('riff-symvers: %d symbols (%d from vmlinux)\n'
                     % (len(rows), sum(1 for r in rows if r[2] == 'vmlinux')))


if __name__ == '__main__':
    main()
