"""Verifies a YARA-X C API build and optionally writes SHA256SUMS for a staged directory.

Checks, for yara_x_capi.dll (dumpbin, found via vswhere) or libyara_x_capi.so (binutils):
  - exported functions are exactly the names in the expected-exports file;
  - Windows: imported DLLs are within the allowlist (no MSVC runtime: +crt-static took effect);
  - Linux: NEEDED libraries are within the allowlist and no symbol needs glibc newer than MAX_GLIBC.

Usage: python -I check-yara-x-capi.py <library> <expected-exports.txt> [--print-exports] [--sums <dir>]
Exit 0 when every check passes, 1 otherwise.
"""
import argparse, hashlib, os, re, subprocess, sys

WINDOWS_IMPORTS = {'kernel32.dll', 'ntdll.dll', 'bcryptprimitives.dll', 'api-ms-win-core-synch-l1-2-0.dll'}
LINUX_NEEDED = {'libc.so.6', 'libm.so.6', 'libgcc_s.so.1', 'ld-linux-x86-64.so.2'}
MAX_GLIBC = (2, 34)  # Ubuntu 22.04+, Debian 12+, RHEL 9+


def run(*args):
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout


def dumpbin():
    vswhere = os.path.expandvars(r'%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe')
    found = [p.strip() for p in run(vswhere, '-latest', '-prerelease', '-products', '*', '-requires',
                                    'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-find',
                                    r'VC\Tools\MSVC\**\bin\Hostx64\x64\dumpbin.exe').split('\n') if p.strip()]
    if not found:
        sys.exit('dumpbin.exe not found: install the Visual Studio C++ x64 build tools.')
    return found[0]


def windows(lib):
    tool = dumpbin()
    exports = set(re.findall(r'^\s+\d+\s+[0-9A-F]+\s+[0-9A-F]{8}\s+(\S+)', run(tool, '/nologo', '/exports', lib), re.M))
    imports = {m.lower() for m in re.findall(r'^\s{4}(\S+\.dll)\s*$', run(tool, '/nologo', '/imports', lib), re.M | re.I)}
    # Parsing nothing must not pass as "no unexpected imports".
    problems = [] if 'kernel32.dll' in imports else ['no KERNEL32.dll import parsed: dumpbin output not understood']
    return exports, problems + [f'unexpected import {i}' for i in sorted(imports - WINDOWS_IMPORTS)]


def linux(lib):
    text = [l.split() for l in run('nm', '-D', '--defined-only', lib).splitlines()]
    # Every defined global symbol (functions and data), not just functions.
    exports = {f[2] for f in text if len(f) == 3 and f[1] in 'TDBRVW'}
    needed = set(re.findall(r'\(NEEDED\).*\[(.+)\]', run('readelf', '-d', lib)))
    glibc = {tuple(map(int, v.split('.'))) for v in re.findall(r'GLIBC_([0-9.]+)', run('objdump', '-T', lib))}
    problems = [] if 'libc.so.6' in needed else ['no libc.so.6 NEEDED parsed: readelf output not understood']
    problems += [] if glibc else ['no GLIBC_ symbol versions parsed: objdump output not understood']
    problems += [f'unexpected NEEDED {n}' for n in sorted(needed - LINUX_NEEDED)]
    problems += [f'needs GLIBC_{".".join(map(str, max(glibc)))} > {".".join(map(str, MAX_GLIBC))}']\
        if glibc and max(glibc) > MAX_GLIBC else []
    return exports, problems


def write_sums(directory):
    lines = [f'{hashlib.sha256(open(os.path.join(directory, n), "rb").read()).hexdigest()}  {n}'
             for n in sorted(os.listdir(directory)) if n != 'SHA256SUMS']
    with open(os.path.join(directory, 'SHA256SUMS'), 'w', newline='\n') as f:
        f.write('\n'.join(lines) + '\n')
    print('\n'.join(lines))


def main():
    p = argparse.ArgumentParser()
    p.add_argument('library')
    p.add_argument('expected')
    p.add_argument('--print-exports', action='store_true')
    p.add_argument('--sums')
    a = p.parse_args()

    exports, problems = (windows if a.library.lower().endswith('.dll') else linux)(a.library)
    if a.print_exports:
        print('\n'.join(sorted(exports)))
        return 0
    expected = {l.strip() for l in open(a.expected) if l.strip() and not l.startswith('#')}
    problems += [f'missing export {e}' for e in sorted(expected - exports)]
    problems += [f'unexpected export {e}' for e in sorted(exports - expected)]
    if problems:
        print('\n'.join(problems), file=sys.stderr)
        print('If the YARA-X tag changed, regenerate the expected-exports file with --print-exports and review the diff.',
              file=sys.stderr)
        return 1
    print(f'{a.library}: {len(exports)} exports as expected; dependencies within the allowlist.')
    if a.sums:
        write_sums(a.sums)
    return 0


if __name__ == '__main__':
    sys.exit(main())
