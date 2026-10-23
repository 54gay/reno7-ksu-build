import struct
from collections import Counter

PATH = "../cve202643499/vmlinux.elf"
data = open(PATH, "rb").read()

e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
e_phnum = struct.unpack_from("<H", data, 0x38)[0]
e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
e_shnum = struct.unpack_from("<H", data, 0x3C)[0]

loads = []
for i in range(e_phnum):
    o = e_phoff + i*e_phentsize
    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from("<IIQQQQQQ", data, o)
    if p_type == 1 and p_filesz:
        loads.append((p_vaddr, p_offset, p_filesz))

def v2o(v):
    for vaddr, off, filesz in loads:
        if vaddr <= v < vaddr+filesz:
            return off + (v-vaddr)
    return None

secs = [struct.unpack_from("<IIQQQQIIQQ", data, e_shoff+i*e_shentsize) for i in range(e_shnum)]
symtab = next(s for s in secs if s[1] == 2)
strtab = secs[symtab[6]]
strtab_off, strtab_size = strtab[4], strtab[5]
symtab_off, symtab_size, symtab_entsize = symtab[4], symtab[5], (symtab[9] or 24)
strtab_data = data[strtab_off:strtab_off+strtab_size]

ksymtab_syms = []
kcrctab_syms = {}
n = symtab_size // symtab_entsize

for i in range(n):
    o = symtab_off + i*symtab_entsize
    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", data, o)
    if st_shndx == 0 or st_value == 0:
        continue
    e = strtab_data.find(b"\0", st_name)
    name = strtab_data[st_name:e].decode("utf-8", "replace")
    if name.startswith("__ksymtab_strings"):
        continue
    if name.startswith("__kcrctab_"):
        kcrctab_syms[name[len("__kcrctab_"):]] = st_value
    else:
        for prefix in ("__ksymtab_unused_gpl_", "__ksymtab_unused_", "__ksymtab_gpl_", "__ksymtab_"):
            if name.startswith(prefix):
                ksymtab_syms.append((name[len(prefix):], st_value))
                break

pairs = [(addr, kcrctab_syms[nm]) for nm, addr in ksymtab_syms if nm in kcrctab_syms]
print(f"ksymtab={len(ksymtab_syms)} kcrctab={len(kcrctab_syms)} pairs={len(pairs)}")

if len(pairs) < 2:
    print("not enough pairs")
    exit(1)

Cs = [kc * 6 - ks for ks, kc in pairs]
cnt = Counter(Cs)
C, freq = cnt.most_common(1)[0]
print(f"C=0x{C:x} freq={freq}/{len(Cs)}")
if freq < len(Cs) * 0.8:
    print("C not consistent, sample Cs:")
    for c in Cs[:10]:
        print(hex(c))

results = {}
miss = 0
for name, ks in ksymtab_syms:
    kc = (ks + C) // 6
    fo = v2o(kc)
    if fo is None:
        miss += 1
        continue
    results[name] = struct.unpack_from("<I", data, fo)[0]

print(f"wrote {len(results)} entries, miss={miss}")
with open("Module.symvers", "w") as f:
    for name, crc in sorted(results.items()):
        f.write("0x%08x\t%s\tvmlinux\tEXPORT_SYMBOL\n" % (crc, name))
