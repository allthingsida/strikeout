import idaapi

class hidestmt_t:
    def __init__(self, is64=True):
        self.n = idaapi.netnode("$ hexrays strikeout-plugin")
        self.c = 'Q' if is64 else 'L'
        self.ptr_size = 8 if is64 else 4

    def load(self):
        return self.parse_blob(self.n.getblob(0, 'I') or [])

    def parse_blob(self, blob):
        addresses = []
        for i, offs in enumerate(range(0, len(blob), self.ptr_size)):
            ea = struct.unpack(self.c, blob[offs:offs+self.ptr_size])[0]
            addresses.append(ea)
        return addresses


    def pack_addresses(self, addresses):
        b = bytearray()
        for addr in addresses:
            b += struct.pack(self.c, addr)
        return bytes(b)


    def save(self, addresses):
        blob = self.pack_addresses(addresses)
        self.n.setblob(blob, 0, 'I')


def compare_blobs(b1, b2):
    if len(b1) != len(b2):
        return -1

    for p0, p1 in zip(b1, b2):
        if p0 != p1:
            return 1

    return 0


def main():
    idaapi.msg_clear()

    n = hidestmt_t()
    addresses = n.load()

    for ea in addresses:
        print(f"{ea:x} ...")

    # #func_ea = idaapi.get_name_ea(idaapi.BADADDR, 'prot_resolve_callback')
    # func_ea = idaapi.get_name_ea(idaapi.BADADDR, 'prot_3_0')
    # new_addresses = []
    # for addr in addresses:
    #     f = idaapi.get_func(addr)
    #     if f and f.start_ea == func_ea:
    #         continue
    #     new_addresses.append(addr)

    # print(f"old={len(addresses)} new={len(new_addresses)}")
    # n.save(new_addresses)
    # #parent_func = idaapi.get_func(func_ea)


main()