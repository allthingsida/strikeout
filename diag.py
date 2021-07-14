import idaapi

# --------------------------------------------------------------------------------
class hidestmt_t:
    def __init__(self, is64=True, use_relative=True):
        self.n = idaapi.netnode("$ hexrays strikeout-plugin")
        self.c = 'Q' if is64 else 'L'
        self.ptr_size = 8 if is64 else 4
        self.use_relative = use_relative


    def load(self):
        addresses = []
        blob = self.n.getblob(0, 'I') or []
        imgbase = idaapi.get_imagebase() if self.use_relative else 0
        for i, offs in enumerate(range(0, len(blob), self.ptr_size)):
            ea = struct.unpack(self.c, blob[offs:offs+self.ptr_size])[0]
            addresses.append(imgbase + ea)
        return addresses


    def kill(self):
        self.n.kill()

    
    def save(self, addresses):
        imgbase = idaapi.get_imagebase() if self.use_relative else 0
        b = bytearray()
        for addr in addresses:
            b += struct.pack(self.c, addr - imgbase)
        blob = bytes(b)
        self.n.setblob(blob, 0, 'I')


# --------------------------------------------------------------------------------
def compare_blobs(b1, b2):
    if len(b1) != len(b2):
        return -1

    for p0, p1 in zip(b1, b2):
        if p0 != p1:
            return 1

    return 0


# --------------------------------------------------------------------------------
def clean_func_info(func_ea=idaapi.BADADDR):
    if func_ea == idaapi.BADADDR:
        func_ea = idaapi.get_screen_ea()
    f = idaapi.get_func(func_ea)
    if not f:
        return (False, 'No function!')
    else:
        func_ea = f.start_ea

    addresses = diag.load()
    print(f'Effective parent function: {f.start_ea:x}..{f.end_ea:x}')

    new_addresses = []
    for addr in addresses:
        f = idaapi.get_func(addr)
        if f and f.start_ea == func_ea:
            print(f'Omitting: {addr:x}')
            continue
        else:
            # print(f'Skipping: {addr:x}')
            pass

        new_addresses.append(addr)


    print(f"Old={len(addresses)} New={len(new_addresses)}")

    # Save when change occurs
    if len(addresses) != len(new_addresses):
        diag.save(new_addresses)


# --------------------------------------------------------------------------------
def dump():
    global diag
    diag = hidestmt_t()
    addresses = diag.load()

    print('Dumping address\n---------------')
    for ea in addresses:
        print(f"{ea:x} ...")

    print(f'Total {len(addresses)}')


# --------------------------------------------------------------------------------
if __name__=='__main__':
    idaapi.msg_clear()

    # dump()
    clean_func_info()