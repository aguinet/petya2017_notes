import sys
base=0x7C00
offset_write = 0x8000

data=open(sys.argv[1],"r").read()

def get_data_va(va,size):
    off = va-base
    return data[off:off+size]

boot = get_data_va(base, offset_write-base)
read = data[1*512:(1+33)*512]
# 'read' is remapped to 0x8000

sys.stdout.write(boot)
sys.stdout.write(read)
