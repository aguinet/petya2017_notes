import sys

if len(sys.argv) < 1:
    print >>sys.stderr, "Usage: %s mem_snapshot" % sys.argv[0]
    sys.exit(1)

fsnap = sys.argv[1]

def read_mem(addr, size):
    global fsnap
    with open(fsnap, "r") as f:
        f.seek(addr)
        return f.read(size)

def write_mem(addr, data):
    global fsnap
    f = open(fsnap, "r+")
    f.seek(addr)
    f.write(data)
    f.close()

stub = open("stub","r").read()
# This step is not mandatory, it's just to show the key that will be used!
key = read_mem(0x674A, 32)
print("Key found in memory: " + key.encode("hex"))
while True:
    ans = raw_input("Do you want to patch the memory? [Y/n] ")
    if ans == "n":
        print("Abort!")
        sys.exit(2)
    if ans == "Y":
        break
write_mem(0x82A8, stub)
print("Memory has been patched!")
