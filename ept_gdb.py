import gdb

class EPTBreak(gdb.Command):
    """Set an EPT hook via QEMU monitor."""

    def __init__(self):
        super().__init__("ept-bp", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):

        if not arg:
            print("Usage: ept-bp <address|symbol>")
            return

        try:
            addr = int(gdb.parse_and_eval(arg))
        except gdb.error as e:
            print(f"Failed to resolve address: {e}")
            return

        print(f"Executed at {addr}")
        #gdb.execute(f"monitor ept_break {addr:#x}")


EPTBreak()

