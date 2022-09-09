from gdb.stub import Stub
from gdb.stub.arch import PowerPC64
from gdb.stub.target import Null

target = Null(PowerPC64())

stub = Stub(target)
stub.start()
