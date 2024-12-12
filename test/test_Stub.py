from io import StringIO

from pygdbstub import IOPipe, Stub
from pygdbstub.arch import PowerPC64
from pygdbstub.target import Null

target = Null(PowerPC64())


def test_qSupported() -> None:
    gdb_send = StringIO("$qSupported:bla:bla#09+")
    gdb_recv = StringIO()
    stub = Stub(target, IOPipe(gdb_send, gdb_recv))

    stub.process1()

    assert gdb_recv.getvalue() == "+$PacketSize=FFFF#48"


def test_bogus() -> None:
    gdb_send = StringIO("$_bogus#7f+")
    gdb_recv = StringIO()
    stub = Stub(target, IOPipe(gdb_send, gdb_recv))

    stub.process1()

    assert gdb_recv.getvalue() == "+$#00"


def test_g() -> None:
    gdb_send = StringIO("$g#67+")
    gdb_recv = StringIO()
    stub = Stub(target, IOPipe(gdb_send, gdb_recv))
    bytes_in_g_packet = sum((reg.size for reg in target.registers)) // 8

    stub.process1()

    reply = gdb_recv.getvalue()

    assert len(reply) == 2 + bytes_in_g_packet * 2 + 3
    assert reply.startswith("+$" + ("00" * bytes_in_g_packet) + "#")
