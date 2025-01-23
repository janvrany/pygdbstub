from io import StringIO

from gdb.stub import IOPipe, Stub
from gdb.stub.arch import PowerPC64
from gdb.stub.target import Null

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


def test_memory_basic() -> None:
    # Write 0x1234, read 0x1234, read non-existent memory 0
    gdb_send = StringIO("$M1234,4:78563412#55+$m1234,4#97+$m0,4#fd+")
    gdb_recv = StringIO()
    stub = Stub(target, IOPipe(gdb_send, gdb_recv))

    stub.process1()
    expect = "+$OK#9a"
    assert gdb_recv.getvalue() == expect

    stub.process1()
    expect += "+$78563412#a4"
    assert gdb_recv.getvalue() == expect

    stub.process1()
    expect += "+$#00"
    assert gdb_recv.getvalue() == expect


def test_memory_two_region() -> None:
    # 0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
    # 78 56 34 12 xx 12 34 56 78 xx xx xx xx xx xx xx xx
    # Write 0, 5 with 0x78563412, 0x12345678
    # Then read 0, 5 and none existent memory 4
    gdb_send = StringIO("$M0,4:78563412#bb+$M5,4:12345678#c0+$m0,4#fd+$m5,4#02+$m4,4#01+")
    gdb_recv = StringIO()
    stub = Stub(target, IOPipe(gdb_send, gdb_recv))

    stub.process1()
    expect = "+$OK#9a"
    assert gdb_recv.getvalue() == expect

    # second write
    stub.process1()
    expect += "+$OK#9a"
    assert gdb_recv.getvalue() == expect

    # the first read
    stub.process1()
    expect += "+$78563412#a4"
    assert gdb_recv.getvalue() == expect

    # the second read
    stub.process1()
    expect += "+$12345678#a4"
    assert gdb_recv.getvalue() == expect

    # the non-existent memory read
    stub.process1()
    expect += "+$#00"
    assert gdb_recv.getvalue() == expect


def test_memory_region_overlaps() -> None:
    # 0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
    # 78 56 34 12 xx 12 34 56 78 xx xx xx xx xx xx xx xx
    #    78 56 34 12 <-- second write
    # Write 0, 5 with 0x78563412, 0x12345678
    # Write 1 with 0x12345678
    gdb_send = StringIO("$M0,4:78563412#bb+$M5,4:12345678#c0+$M1,4:78563412#bc+$m0,9#02+")
    gdb_recv = StringIO()
    stub = Stub(target, IOPipe(gdb_send, gdb_recv))

    stub.process1()
    expect = "+$OK#9a"
    assert gdb_recv.getvalue() == expect

    # second write
    stub.process1()
    expect += "+$OK#9a"
    assert gdb_recv.getvalue() == expect

    # third write
    stub.process1()
    expect += "+$OK#9a"
    assert gdb_recv.getvalue() == expect

    # Read the whole
    stub.process1()
    expect += "+$787856341212345678#b7"
    assert gdb_recv.getvalue() == expect
