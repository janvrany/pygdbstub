from io import StringIO

from pygdbstub import RSP, IOPipe


def test_send_01() -> None:
    input = StringIO("+")
    output = StringIO()
    rsp = RSP(IOPipe(input, output))

    rsp.send("OK")
    assert output.getvalue() == "$OK#9a"


def test_recv_01() -> None:
    input = StringIO("$OK#9a")
    output = StringIO()
    rsp = RSP(IOPipe(input, output))

    data = rsp.recv()
    assert data == "OK"
    assert output.getvalue() == "+"


def test_recv_02() -> None:
    input = StringIO(str(b"$\x7d\x5d#37", encoding="ascii"))
    output = StringIO()
    rsp = RSP(IOPipe(input, output))

    data = rsp.recv()
    assert data == "}"
    assert output.getvalue() == "+"
