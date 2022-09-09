from io import StringIO

from gdb.stub import RSP, IOPipe


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
