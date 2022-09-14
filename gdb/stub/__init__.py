import enum
import io
import sys
from argparse import ArgumentParser

from gdb.stub.arch import PowerPC64
from gdb.stub.target import Null
from gdb.stub.target.microwatt import Microwatt


class IOPipe:
    def __init__(self, _in=sys.stdin, _out=sys.stdout):
        self._in = _in
        self._out = _out
        sys.stdout.reconfigure(line_buffering=False, write_through=False)

    def write(self, buffer: str):
        self._out.write(buffer)

    def flush(self):
        self._out.flush()

    def read(self, count: int) -> str:
        return self._in.read(count)

    def readinto(self, buffer: str) -> int:
        return self._in.readinto(self, buffer)


ByteToHexMap = ["%02x" % x for x in range(256)]


class RSP(object):
    """
    And implementation of RSP protocol taking care of proper
    escaping and checksuming.
    """

    def __init__(self, channel=IOPipe()):
        self._io = channel

    def bytes2hex(self, *data: bytes) -> str:
        hex = io.StringIO()
        for datum in data:
            for b in datum:
                hex.write(ByteToHexMap[b])
        return hex.getvalue()

    def checksum(self, data: str) -> int:
        # FIXME: handle escaping
        # See https://github.com/openrisc/or1ksim/blob/or1k-master/debug/rsp-server.c#L689
        sum = 0
        for c in data:
            v = ord(c)
            assert v < 128
            sum += v
        return sum & 0xFF

    def send_ack(self, request_retransmit=False) -> None:
        if request_retransmit:
            self._io.write("-")
        else:
            self._io.write("+")

    def recv_ack(self) -> bool:
        ack_or_not = self._io.read(1)
        assert ack_or_not == "+" or ack_or_not == "-"
        return ack_or_not == "+"

    def send(self, data: str) -> None:
        self._io.write("$")
        for c in data:
            # FIXME: handle escaping
            # See https://github.com/openrisc/or1ksim/blob/or1k-master/debug/rsp-server.c#L689
            self._io.write(c)
        self._io.write("#")
        self._io.write("%02x" % self.checksum(data))
        self._io.flush()
        assert self.recv_ack()

    def recv(self) -> str | None:
        while True:
            c = self._io.read(1)
            if c is None:
                return None
            elif c == "$":
                break

        buffer = io.StringIO()
        while True:
            c = self._io.read(1)
            # FIXME: handle escaping
            # See https://github.com/openrisc/or1ksim/blob/or1k-master/debug/rsp-server.c#L689
            if c == "#":
                break
            else:
                buffer.write(c)
        data = buffer.getvalue()

        csum = int("0x" + self._io.read(2), 16)
        assert csum == self.checksum(data)
        self.send_ack()
        return data


class TARGET_SIGNAL(enum.IntEnum):
    """
    Definition of GDB target signals. Data taken from the GDB 6.8
    source. Only those we use defined here.
    """

    NONE = 0
    INT = 2
    ILL = 4
    TRAP = 5
    FPE = 8
    BUS = 10
    SEGV = 11
    ALRM = 14
    USR2 = 31
    PWR = 32


class Stub(object):
    def __init__(self, target, rsp=RSP()):
        self._target = target
        self._rsp = rsp

    def start(self):
        self._target.connect()
        while True:
            self.process1()

    def process1(self):
        """
        Wait and process single packet, then return.
        """
        packet = self._rsp.recv()
        try:
            packet_type = packet[0]
            # Sigh, some packet types are not letters so
            # handle them specially
            if packet_type == "?":
                handler = self.handle_questionmark
            else:
                handler = getattr(self, "handle_" + packet_type)
            handler(packet)
        except AttributeError:
            self._rsp.send("EFF")

    def handle_q(self, packet):
        if packet.startswith("qSupported"):
            self._rsp.send("PacketSize=FFFF")
        elif packet.startswith("qTStatus"):
            """
            ‘qTStatus’

            Ask the stub if there is a trace experiment running right now.

            See https://sourceware.org/gdb/current/onlinedocs/gdb/Tracepoint-Packets.html#Tracepoint-Packets
            """
            # We do not support tracing, just reply an empty packet
            self._rsp.send("")
        elif packet.startswith("qC"):
            """
            `qC`

            Return the current thread ID.

            Reply:
                `QC thread-id`: Where thread-id is a thread ID as documented in thread-id syntax.
                `(anything else)`: Any other reply implies the old thread ID.
            """
            self._rsp.send("")
        elif packet.startswith("qAttached"):
            """
            `qAttached:pid`

            Return an indication of whether the remote server attached to an existing
            process.

            See https://sourceware.org/gdb/current/onlinedocs/gdb/General-Query-Packets.html#General-Query-Packets

            Reply:
                * `1` The remote server attached to an existing process.
                * `0` The remote server created a new process.
                * `E NN` A badly formed request or an error was encountered.
            """
            # We are always attached, so reply "1"
            self._rsp.send("1")
        else:
            self._rsp.send("EF0")

    def handle_v(self, packet):
        if packet.startswith("vMustReplyEmpty"):
            self._rsp.send("")
        elif packet.startswith("vKill"):
            self._rsp.send("OK")
        else:
            self._rsp.send("EF1")

    def handle_H(self, packet):
        """
        `H op thread-id`

        Set thread for subsequent operations (m`, M, g, G, et.al.)...

        See https://sourceware.org/gdb/current/onlinedocs/gdb/Packets.html#Packets

        Reply:
          * `OK` for success
          * `E NN` for an error
        """
        # We do not support threads, so just reply OK
        self._rsp.send("OK")

    def handle_questionmark(self, packet):
        """
        `?`
        This is sent when connection is first established to query the reason the
        target halted. The reply is the same as for step and continue. This packet
        has a special interpretation when the target is in non-stop mode; see
        Remote Non-Stop [1]

        Reply: See Stop Reply Packets [2], for the reply specifications.

        [1]: https://sourceware.org/gdb/current/onlinedocs/gdb/Remote-Non_002dStop.html#Remote-Non_002dStop
        [2]: https://sourceware.org/gdb/current/onlinedocs/gdb/Stop-Reply-Packets.html#Stop-Reply-Packets
        """
        # FIXME
        self._rsp.send("S%02x" % TARGET_SIGNAL.TRAP)

    def handle_g(self, packet):
        """
        `g`
        Read general registers.

        Reply:
            * `XX…` Each byte of register data is described by two hex digits.
            * `E NN` for an error.
        """
        reply = self._rsp.bytes2hex(*[bytes(reg) for reg in self._target.registers])
        self._rsp.send(reply)

    def handle_m(self, packet):
        """
        `m addr,length`
        Read length addressable memory units starting at address addr (see addressable
        memory unit). Note that addr may not be aligned to any particular boundary.

        The stub need not use any particular size or alignment when gathering data
        from memory for the response; even if addr is word-aligned and length is a
        multiple of the word size, the stub is free to use byte accesses, or not. For
        this reason, this packet may not be suitable for accessing memory-mapped I/O
        devices.

        Reply:
            * `XX…` Memory contents; each byte is transmitted as a two-digit
              hexadecimal number. The reply may contain fewer addressable memory
              units than requested if the server was able to read only part of the
              region of memory.
            * `E NN` NN is errno
        """
        addr, length = packet[1:].split(",")
        reply = self._target.memory_read(int(addr, 16), int(length, 10))
        reply = self._rsp.bytes2hex(reply)
        self._rsp.send(reply)


def main(argv=sys.argv):
    targets = {
        "null-ppc64le": lambda: Null(PowerPC64()),
        "microwatt": lambda: Microwatt(),
    }
    parser = ArgumentParser(description=__doc__)
    parser.add_argument(
        "-t", "--target", choices=list(targets.keys()), help="Target to connect to"
    )
    args = parser.parse_args(argv[1:])
    target = targets[args.target]()
    stub = Stub(target)
    stub.start()
