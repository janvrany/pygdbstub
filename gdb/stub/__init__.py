import enum
import io
import sys
from argparse import ArgumentParser
from socket import SocketIO

from gdb.stub.arch import PowerPC64
from gdb.stub.target import Null, Target
from gdb.stub.target.microwatt import Microwatt


class IOPipe:
    def __init__(
        self,
        _in=sys.stdin,
        _out=sys.stdout,
    ):
        if isinstance(_in, io.RawIOBase):
            self._in = io.TextIOWrapper(_in, "ascii")
        else:
            self._in = _in
        if isinstance(_out, io.RawIOBase):
            self._out = io.TextIOWrapper(_out, "ascii")
        else:
            self._out = _out

    def write(self, buffer: str):
        self._out.write(buffer)

    def flush(self):
        self._out.flush()

    def read(self, count: int) -> str | None:
        """
        Wait for and read `count` characters. Return `None`
        if there are no more data to read (peer closed the
        connection).
        """
        data = self._in.read(count)
        if data is None:
            return None
        elif len(data) == 0:
            return None
        else:
            return data

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
        self._io.flush()

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

    def send_unsupported(self):
        # Packet not (yet) supported.
        #
        #    For any command not supported by the stub, an empty response
        #    (‘$#00’) should be returned. That way it is possible to extend
        #    the protocol. A newer GDB can tell if a packet is supported
        #    based on that response.
        #
        # See https://sourceware.org/gdb/current/onlinedocs/gdb/Overview.html#Overview
        self.send("")

    def recv(self) -> str | None:
        while True:
            c = self._io.read(1)
            if c is None:
                # Client closed the connection
                return None

            if c == "\x03":
                # Handle Ctrl-C
                #
                #    ‘Ctrl-C’, on the other hand, is defined and implemented
                #    for all transport mechanisms. It is represented by sending
                #    the single byte 0x03 without any of the usual packet overhead
                #    described in the Overview section (see Overview). When a 0x03
                #    byte is transmitted as part of a packet, it is considered to be
                #    packet data and does not represent an interrupt. E.g., an ‘X’
                #    packet (see X packet), used for binary downloads, may include
                #    an unescaped 0x03 as part of its packet.
                #
                # See https://sourceware.org/gdb/current/onlinedocs/gdb/Interrupts.html#interrupting-remote-targets
                return c
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
    def __init__(self, target: Target, channel: IOPipe = IOPipe()):
        self._target = target
        self._rsp = RSP(channel)

    #
    # __enter__ and __exit__ allow to use `with` statement.
    # This is useful for interactive work with target.
    #
    def __enter__(self):
        self._target.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._target.disconnect()

    #
    # Ensure that gets disconnected when the object is gone.
    #
    def __del__(self):
        self._target.disconnect()

    def start(self):
        with self:
            self._target.flush()
            self._target.stop()
            while self.process1():
                pass

    def process1(self) -> bool:
        """
        Wait for and process single packet. Return `True` if packet
        was processed (even if there was an error processing it),
        `False` if there were no more packets (connection closed)
        """
        packet = self._rsp.recv()
        if packet is None:
            return False
        packet_type = packet[0]
        # Sigh, some packet types are not letters so
        # handle them specially
        if packet_type == "?":
            handler = self.handle_questionmark
        elif packet_type == "\x03":
            handler = self.handle_etx
        else:
            try:
                handler = getattr(self, "handle_" + packet_type)
            except AttributeError:
                self._rsp.send_unsupported()
                return
        try:
            handler(packet)
        except Exception:
            # Error when processing the packet
            self._rsp.send("EF1")
        return True

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
            self._rsp.send_unsupported()
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
            self._rsp.send_unsupported()

    def handle_v(self, packet):
        if packet.startswith("vMustReplyEmpty"):
            self._rsp.send("")
        elif packet.startswith("vKill"):
            self._rsp.send("OK")
        elif packet.startswith("vCont?"):
            """
            `vCont?`
            Request a list of actions supported by the `vCont` packet.

            Reply:
                * `vCont[;action…]` The `vCont` packet is supported. Each action is a supported command in the `vCont` packet.
                * `` (empty reply) The ‘vCont’ packet is not supported.
            """
            # We do not support vCont
            self._rsp.send_unsupported()
        elif packet.startswith("vCtrlC"):
            """
            `vCtrlC`
            Interrupt remote target as if a control-C was pressed on the remote terminal. This is the equivalent
            to reacting to the ^C (`\003`, the control-C character) character in all-stop mode while the target
            is running, except this works in non-stop mode. See interrupting remote targets, for more info on the
            all-stop variant.

            Reply:
                * `E nn` for an error
                * `OK` for success
            """
            self._target.flush()
            self._target.stop()
            self._rsp.send("OK")
        else:
            self._rsp.send_unsupported()

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

    def handle_etx(self, packet):
        # Ctrl-C was pressed in GDB. Stop the target...
        self._target.flush()
        self._target.stop()
        # ...and report it has stopped.
        self._rsp.send("S00")

    def handle_s(self, packet):
        """
        `s [addr]`

        Single step, resuming at addr. If addr is omitted, resume at same address.
        This packet is deprecated for multi-threading support. See `vCont` packet.

        Reply: See Stop Reply Packets, for the reply specifications.
        """
        if len(packet) == 1:
            self._target.flush()
            self._target.step()
            self._rsp.send("S00")
        else:
            self._rsp.send("E01")

    def handle_c(self, packet):
        """
        `c [addr]`

        Continue at addr, which is the address to resume. If addr is omitted,
        resume at current address..
        This packet is deprecated for multi-threading support. See `vCont` packet.

        Reply: See Stop Reply Packets, for the reply specifications.
        """
        if len(packet) == 1:
            self._target.flush()
            self._target.cont()
            # Do not send any reply:
            #
            #    Except for ‘?’ and ‘vStopped’, that reply is only returned when
            #    the target halts.
            #
            # See https://sourceware.org/gdb/current/onlinedocs/gdb/Stop-Reply-Packets.html#Stop-Reply-Packets
        else:
            self._rsp.send("E01")


def main(argv=sys.argv):
    targets = {
        "null-ppc64le": lambda: Null(PowerPC64()),
        "microwatt": lambda: Microwatt(),
    }
    parser = ArgumentParser(description=main.__doc__)
    parser.add_argument(
        "-t", "--target", choices=list(targets.keys()), help="Target to connect to"
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        help="TCP port to listen on. If not specified, use stdin/stdout for communication with GDB.",
    )
    args = parser.parse_args(argv[1:])
    target = targets[args.target]()
    if args.port is None:
        #
        # Use stdin/stdout for communication.
        #
        stub = Stub(target)
        stub.start()
    else:
        #
        # Listen on TCP port
        #
        from socket import AF_INET, SOCK_STREAM, error, socket

        listener = socket(AF_INET, SOCK_STREAM)
        # Wait for client to connect...
        try:

            listener.bind(("localhost", args.port))
            print(f"Listening on localhost:{args.port}")
            listener.listen(1)
        except error as e:
            print(f"Cannot listen on localhost:{args.port}: error {e[0]} - {e[1]}")
        client, addr = listener.accept()

        # Once client connects, stop listening and
        # start stub on client socket
        try:
            print(f"Client connected from {addr[0]}:{addr[1]}")
            listener.close()
            client_io = SocketIO(client, "rw")
            try:
                stub = Stub(target, IOPipe(client_io, client_io))
                stub.start()
            finally:
                client_io.close()
        except error as e:
            print(f"Failed to handle client: {args.port}: error {e[0]} - {e[1]}")
