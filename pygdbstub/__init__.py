import enum
import io
import logging
import os
import sys
from argparse import ArgumentParser
from fcntl import F_GETFL, F_SETFL, fcntl
from selectors import EVENT_READ, DefaultSelector
from socket import SocketIO

from .target import Target

logging.basicConfig()
_logger = logging.getLogger(__name__)


class IOPipe:
    _logger = logging.getLogger(__name__ + ".io")
    _logger.disabled = True  # disabled by default to reduce noise

    def __init__(
        self,
        _in=sys.stdin,
        _out=sys.stdout,
    ):
        if isinstance(_in, io.BufferedReader):
            self._in = io.TextIOWrapper(_in, "ascii")
        elif isinstance(_in, io.RawIOBase):
            self._in = io.TextIOWrapper(io.BufferedReader(_in, 256), "ascii")
        else:
            self._in = _in
        if isinstance(_out, io.RawIOBase):
            self._out = io.TextIOWrapper(_out, "ascii")
        else:
            self._out = _out

        # Check, if input stream is selectable...
        try:
            fd = _in.fileno()
            # ...if so, make it non-blocking...
            if hasattr(_in, "setblocking"):
                _in.setblocking(False)
            else:
                flags = fcntl(_in, F_GETFL)
                flags |= os.O_NONBLOCK
                fcntl(_in, F_SETFL, flags)
            # ...and setup selector object
            self._selector = DefaultSelector()
            self._selector.register(fd, EVENT_READ, None)
        except OSError:
            self._selector = None

    def write(self, buffer: str):
        self._out.write(buffer)

    def flush(self):
        self._out.flush()

    @property
    def closed(self):
        return self._in.closed or self._out.closed

    def readwait(self, timeout: float | None = None):
        """
        Block until some data are available. If the
        input is not 'waitable' (like in-memory buffer),
        return immediately.

        If timeout is given (not None), raise `TimeoutError`
        if no data are available before timeout expires.
        """
        if hasattr(self._in.buffer, "peek"):
            if len(self._in.buffer.peek(1)) != 0:
                self._logger.debug("readwait() done, data in buffer")
                return

        if self._selector is not None:
            while True:
                self._logger.debug("readwait() ...")
                if self._in.closed:
                    self._logger.debug("readwait() done, channel closed")
                    return
                events = self._selector.select(timeout)
                if len(events) > 0:
                    self._logger.debug("readwait() done, data available")
                    return
                if timeout:
                    self._logger.debug("readwait() done, timed out!")
                    raise TimeoutError("No data available")

    def read(self, count: int, timeout: float | None = None) -> str | None:
        """
        Wait for and read `count` characters. Return `None`
        if there are no more data to read (peer closed the
        connection).

        If timeout is given (not None), raise `TimeoutError`
        if no data are available before timeout expires.
        """
        if self._in.closed:
            return None
        data = self._in.read(count)
        if data is None or len(data) == 0:
            self.readwait(timeout)
            data = self._in.read(count)
        if data is None or len(data) == 0:
            return None
        else:
            return data


Bytes2HexMap = ["%02x" % x for x in range(256)]


def bytes2hex(*data: bytes) -> str:
    hex = io.StringIO()
    for datum in data:
        for b in datum:
            hex.write(Bytes2HexMap[b])
    return hex.getvalue()


def string2hex(*data: str) -> str:
    return bytes2hex(*[bytes(datum, "ascii") for datum in data])


Hex2BytesMap = {("%02x" % x): x for x in range(256)}


def hex2bytes(hex: str) -> bytearray:
    assert len(hex) % 2 == 0
    data = bytearray(len(hex) // 2)
    for i in range(len(data)):
        b = Hex2BytesMap[hex[2 * i : 2 * i + 2]]
        data[i] = b
    return data


def hex2string(hex: str) -> str:
    return hex2bytes(hex).decode("ascii")


class RSP(object):
    """
    And implementation of RSP protocol taking care of proper
    escaping and checksuming.
    """

    _logger = logging.getLogger(__name__ + ".rsp")

    def __init__(self, channel=IOPipe()):
        self._io = channel

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
        csum = 0
        for c in data:
            assert ord(c) < 256
            if c in ("$", "#", "*", "}"):
                # Handle escaping.
                #
                #    The binary data representation uses 7d (ASCII ‘}’) as an escape character. Any escaped byte is
                #    transmitted as the escape character followed by the original character XORed with 0x20. For
                #    example, the byte 0x7d would be transmitted as the two bytes 0x7d 0x5d. The bytes 0x23 (ASCII ‘#’),
                #    0x24 (ASCII ‘$’), and 0x7d (ASCII ‘}’) must always be escaped. Responses sent by the stub must also
                #    escape 0x2a (ASCII ‘*’), so that it is not interpreted as the start of a run-length encoded
                #    sequence (described next).
                #
                # See https://sourceware.org/gdb/current/onlinedocs/gdb/Overview.html#Binary-Data
                csum += ord("}")
                self._io.write("}")
                c = chr(ord(c) ^ 0x20)
            csum += ord(c)
            self._io.write(c)
        csum = csum & 0xFF
        self._io.write("#")
        self._io.write("%02x" % csum)
        self._io.flush()
        self._logger.debug("send: " + data)
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

    def recv(self, timeout: float | None = None) -> str | None:
        while True:
            c = self._io.read(1, timeout)
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
                self._logger.debug("recv Ctrl-C")
                return c
            elif c == "$":
                break

        buffer = io.StringIO()
        buffer_csum = 0

        while True:
            c = self._io.read(1)
            if c is None:
                # Client closed the connection
                return None
            if c == "}":
                # Handle escaping.
                #
                #    The binary data representation uses 7d (ASCII ‘}’) as an escape character. Any escaped byte is
                #    transmitted as the escape character followed by the original character XORed with 0x20. For
                #    example, the byte 0x7d would be transmitted as the two bytes 0x7d 0x5d. The bytes 0x23 (ASCII ‘#’),
                #    0x24 (ASCII ‘$’), and 0x7d (ASCII ‘}’) must always be escaped. Responses sent by the stub must also
                #    escape 0x2a (ASCII ‘*’), so that it is not interpreted as the start of a run-length encoded
                #    sequence (described next).
                #
                # See https://sourceware.org/gdb/current/onlinedocs/gdb/Overview.html#Binary-Data
                c = self._io.read(1)
                if c is None:
                    # Client closed the connection
                    return None
                else:
                    # Update checksum
                    buffer_csum += ord(c)
                buffer_csum += ord("}") + ord(c)
                buffer.write(chr(ord(c) ^ 0x20))
            elif c == "#":
                break
            else:
                buffer_csum += ord(c)
                buffer.write(c)
        buffer_csum = buffer_csum & 0xFF

        csum = int("0x" + self._io.read(2), 16)
        assert (
            csum == buffer_csum
        ), f"Checksums do not match (sent: {hex(csum)}, recv'd: {hex(buffer_csum)})"
        self.send_ack()
        self._logger.debug("recv: " + buffer.getvalue())
        return buffer.getvalue()


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
    _logger = logging.getLogger(__name__)
    _poll_interval = 0.5  # seconds

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
            while True:
                try:
                    if not self.process1(self._poll_interval):
                        return
                except TimeoutError:
                    self.check_target()

    def process1(self, timeout: float | None = None) -> bool:
        """
        Wait for and process single packet. Return `True` if packet
        was processed (even if there was an error processing it),
        `False` if there were no more packets (connection closed)
        """
        packet = self._rsp.recv(timeout)
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
                return True
        try:
            handler(packet)
        except Exception:
            # Error when processing the packet
            self._rsp.send("EF1")
        return True

    def check_target(self):
        """
        Check for any changes in target (like target spuriously resumed, target
        stopped on swbreakpoint, died and so on). Report (stop) event (if any)
        back to GDB.

        Called whenever there are no packets available for some time.
        """

        if self._target.has_swbreak():
            if self._target.hit_swbreak():
                # Here we simply report `S05` and not `T05swbreak` because we
                # do not support qSupported yet and therefore could not report
                # to GDB we support swbreak:
                #
                #   This packet should not be sent by default; older GDB versions
                #   did not support it. GDB requests it, by supplying an
                #   appropriate ‘qSupported’ feature (see qSupported). The
                #   remote stub must also supply the appropriate ‘qSupported’
                #   feature indicating support.
                #
                # See https://sourceware.org/gdb/current/onlinedocs/gdb/Stop-Reply-Packets.html#Stop-Reply-Packets
                self._rsp.send("S%02x" % TARGET_SIGNAL.TRAP)
        pass

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
        elif packet.startswith("qRcmd"):
            """
            `qRcmd,command`
            command (hex encoded) is passed to the local interpreter for execution.
            Invalid commands should be reported using the output string. Before the
            final result packet, the target may also respond with a number of intermediate
            `Ooutput` console output packets. Implementors should note that providing
            access to a stubs's interpreter may have security implications.

            Reply:
                * `OK` A command response with no output.
                * `OUTPUT` A command response with the hex encoded output string OUTPUT.
                * `E NN` Indicate a badly formed request. The error number NN is given as hex digits.
                * An empty reply indicates that `qRcmd` is not recognized.
            """
            _, command = packet.split(",")
            try:
                response = io.StringIO()
                handled = self._target.monitor(hex2string(command), response)
                if handled is None:
                    self._rsp.send_unsupported()
                elif handled is True:
                    if response.getvalue() is None:
                        self._rsp.send("OK")
                    else:
                        self._rsp.send(string2hex(*[response.getvalue()]))
                else:
                    self._rsp.send("EF0")
            except Exception:
                self._rsp.send("EF1")
        else:
            self._rsp.send_unsupported()

    def handle_v(self, packet):
        if packet.startswith("vMustReplyEmpty"):
            self._rsp.send("")
        elif packet.startswith("vCont?"):
            """
            `vCont?`p
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
        reply = bytes2hex(*[bytes(reg) for reg in self._target.registers])
        self._rsp.send(reply)

    def handle_P(self, packet):
        """
        Write register n… with value r…. The register number n is in hexadecimal, and r… contains two hex digits for each byte in the register (target byte order).
        E.g.
        Pf=34120000
        """
        regnum, value = packet[1:].split("=")
        regnum = int(regnum, 16)
        value = hex2bytes(value)
        self._target.register_write(regnum, value)
        self._rsp.send("OK")

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
        reply = self._target.memory_read(int(addr, 16), int(length, 16))
        reply = bytes2hex(reply)
        self._rsp.send(reply)

    def handle_M(self, packet):
        """
        `M addr,length:XX…`
        Write length addressable memory units starting at address addr (see addressable
        memory unit). The data is given by XX…; each byte is transmitted as a two-digit
        hexadecimal number.

        Reply:
            * `OK` for success
            * `E NN` for an error (this includes the case where only part of the data was written).
        """
        addr, length_and_data = packet[1:].split(",")
        length, data = length_and_data.split(":")
        self._target.memory_write(int(addr, 16), hex2bytes(data), int(length, 16))
        self._rsp.send("OK")

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

    def handle_k(self, packet):
        """
        `k`
        Kill request.

        The exact effect of this packet is not specified.

        For a bare-metal target, it may power cycle or reset the target system.
        For that reason, the `k` packet has no reply.

        ...
        """
        self._target.flush()
        self._target.reset()
        self._rsp.send("S00")

    def handle_z(self, packet):
        self.handle_zZ(packet)

    def handle_Z(self, packet):
        self.handle_zZ(packet)

    def handle_zZ(self, packet):
        """
        `z type,addr,kind`
        `Z type,addr,kind`

        Insert (`Z`) or remove (`z`) a type breakpoint or watchpoint starting at
        address `addr` of kind `kind`.

        Each breakpoint and watchpoint packet type is documented separately, see
        https://sourceware.org/gdb/current/onlinedocs/gdb/Packets.html#Packets

        Implementation notes: A remote target shall return an empty string for
        an unrecognized breakpoint or watchpoint packet type. A remote target
        shall support either both or neither of a given `Ztype…` and `ztype…`
        packet pair. To avoid potential problems with duplicate packets, the
        operations should be implemented in an idempotent way.
        """
        if not self._target.has_swbreak():
            self._rsp.send_unsupported()
            return

        type, addr, kind = packet[1:].split(",")
        addr = int(addr, 16)
        kind = int(kind, 16)
        if packet[0] == "Z":
            if type == "0":
                self._target.set_swbreak(addr, kind)
                self._rsp.send("OK")
        elif packet[0] == "z":
            if type == "0":
                self._target.del_swbreak(addr, kind)
                self._rsp.send("OK")
        else:
            self._rsp.send_unsupported()


def main(argv=sys.argv):
    from .arch import PowerPC64
    from .target import Null
    from .target.microwatt import Microwatt

    targets = {
        "null-ppc64le": lambda *params: Null(PowerPC64(*params)),
        "microwatt": lambda *params: Microwatt(*params),
    }
    parser = ArgumentParser(description=main.__doc__)
    parser.add_argument(
        "-t", "--target", choices=list(targets.keys()), help="Target to connect to."
    )
    parser.add_argument("-b", "--board", type=str, help="Board to connect to")
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        help="TCP port to listen on. If not specified, use stdin/stdout for communication with GDB.",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_const",
        const=True,
        default=False,
        help="Open a debugger on uncaught exception. Only really usefull when using TCP stream",
    )
    args = parser.parse_args(argv[1:])
    if args.debug:
        from .debug import breakpointhook, excepthook

        sys.excepthook = excepthook
        sys.breakpointhook = breakpointhook
        _logger.setLevel(logging.DEBUG)
    if args.board is not None:
        from . import boards

        try:
            board = getattr(boards, args.board)
        except AttributeError:
            print(f"No such board defined: {args.board}")
            return 1
        target = targets[args.target](board())
    else:
        target = targets[args.target]()
    if args.port is None:
        #
        # Use stdin/stdout for communication.
        #
        # Here we disable logging altogether otherwise log messages
        # would go to stdout/stderr which is used for RSP
        # communication - we do not want that
        _logger.disabled = True
        _logger.propagate = False
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
            _logger.info(f"Listening on localhost:{args.port}")
            listener.listen(1)
        except error as e:
            _logger.error(
                f"Cannot listen on localhost:{args.port}: error {e[0]} - {e[1]}"
            )
        client, addr = listener.accept()

        # Once client connects, stop listening and
        # start stub on client socket
        try:
            _logger.info(f"Client connected from {addr[0]}:{addr[1]}")
            listener.close()
            client_io = SocketIO(client, "rw")
            try:
                stub = Stub(target, IOPipe(client_io, client_io))
                stub.start()
            finally:
                client_io.close()
        except error as e:
            _logger.error(
                f"Failed to handle client: {args.port}: error {e[0]} - {e[1]}"
            )
