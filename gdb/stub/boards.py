import urjtag


class Board(object):
    def __init__(self, cable, params=[]):
        self._cable = cable
        self._params = params

    def chain(self):
        """
        Create and initialize JTAG chain.
        """
        cable = self._cable
        params = self._params
        chain = urjtag.chain()
        chain.cable(cable, *params)
        return chain


class Arty(Board):
    def __init__(self):
        super().__init__("DigilentNexysVideo")


class Genesys2(Board):
    def __init__(self):
        super().__init__("DigilentHS1", ["interface=1", "index=0"])
