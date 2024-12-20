import logging

_logger = logging.getLogger(__name__)

class Board(object):
    def __init__(self, cable, params=[]):
        try:
            import urjtag
        except ImportError as ie:
            _logger.error("Failed to import urjtag, please see README.md for details.")
            _logger.info("https://github.com/janvrany/pygdbstub/blob/master/README.md")
            raise ie
   
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
