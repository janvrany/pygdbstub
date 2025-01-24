"""
Tests for Null target (gsb.stub.target.Null)
"""

from gdb.stub.arch import PowerPC64
from gdb.stub.target import Null

def test_01():
    target = Null(PowerPC64())
    target.memory_write(200, b'\xCA\xFE\xCA\xFE')

    assert target.memory_read(200, 4) == b'\xCA\xFE\xCA\xFE'
    assert target.memory_read(201, 2) ==     b'\xFE\xCA'
    

def test_02():
    target = Null(PowerPC64())
    target.memory_write(200, b'\xCA\xFE\xCA\xFE')

    # Trying to read past (previously written) region
    assert target.memory_read(202, 4) == b'\xBE\xEF'

def test_02():
    target = Null(PowerPC64())
    target.memory_write(200, b'\xCA\xFE\xCA\xFE')

    # Writing 4 bytes over the initial region at address 203
    # should result in continguous region of 7 bytes. 
    target.memory_write(203, b'\xDE\xAD\xAF\xFE')
    assert target.memory_read(200, 7) == b'\xCA\xFE\xCA\xDE\xAD\xAF\xFE'

def test_04():
    target = Null(PowerPC64())
    target.memory_write(200, b'\xCA\xFE\xCA\xFE')

    # Reading 1 byte from address 199 should return an empty bytearray
    # as this address was not written to.     
    assert target.memory_read(199, 1) == b''

def test_05():
    target = Null(PowerPC64())
    target.memory_write(200, b'\xCA\xFE\xCA\xFE')

    # Write 1 byte at address 199, this should join it to
    # the initial region. 
    target.memory_write(199, b'\x01')
    assert target.memory_read(199, 3) == b'\x01\xCA\xFE'

def test_06():
    target = Null(PowerPC64())
    target.memory_write(200, b'\xCA\xFE\xCA\xFE')

    # Write 1 byte at address 205, this should join it to
    # the initial region. 
    target.memory_write(201, b'\x02')
    assert target.memory_read(200, 2) == b'\xFE\x02'

def test_07():
    target = Null(PowerPC64())
    target.memory_write(200, b'\xCA\xFE\xCA\xFE')

    # Write disjoint region of 4 bytes at 208.
    target.memory_write(208, b'\xDE\xAD\xBE\xEF')
    assert target.memory_read(208, 4) == b'\xDE\xAD\xBE\xEF'

    # Now write over the hole 
    target.memory_write(204, b'\xA5\x5A\xA5\x5A')
    assert target.memory_read(200, 4) == b'\xCA\xFE\xCA\xFE'
    assert target.memory_read(204, 4) == b'\xA5\x5A\xA5\x5A'
    assert target.memory_read(208, 4) == b'\xDE\xAD\xBE\xEF'
    assert target.memory_read(200, 12) == b'\xCA\xFE\xCA\xFE\xA5\x5A\xA5\x5A\xDE\xAD\xBE\xEF'

def test_08():
    target = Null(PowerPC64())
    target.memory_write(200, b'\xCA\xFE\xCA\xFE')

    # Write disjoint region of 4 bytes at 208.
    target.memory_write(208, b'\xDE\xAD\xBE\xEF')
    assert target.memory_read(208, 4) == b'\xDE\xAD\xBE\xEF'

    # Now write over the hole with overlaps
    target.memory_write(202, b'\x01\x02\xA5\x5A\xA5\x5A\x03\x04')
    assert target.memory_read(200, 4) == b'\xCA\xFE\x01\x02'
    assert target.memory_read(204, 4) == b'\xA5\x5A\xA5\x5A'
    assert target.memory_read(208, 4) == b'\x03\x04\xBE\xEF'
    assert target.memory_read(201, 10) == b'\xFE\x01\x02\xA5\x5A\xA5\x5A\x03\x04\xBE'

def test_08():
    target = Null(PowerPC64())
    target.memory_write(200, b'\xCA\xFE\xCA\xFE')

    # Write disjoint region of 4 bytes at 208.
    target.memory_write(208, b'\xDE\xAD\xBE\xEF')
    assert target.memory_read(208, 4) == b'\xDE\xAD\xBE\xEF'

    # Now write over the hole with overlaps
    target.memory_write(202, b'\x01\x02\xA5\x5A\xA5\x5A\x03\x04')
    assert target.memory_read(200, 4) == b'\xCA\xFE\x01\x02'
    assert target.memory_read(204, 4) == b'\xA5\x5A\xA5\x5A'
    assert target.memory_read(208, 4) == b'\x03\x04\xBE\xEF'
    assert target.memory_read(201, 10) == b'\xFE\x01\x02\xA5\x5A\xA5\x5A\x03\x04\xBE'

def test_09():
    target = Null(PowerPC64())
    target.memory_write(200, b'\xCA\xFE\xCA\xFE')

    # Write disjoint region of 4 bytes at 208.
    target.memory_write(208, b'\xDE\xAD\xBE\xEF')
    assert target.memory_read(208, 4) == b'\xDE\xAD\xBE\xEF'

    assert target.memory_read(202, 8) == b'\xCA\xFE'

    



