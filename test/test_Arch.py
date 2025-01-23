from pygdbstub.arch import PowerPC64


def test_PowerPC64() -> None:
    arch = PowerPC64()

    r15 = arch.registers[15]

    assert r15.name == "r15"
    assert r15.size == 64
    assert r15.get() == 0
    assert bytes(r15) == bytes(8)
    r15.set(0xCAFE)
    assert r15.get() == 0xCAFE
    assert bytes(r15) == b"\xFE\xCA\x00\x00\x00\x00\x00\x00"
    r15.set_bytes(b"\xFE\xAF\x00\x00\x00\x00\x00\x00")
    assert r15.get() == 0xAFFE

    f10 = arch.registers["f10"]

    assert f10.name == "f10"
    assert f10.size == 64
    assert f10.get() == 0.0
    assert bytes(f10) == bytes(8)
    f10.set(float(-0.2))
    assert f10.get() == float(-0.2)
