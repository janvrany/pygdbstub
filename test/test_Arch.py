from gdb.stub.arch import PowerPC64


def test_PowerPC64() -> None:
    arch = PowerPC64()

    r15 = arch.registers[15]

    assert r15.name == "r15"
    assert r15.size == 64
    assert bytes(r15) == bytes(8)

    f10 = arch.registers["f10"]

    assert f10.name == "f10"
    assert f10.size == 64
    assert bytes(r15) == bytes(8)
