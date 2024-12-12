from setuptools import find_packages, setup

setup(
    name="pygdbstub",
    version="0.0.1",
    packages=find_packages(include=["pygdbstub", "pygdbstub.*"]),
    install_requires=[],
    description="Another GDB stub implemented in Python3",
    author="Jan Vraný",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT",
    ],
    requires=[],
)
