from setuptools import find_packages, setup

README = open("README.md", encoding="utf-8").read()

# extract version from package
with open("pygdbstub/__init__.py", "r", encoding="utf-8") as f:
    for line in f:
        if line.startswith("__version__"):
            version = line.split("=")[1].strip().strip("\"'")
            break
    else:
        raise ValueError("Version not found")

setup(
    name="pygdbstub-neo",
    version=version,
    packages=find_packages(include=["pygdbstub", "pygdbstub.*"]),
    install_requires=[],
    description="Another GDB stub implemented in Python3",
    long_description=README,
    long_description_content_type="text/markdown",
    author="Jan Vraný",
    keywords=["gdb", "stub", "python"],
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
    ],
    requires=[],
)
