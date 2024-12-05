# Another GDB stub implemented in Python3

## Setup
```sh
# Install and compile urjtag (for Microwatt)
apt install libusb-1.0-0-dev libftdi1-dev python3-dev
git clone -b ftdi-arty https://github.com/shingarov/urjtag.git
cd urjtag/urjtag
PYTHON=python3 ./configure --enable-python --without-ftd2xx
make -j$(nproc)
cd ../..

# Clone this repository
git clone https://github.com/janvrany/pygdbstub.git
cd pygdbstub

# Create virtual environment for pygdbstub
virtualenv --prompt "pygdbstub" .venv
echo "export LD_LIBRARY_PATH=$(realpath ../urjtag/urjtag/src/.libs)" >> .venv/bin/activate
source .venv/bin/activate

# Install dependencies
pip3 install -r requirements-dev.txt
pip3 install ../urjtag/urjtag/bindings/python

# Setup pre-commit and pre-push hooks (if you want)
pre-commit install -t pre-commit
pre-commit install -t pre-push
```

## Usage examples

### Using TCP port

```
.venv/bin/python -m pygdbstub -t microwatt -b Genesys2 -p 7000
```

* run *pygdbstub* (`-m pygdbstub`)
* connect to Microwatt on Digilent Genesys2 FPGA boatd (`-t microwatt -b Genesys2`)
* listen on localhost, port 7000 (`-p 7000`)

Then in GDB, connect to stub like:

```
(gdb) set arch powerpc:common64
(gdb) target remote :7000
```

### Starting *pygdbstub* directly from GDB

```
(gdb) set arch powerpc:common64
(gdb) target remote | .venv/bin/python -m pygdbstub -t microwatt
```

* run *pygdbstub* (`-m pygdbstub`)
* connect to Microwatt on Arty FPGA (`-t microwatt`, Arty is default board for Microwatt target)
* use stdio to communicate with GDB (default)

## For developers

### Running tests

To run tests, just run:

```
pytest
```

### Debugging communication

Some hints to help debugging communication between GDB and pygdbstub:

 * In GDB, turn on remote protocol debugging:

   ```
   set debug remote 1
   ```

 * If you really want to see the exact bytes going back and forth, run
   stub using `socat`:

   ```
   socat -v tcp4-listen:7007,reuseaddr,fork 'exec:python3 -m pygdbstub'
   ```

   and then in GDB, connect to port 7007:

   ```
   target remote :7007
   ```
