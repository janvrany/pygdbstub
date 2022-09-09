# Another GDB stub implemented in Python3

## Setup
```sh
# Clone the repository
git clone https://github.com/janvrany/pygdbstub.git
cd pygdbstub

# Create virtual environment for pygdbstub
virtualenv --prompt "pygdbstub" .venv
source .venv/bin/activate

# Install dependencies
pip3 install -r requirements-dev.txt 

# Setup pre-commit and pre-push hooks (if you want)
pipenv run pre-commit install -t pre-commit
pipenv run pre-commit install -t pre-push
```

## Debugging communication

Some hints to help debuging communication between GDB and pygdbstub:

 * In GDB, turn on remote protocol debugging: 
   
   ```
   set debug remote 1
   ```

 * If you really want to see the exact bytes going back and forth, run 
   stub using `socat`:

   ```
   socat -v tcp4-listen:7007,reuseaddr,fork 'exec:python3 -m gdb.stub'
   ```

   and then in GDB, connect to port 7007:

   ```
   target remote :7007
   ```
