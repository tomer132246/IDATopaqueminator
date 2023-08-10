# IDATopaqueminator
IDA plugin for simple opaque predicates removal using symbolic execution with angr

# Dependencies
- IDA 7.x
- Angr (pip install latest version.)
- Keystone (you can probably remove this prequisite from the code, im using it only for testing.)
- Tested with python 3.9


# Installation
- Simply place the .py files in the %IDA_INSTALLATION%\plugins.


# Usage
- Ctrl-Alt-T To recieve an anlysis on the current function (the one you are viewing.).
- NOTE:
  1. The results may be inaccurate!. The plugin is instrumentlizing the shell-code of the current function without prior context knowledge.
  2. THE PLUGIN WILL AND SHALL NOT DO ANY CHANGES TO YOUR IDB.
  3. The analyzing is currently done per-basic-block. *(https://en.wikipedia.org/wiki/Basic_block)


# TODO
1. Multiple blocks analyzing.
    - Need to propagate the information in-between basic blocks.
3. Better loop handling.



