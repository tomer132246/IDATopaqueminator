# IDATopaqueminator
IDA plugin for simple opaque predicates removal using symbolic execution with angr


# Installation
- Simply place the .py files in the %IDA_INSTALLATION%\plugins.


# Usage
- Ctrl-Shift-T To recieve an anlysis on the current function (the one you are viewing.).
- NOTE:
  1. The results may be inaccurate!. The plugin is instrumentlizing the shell-code of the current function without prior context knowledge.
  2. THE PLUGIN WILL AND SHALL NOT DO ANY CHANGES TO YOUR IDB.
  3. The analyzing is currently done per-basic-block. *(https://en.wikipedia.org/wiki/Basic_block)




