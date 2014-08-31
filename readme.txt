
Desquirr - A decompiler plugin for Interactive Disassembler Pro
===============================================================

Copyright (c) 2002 David Eriksson <david@2good.nu>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


Introduction
------------

Desquirr is a decompiler plugin for IDA Pro. It is currently capable of simple
data flow analysis of binaries with Intel x86 machine code.

This program is currently under development. Suggestions, bug reports and
patches are welcome.

For more information, please visit this web site:

  http://desquirr.sourceforge.net/

  
Installation and configuration
------------------------------

1. Copy desquirr.plw to the plugins subdirectory in your IDA Pro installation

2. Edit plugins.cfg (optionally) to get different kinds of decompilation:

     Decompile_to_C desquirr Ctrl+F9  0
     Decompile desquirr Ctrl+F10  1
              

Limitations
-----------

The limitations are not limited to this list :-)

o Only decompiles one function at a time

o Does not handle all types of instructions

o Does not handle DX:AX or EDX:EAX very well

o Does not handle register variables properly

o Leaves pop statements in the end of functions

o Lots of code is inlined in the .hpp files but should be moved to the .cpp
  files


Software needed to compile Desquirr
-----------------------------------

Interactive Disassembler Pro and SDK version 4.21:

  http://www.datarescue.com/idabase/

The Boost C++ Libraries version 1.27.0:

  http://boost.org/

The free Borland C++Builder Compiler:

  http://www.borland.com/bcppbuilder/freecompiler/


