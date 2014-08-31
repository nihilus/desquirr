// 
// Copyright (c) 2002 David Eriksson <david@2good.nu>
// 
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
//
// $Id: desquirr.hpp,v 1.7 2005/10/15 23:55:06 wjhengeveld Exp $
#ifndef _DESQUIRR_HPP
#define _DESQUIRR_HPP

//
// C++ includes
//
#include <algorithm>
#include <iostream>
#include <sstream>
#include <list>
#include <map>
#include <stack>
#include <string>
#include <vector>

//
// Boost includes
//
#if !defined(_MSC_VER) && !defined(__GNUC__)
#pragma option push -b -a8 -pc -Vx- -Ve- -w-inl -w-aus -w-sig
#endif
#include <boost/shared_ptr.hpp>
#include <boost/shared_array.hpp>
#include <boost/format.hpp>
#if !defined(_MSC_VER) && !defined(__GNUC__)
#pragma option pop
#endif

typedef unsigned char Calling;  // calling convention and memory model

// from typedef.hpp
const Calling CALLING_MASK = 0xF0;
const Calling  CALLING_INVALID  = 0x00;  // this value is invalid
const Calling  CALLING_UNKNOWN  = 0x10;  // unknown calling convention
const Calling  CALLING_VOIDARG  = 0x20;  // function without arguments
                                    // ATT7: if has other cc and argnum == 0,
                                    // represent as f() - unknown list
const Calling  CALLING_CDECL    = 0x30;  // stack
const Calling  CALLING_ELLIPSIS = 0x40;  // cdecl + ellipsis
const Calling  CALLING_STDCALL  = 0x50;  // stack, purged
const Calling  CALLING_PASCAL   = 0x60;  // stack, purged, reverse order of args
const Calling  CALLING_FASTCALL = 0x70;  // stack, first args are in regs (compiler-dependent)
const Calling  CALLING_THISCALL = 0x80;  // stack, first arg is in reg (compiler-dependent)

// from nalt.hpp
#define STRING_PASCAL   1       // Pascal-style ASCII string (length byte)
#define STRING_LEN2     2       // Pascal-style, length is 2 bytes
#define STRING_UNICODE  3       // Unicode string
#define STRING_LEN4     4       // Pascal-style, length is 4 bytes
#define STRING_ULEN2    5       // Pascal-style Unicode, length is 2 bytes
#define STRING_ULEN4    6       // Pascal-style Unicode, length is 4 bytes
#define STRING_LAST     6       // Last string type



enum  Signness
{
	UNKNOWN_SIGN,
	UNSIGNED_INT,
	SIGNED_INT
};

enum { INVALID_ADDR = 0xffffffff };
typedef unsigned long Addr;
typedef unsigned long RegisterIndex;



//
// Forward declararions
//
class ErasePool;
class Expression;
class Instruction;
class Node;
class Function;

//
// Typedefs
//
typedef boost::shared_ptr<ErasePool> ErasePool_ptr;

typedef boost::shared_ptr<Expression> Expression_ptr;
//typedef std::list<Expression_ptr>     Expression_list;
typedef std::vector<Expression_ptr>   Expression_vector;

typedef boost::shared_ptr<Instruction> Instruction_ptr;
typedef std::vector<Instruction_ptr>   Instruction_vector;
typedef std::list<Instruction_ptr>     Instruction_list;

typedef Instruction_vector Instruction_collection;

typedef std::stack<Instruction_list::iterator> Instruction_list_iterator_stack;

typedef std::pair    <unsigned short, Addr> RegisterToAddress_pair;
typedef std::multimap<unsigned short, Addr> RegisterToAddress_map;

typedef boost::shared_ptr<Node>  Node_ptr;
typedef std::list<Node_ptr>      Node_list;

typedef boost::shared_ptr<Function>  Function_ptr;
typedef std::list<Function_ptr>      Function_list;

enum LongSize 
{
	UNKNOWN_LONG_SIZE = 0,
	IS_16_BIT = 16,
	IS_32_BIT = 32,
};

void setbits(LongSize size);
bool is16bit();
bool is32bit();

int message(const char *format,...);

void DumpList(Instruction_list& list);
std::ostream& printlist(std::ostream& os, Instruction_list& list);
void DumpList(Node_list& list);
std::ostream& printlist(std::ostream& os, Node_list& list);
void DumpVector(Expression_vector& list);
std::ostream& printvector(std::ostream& os, Expression_vector& list);

#endif // _DESQUIRR_HPP

