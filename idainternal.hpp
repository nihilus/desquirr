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
// $Id: idainternal.hpp,v 1.2 2005/07/23 09:22:23 wjhengeveld Exp $
#ifndef _IDAINTERNAL_HPP
#define _IDAINTERNAL_HPP

// IDA headers

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <funcs.hpp>
#include <ua.hpp>
#include <name.hpp>
#include <frame.hpp>
#include <struct.hpp>
#include <typeinf.hpp>

#include "desquirr.hpp"
#include "instruction.hpp"


typedef std::vector<insn_t> insn_vector;

class LowLevel : public Instruction /*{{{*/
{
	public:
		LowLevel(insn_t insn)
			: Instruction(LOW_LEVEL, insn.ea),
				mInsn(insn)
		{}

		virtual void Accept(InstructionVisitor& visitor)
		{
			visitor.Visit(*this);
		}

		insn_t& Insn() { return mInsn; }
		
		static bool Insn(Instruction_ptr instruction, insn_t& insn) 
		{ 
			if (instruction->IsType(Instruction::LOW_LEVEL))
			{
				insn = static_cast<LowLevel*>(instruction.get())->Insn();
				return true;
			}
		
			return false; 
		}
		
	private:
		insn_t mInsn;
		
};/*}}}*/

insn_t GetLowLevelInstruction(ea_t address);


#endif // _IDAINTERNAL_HPP

