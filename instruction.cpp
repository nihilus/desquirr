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
// $Id: instruction.cpp,v 1.8 2007/01/30 09:49:30 wjhengeveld Exp $

//
// C++ headers
//
#include <stack>

//
// IDA headers
//
#include <ida.hpp>
#include <nalt.hpp>

//
// Local headers
//
#include "instruction.hpp"
#include "expression.hpp"
#include "analysis.hpp"

/**
 * Apply InstructionVisitor on a list of nodes
 */
void Accept(Node_list& nodes, InstructionVisitor& visitor)/*{{{*/
{
	for (Node_list::iterator i = nodes.begin();
			i != nodes.end();
			i++)
	{
		visitor.NodeBegin(*i);
		Accept((**i).Instructions(), visitor);
		visitor.NodeEnd();
	}
}/*}}}*/

/**
 * Apply visitor on a list of instructions
 */
void Accept(Instruction_list& instructions, InstructionVisitor& visitor)/*{{{*/
{
	for (Instruction_list::iterator i = instructions.begin();
			i != instructions.end();
			i++)
	{
		(**i).Accept(visitor);
	}
}/*}}}*/

const int BoolArray::POWER_OF_2[BoolArray::SIZE] =/*{{{*/
{
	1<<0, 1<<1, 1<<2, 8, 16, 32, 64, 128, 
	256, 512, 1024, 2048, 4096, 8192, 16384, 32768,
	1<<16, 1<<17, 1<<18, 1<<19, 1<<20, 1<<21
};/*}}}*/


/* Find DU-chains {{{ */
class FindDefintionUseChainsHelper
{
	public:
		FindDefintionUseChainsHelper(Instruction_list& instructions)
			: mInstructions(instructions)
		{}

		void OnDefinedRegister(Instruction_list::iterator item, 
				Instruction_ptr instr, int reg)
		{
			// XXX: not for register variables

			for(item++; item != mInstructions.end(); item++)
			{
				Instruction_ptr next = *item;

				// Used here?
				if ( next->Uses().Get(reg) )
				{
					instr->AddToDuChain(reg, next->Address());
				}

				// Defined here?
				if ( next->Definitions().Get(reg) )
				{
					break;
				}
			}
			
			if (mInstructions.end() == item)
			{
				// We got to the end of the instruction list,
				// that means this is the last defintion of this register!
				// TODO: check that it is in liveout too!
				instr->SetLastDefinition(reg);
			}
		}

		void OnInstruction(Instruction_list::iterator item)
		{
			Instruction_ptr instr = *item;
			BoolArray& def = instr->Definitions();
			
			for (int reg = 0; reg < BoolArray::SIZE; reg++)
			{
				// Is register i is defined here?
				if (def.Get(reg))
				{
					OnDefinedRegister(item, instr, reg);
				}
			}
		}

	private:
		Instruction_list& mInstructions;
};

void Instruction::FindDefintionUseChains(Instruction_list& instructions)
{
	FindDefintionUseChainsHelper helper(instructions);
	
	for (Instruction_list::iterator item = instructions.begin();
			item != instructions.end();
			item++)
	{
		helper.OnInstruction(item);

#if 0
		Instruction_ptr instr = *item;
		msg("%p DU chain:\n", instr->Address());
		for (RegisterToAddress_map::iterator du = instr->mDuChain.begin();
				du != instr->mDuChain.end();
				du++)
		{
			msg("\t%s -> %p\n", Register::Name(du->first).c_str(), du->second);
		}
#endif
	}

}/*}}}*/

// outputs:
//    { var:[addr, addr], var:[addr, addr] }
std::ostream& operator<< (std::ostream& os, const RegisterToAddress_map& vs)
{
    unsigned short reg= 0xffff;
    bool bFirstAddr= true;
    os << "{ ";
    for (RegisterToAddress_map::const_iterator i=vs.begin() ; i!=vs.end() ; ++i)
    {
        if (reg!=0xffff && reg!=(*i).first)
            os << "], ";
        if (reg==0xffff || reg!=(*i).first) {
            reg = (*i).first;
            os << "R" << reg;
            os << "[";
            bFirstAddr= true;
        }

        if (!bFirstAddr)
            os << ", ";
        os << boost::format("%08lx") % (*i).second;
        bFirstAddr= false;
    }
    if (!bFirstAddr)
        os << "] ";
    os << "}";

    return os;
}

