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
// $Id: ida-x86.hpp,v 1.2 2007/01/30 09:48:59 wjhengeveld Exp $
#ifndef _IDA_X86_HPP
#define _IDA_X86_HPP

#include "desquirr.hpp"
#include "idapro.hpp"
#include "x86.hpp"

class IdaX86 : public IdaPro
{
	public:
		IdaX86()
			: mIs32Bit(false)
		{
		}

		virtual std::string RegisterName(RegisterIndex index) const;
		virtual void FillList(func_t* function, Instruction_list& instructions);
		virtual void DumpInsn(insn_t& insn);
        virtual bool ParametersOnStack() { return true; }

		/** Look for Borland C++ throw instruction */
		static void TryBorlandThrow(DataFlowAnalysis* analysis, 
				Assignment* assignment);

	private:
		bool mIs32Bit;
};


#endif
