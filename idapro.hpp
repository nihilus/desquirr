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
// $Id: idapro.hpp,v 1.6 2007/01/30 09:49:20 wjhengeveld Exp $
#ifndef _IDAPRO_HPP
#define _IDAPRO_HPP

#include "desquirr.hpp"
#include "frontend.hpp"

#include <string>
#include <kernwin.hpp>

class DataFlowAnalysis;
class Assignment;
class CallExpression;
class func_t;
class insn_t;
class op_t;

class IdaPro : public Frontend
{
	public:
		IdaPro()
		{
		}
		
		virtual int vmsg(const char *format, va_list va);
		virtual Addr AddressFromName(const char *name, 
				Addr referer = INVALID_ADDR);
		
		virtual void FillList(func_t* function, Instruction_list& instructions) = 0;
		void DumpInsn(Addr address);
        virtual bool ParametersOnStack() = 0;
		virtual void DumpInsn(insn_t& insn) = 0;
		static void LoadCallTypeInformation(CallExpression* call);

	protected:
		const char* GetOptypeString(op_t& op);
};

extern std::string GetStackVariableName(ea_t ea, int operand, int *pIndex);
extern Expression_ptr CreateStackVariable(insn_t &insn, int operand);

// used in expression.cpp GlobalVariable::CreateFrom
extern Expression_ptr CreateGlobalVariable(const insn_t &insn, int operand);
extern Expression_ptr CreateVariable(const insn_t &insn, int operand);
// used in ida-*.cpp CreateLabel / MakeLowLevelList
extern std::string GetLocalCodeLabel(ea_t ea, int *pIndex);
extern Expression_ptr CreateLocalCodeReference(ea_t ea);
extern Instruction_ptr CreateLocalCodeLabel(ea_t ea);
extern Expression_ptr CreateGlobalCodeLabel(ea_t ea);


#endif

