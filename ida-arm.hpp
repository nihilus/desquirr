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
// $Id: ida-arm.hpp,v 1.4 2007/01/30 09:48:35 wjhengeveld Exp $
#ifndef _IDA_ARM_HPP
#define _IDA_ARM_HPP

#include "desquirr.hpp"
#include "idapro.hpp"

// from arm.hpp
class IdaArm : public IdaPro
{
	public:
		virtual std::string RegisterName(RegisterIndex index) const;
		static const char* const ConditionOp(int condition);
		virtual void FillList(func_t* function, Instruction_list& instructions);
		virtual void DumpInsn(insn_t& insn);
        virtual bool ParametersOnStack() { return false; }

    enum ArmRegNo
    {
     R0, R1,  R2,  R3,  R4,  R5,  R6,  R7,
     R8, R9, R10, 
	 R11, FP=R11,
	 R12,
	 R13, SP=R13, 
	 R14, LR=R14,
	 R15, PC=R15,
     CPSR, NR_NORMAL_REGISTERS=CPSR,
	 CPSR_flg,
     SPSR, SPSR_flg,
     T, rVcs, rVds,            // virtual registers for code and data segments
     Racc0,                 // Intel xScale coprocessor accumulator
// extended for desquirr
     Cond,
     Temp
    };

};

#endif // _IDA_ARM_HPP

