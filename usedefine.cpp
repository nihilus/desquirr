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
// $Id: usedefine.cpp,v 1.3 2007/01/30 09:49:50 wjhengeveld Exp $
#include "usedefine.hpp"
#include "node.hpp"
#include "idapro.hpp"
#include "instruction.hpp"
#include "expression.hpp"

/* Set registers {{{ */
class SetRegistersVisitor : public ExpressionVisitor
{
	public:
		SetRegistersVisitor(BoolArray& registers)
			: mRegisters(registers)
		{
			// Do not clear registers!
		}
		
		virtual void Visit(Register& expression)
		{
			mRegisters.Set( expression.SimpleIndex() );
		}

		virtual void Visit(BinaryExpression&)  {}
		virtual void Visit(CallExpression& expression)   {}
 		virtual void Visit(Dummy&)             {}
		virtual void Visit(GlobalVariable&)            {}
		virtual void Visit(NumericLiteral&)    {}
		virtual void Visit(StackVariable&)     {}
		virtual void Visit(StringLiteral&)     {}
		virtual void Visit(TernaryExpression&) {}
		virtual void Visit(UnaryExpression&)   {}
	
	private:
		BoolArray& mRegisters;
};

static void SetRegisters(Expression_ptr e, BoolArray& registers)
{
	SetRegistersVisitor helper(registers);
	e->AcceptDepthFirst(helper);
}/*}}}*/

class UsesAndDefintionsVisitor : public InstructionVisitor
{
	private:
		void BeginInstruction(Instruction& instruction)
		{
			instruction.Definitions().Clear();
			instruction.Uses().Clear();
		}

		void EndInstruction(Instruction& instruction)
		{
			// Do not say we use something we define first
			mCurrentNode->Uses()        |= instruction.Uses() & ~mCurrentNode->Definitions();
			mCurrentNode->Definitions() |= instruction.Definitions();
		}
		
		void Use(Instruction& instruction, int index)
		{
			SetRegisters(instruction.Operand(index), instruction.Uses());
		}
		
		void Define(Instruction& instruction, int index)
		{
			SetRegisters(instruction.Operand(index), instruction.Definitions());
		}

		void UseOne(Instruction& instruction)
		{
			BeginInstruction(instruction);
			Use(instruction, 0);
			EndInstruction(instruction);
		}

	public:
		virtual void Visit(Assignment& instruction)
		{
			BeginInstruction(instruction);
			if (instruction.Operand(0)->IsType(Expression::UNARY_EXPRESSION))
			{
				// TODO: verify that the Operand is UnaryExpression("*", Register())
				// This is an indirect store, so we use the operand, not define it!
				Use(instruction, 0);
			}
			else
			{
				Define(instruction, 0);
			}

            if (instruction.Operand(1)->IsType(Expression::CALL)) {
                if (!static_cast<IdaPro&>(Frontend::Get()).ParametersOnStack()) {
                    CallExpression* call= static_cast<CallExpression*>(instruction.Operand(1).get());
                    if (call->ParameterCount()==CallExpression::UNKNOWN_PARAMETER_COUNT)
                        call->ParameterCount(4);
                    int i= 0;
                    while (i < 4 && i < call->ParameterCount()) {
                        call->AddParameter( Register::Create(i) );
                        i++;
                    }
                }
                Use(instruction, 1);
                Define(instruction, 1);
            }
            else {
                Use(instruction, 1);
            }

			EndInstruction(instruction);
		}

		virtual void Visit(ConditionalJump& instruction)
		{
			BeginInstruction(instruction);
			Use(instruction, 0);
			Use(instruction, 1);
			EndInstruction(instruction);
		}

		virtual void Visit(Pop& instruction)
		{
			BeginInstruction(instruction);
			Define(instruction, 0);
			EndInstruction(instruction);
		}

		virtual void Visit(Case& instruction)     {}
		virtual void Visit(Label& instruction)    {}
		virtual void Visit(LowLevel& instruction) {}

		virtual void Visit(Jump& instruction)   { UseOne(instruction); }
		virtual void Visit(Push& instruction)   { UseOne(instruction); }
		virtual void Visit(Return& instruction) { UseOne(instruction); }
		virtual void Visit(Switch& instruction) { UseOne(instruction); }
		virtual void Visit(Throw& instruction)  { UseOne(instruction); }

		virtual void NodeBegin(Node_ptr node)
		{
			mCurrentNode = node;
		}

	private:
		Node_ptr mCurrentNode;
};

void UpdateUsesAndDefinitions(Node_list& nodes)
{
	UsesAndDefintionsVisitor visitor;
	Accept(nodes, visitor);
}

