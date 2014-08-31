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
// $Id: dataflow.cpp,v 1.6 2007/01/30 09:48:19 wjhengeveld Exp $
#include "idainternal.hpp"
#include "dataflow.hpp"
#include "node.hpp"
#include "idapro.hpp"
#include "ida-x86.hpp"

bool DataFlowAnalysis::RemoveUnusedDefinition()/*{{{*/
{
	BoolArray& def = Instr()->Definitions();

	for (int reg = 0; reg < BoolArray::SIZE; reg++)
	{
		// Is register i is defined here?
		if (def.Get(reg))
		{
			// Are there no uses of this definition?
			if (Instr()->DefinitionHasNoUses(reg) &&
					!(Instr()->IsLastDefinition(reg) && 
						Node()->InLiveOut(reg)))
			{
				if (Instr()->RemoveDefinition(reg))
				{
					// We can remove the whole instruction!
//					message("%p Wow! Removing instruction!\n", Instr()->Address());
					Erase(Iterator());
					return true;
				}
			}
		}		
	}
	return false;
}/*}}}*/

// ReplaceRegisterExpression {{{
class ReplaceRegisterExpressionHelper
{
	public:
		ReplaceRegisterExpressionHelper(
				unsigned short reg,
				Expression_ptr replacement)
			: mReplaceDone(false), mRegister(reg), mReplacement(replacement)
		{ }

		void Replace(Instruction_ptr instruction, int operand)
		{
			if (Replace(instruction->Operand(operand)))
			{
				instruction->Operand(operand, mReplacement);
				mReplaceDone = true;
			}
		}

		bool Replace(Expression_ptr parent)
		{
			if (parent->IsType(Expression::REGISTER) &&
					static_cast<Register*>(parent.get())->Index() == mRegister)
			{
				return true; /* tell caller to replace the parent! */
			}

			for (int i = 0; i < parent->SubExpressionCount(); i++)
			{
				if (Replace(parent->SubExpression(i)))
				{
					parent->SubExpression(i, mReplacement);
					mReplaceDone = true;
					return false;
				}
			}
			return false;
		}

		bool ReplaceDone() { return mReplaceDone; }

	private:
		bool mReplaceDone;
		unsigned short mRegister;
		Expression_ptr mReplacement;
};

bool ReplaceRegisterExpression(
		Instruction_ptr instruction,
		int operand,
		unsigned short reg,
		Expression_ptr replacement)
{
	ReplaceRegisterExpressionHelper helper(reg, replacement);
	helper.Replace(instruction, operand);
	return helper.ReplaceDone();
}/*}}}*/

class GetFunctionParametersFromStackHelper : public ExpressionVisitor/*{{{*/
{
	public:
		GetFunctionParametersFromStackHelper(DataFlowAnalysis* analysis)
			: mAnalysis(analysis)
		{}
	
		virtual void Visit(CallExpression& expression)
		{
			mAnalysis->CollectParameters(&expression);
		}

		virtual void Visit(BinaryExpression&)  {}
		virtual void Visit(Dummy&)             {}
		virtual void Visit(GlobalVariable&)            {}
		virtual void Visit(NumericLiteral&)    {}
		virtual void Visit(Register&)          {}
		virtual void Visit(StackVariable&)     {}
		virtual void Visit(StringLiteral&)     {}
		virtual void Visit(TernaryExpression&) {}
		virtual void Visit(UnaryExpression&)   {}
		
	private:
		DataFlowAnalysis* mAnalysis;
}; /*}}}*/

void DataFlowAnalysis::CollectParameters(CallExpression* call)/*{{{*/
{
	if (call->IsFinishedAddingParameters())
		return; // already collected parameters for this call 
	
	if (static_cast<IdaPro&>(Frontend::Get()).ParametersOnStack()) {
        int parameters_left = call->ParameterCount();

        if (CallExpression::UNKNOWN_PARAMETER_COUNT == parameters_left)
        {
            parameters_left = Stack().size();
            message("%p I guess this function call takes %i parameters.\n", 
                    Instr()->Address(), parameters_left);
            call->ParameterCountFromStack(parameters_left);
        }

        while (!Stack().empty() && parameters_left > 0)
        {
            Push* push = static_cast<Push*>(Stack().top()->get());
            call->AddParameter( push->Operand() );
            Erase(Stack().top());
            Stack().pop();
            parameters_left--;
        }

        call->SetFinishedAddingParameters();

        if (parameters_left != 0)
        {
            message("%p Unexpected number of parameters left: %i. Wanted %i parameters.\n", 
                    Instr()->Address(), parameters_left, call->ParameterCount());
        }
    }

#if 0
	call->SetDataTypes();
#endif
} /*}}}*/

void DataFlowAnalysis::GetFunctionParametersFromStack()/*{{{*/
{
	GetFunctionParametersFromStackHelper helper(this);
	
	for (int i = 0; i < Instr()->OperandCount(); i++)
	{
		Instr()->Operand(i)->AcceptDepthFirst(helper);
	}
}/*}}}*/

void DataFlowAnalysis::TryConvertPushPopToAssignment()/*{{{*/
{
	Instruction_list::iterator pop  = Iterator();
	Instruction_list::iterator push = Stack().top();

	if (Stack().size() == 0)
	{
		message("%p [TryConvertPushPopToAssignment] Empty stack\n", Instr()->Address());
		return;
	}

	if (Instructions().end() == pop)
	{
		message("%p [TryConvertPushPopToAssignment] Bad pop\n", Instr()->Address());
		return;
	}

	if (Instructions().end() == push)
	{
		message("%p [TryConvertPushPopToAssignment] Bad push\n", Instr()->Address());
		return;
	}
	
	//
	//  If there are no defintions of popped register between push and pop,
	//  we can make an assignment at the push
	//
	Expression_ptr popped = (**pop).Operand(0);

	// This should always be a register, but who knows?
	if (popped->IsType(Expression::REGISTER))
	{
		Expression_ptr pushed = (**push).Operand(0);

		unsigned short reg = static_cast<Register*>(pushed.get())->Index();
		Instruction_list::iterator i = push;

		for (i++; i != pop; i++)
		{
			if ( (**i).Definitions().Get(reg))
				break;
		}

		if (i == pop)
		{
			message("%p Replacing push/pop with assignment!\n", 
					(**push).Address());
			Instructions().insert(
					push,
					Instruction_ptr(new Assignment(
							(**push).Address(),
							popped,	
							pushed
							))
					);
			Erase(push);
			Erase(pop);
		}
	}
    else {
        msg("WARNING: popped expr is not a register: %d\n", popped->Type());
    }
}/*}}}*/

Instruction_list::iterator DataFlowAnalysis::FindInstructionAtAddress(/*{{{*/
		Instruction_list::iterator item, Addr address)
{
	for(item++; item != Instructions().end(); item++)
	{
		if ((**item).Address() == address)
			break;
	}
	return item;
}/*}}}*/

Analysis::AnalysisResult DataFlowAnalysis::ReplaceUseWithDefinition(/*{{{*/
		Assignment* assignment)
{
	RegisterToAddress_map& du_chain = assignment->DuChain();

	if (du_chain.size() != 1)
		return CONTINUE;

	unsigned short reg = du_chain.begin()->first;
//	message("%p du_chain.count(%i) = %i\n", assignment->Address(), reg, du_chain.count(reg));

	// Don't do this for the last defintion if it is in LiveOut
	if (assignment->IsLastDefinition(reg) && Node()->InLiveOut(reg))
		return CONTINUE;

#if 0
	pair<RegisterToAddress_map::const_iterator, RegisterToAddress_map::const_iterator> range = 
		du_chain.equal_range(reg);

	for (RegisterToAddress_map::const_iterator item = range.first;
			item != range.second;
			item++)
	{
		message("item->second = %p\n", item->second);
	}
#endif

	// Find end of DU-chain
	Instruction_list::iterator target_item = 
		FindInstructionAtAddress(Iterator(), du_chain.begin()->second);

	// Verify we found it
	if (Instructions().end() == target_item)
		return CONTINUE;

	// XXX: not for calls?
	if (assignment->IsCall())
	{
		// XXX: See if adjacent instructions
		Instruction_list::iterator tmp = Iterator();
		tmp++;
		if (tmp != target_item)
			return CONTINUE;
	}

	Instruction_ptr target = *target_item;
	bool replace_done = false;

	// assuming the register is only used once
	for (int i = 0; i < target->OperandCount(); i++)
	{
		if (target->OperandType(i) == Instruction::USE)
		{
			if (ReplaceRegisterExpression(target, i, reg, assignment->Second()))
			{
				replace_done = true;
				break;
			}
		}
	}

	if (replace_done)
	{
		target->Uses().Clear(reg);
		target->Uses() |= assignment->Uses();
		target->LastDefinitions() |= assignment->LastDefinitions();
		Erase(Iterator());
	}

	return CONTINUE;
}/*}}}*/

Analysis::AnalysisResult DataFlowAnalysis::ReplaceUseWithDefinition2(/*{{{*/
		Assignment* assignment)
{
	// Must be a register
	if (!assignment->First()->IsType(Expression::REGISTER))
		return CONTINUE;
	
	unsigned short reg = Register::Index(assignment->First());

	// Must be last definition and be in LiveOut
	if (!assignment->IsLastDefinition(reg) ||
			!Node()->InLiveOut(reg))
		return CONTINUE;

	// Must be a primitive type
	switch (assignment->Second()->Type())
	{
		case Expression::GLOBAL:
		case Expression::NUMERIC_LITERAL:
		case Expression::STACK_VARIABLE:
		case Expression::STRING_LITERAL:
			break;

		default:
			return CONTINUE;
	}

/*	message("%p In ReplaceUseWithDefinition2 and past the tests\n", 
			assignment->Address());*/

	// for each successor
	for (int i = 0; i < Node()->SuccessorCount(); i++)
	{
		Node_ptr successor = Node()->Successor(i);
		if (!successor->LiveIn().Get(reg))
			continue;
//		message("  sucessor->Address() = %p\n", successor->Address());
		if (successor->InLiveOut(reg))
		{
//			message("Can't handle substitution on more than the direct successors yet :-(\n");
			return CONTINUE;
		}
	
		for (Node_list::iterator n = mNodeList.begin();
				n != mNodeList.end();
				n++)
		{
			Node_ptr node = *n;

			if (Node() != node)
			{
				for (int i = 0; i < node->SuccessorCount(); i++)
				{
					if (node->Successor(i) == successor)
					{
//						message("    predecessor found @ %p\n", node->Address());
						if (node->InLiveOut(reg))
						{
//							message("      predecessor had register in LiveOut :-(\n");
							return CONTINUE;
						}
					}
				}
			}
		}
	}

	// for each successor again
	for (int i = 0; i < Node()->SuccessorCount(); i++)
	{
		Node_ptr successor = Node()->Successor(i);

		if (!successor->LiveIn().Get(reg))
			continue;
		
		// for each instruction in successor
		for (Instruction_list::iterator target_item = successor->Instructions().begin();
				target_item != successor->Instructions().end();
				target_item++)
		{
			Instruction_ptr target = *target_item;

#if 1
			bool replace_done = false;

			// assuming the register is only used once
			for (int i = 0; i < target->OperandCount(); i++)
			{
				if (target->OperandType(i) == Instruction::USE)
				{
					if (ReplaceRegisterExpression(target, i, reg, assignment->Second()))
					{
						replace_done = true;
						break;
					}
				}
			}

			if (replace_done)
			{
//				message("%p Replaced expression in this instruction\n", target->Address());

				target->Uses().Clear(reg);
				target->Uses() |= assignment->Uses();
				//target->LastDefinitions() |= assignment->LastDefinitions();
			}

			// Stop if the register was redefined by this instruction
			if (target->Definitions().Get(reg))
				break;
		}
			
		successor->LiveIn().Clear(reg);
	}
	
	Node()->LiveOut().Clear(reg);
//	Erase(Iterator());
#endif

	return CONTINUE;			
}/*}}}*/

void DataFlowAnalysis::OnAssignment(Assignment* assignment)/*{{{*/
{
#if 0
	if (Expression::Equal(assignment->First(), assignment->Second()))
	{
		message("%p Assign to self\n", Instr()->Address());
	}
#endif

	//ReplaceUseWithDefinition2(assignment);
	ReplaceUseWithDefinition(assignment);
	//TryIncDec(assignment);

	// Propagate data type
	//assignment->First()->DataType() = assignment->Second()->DataType();

	IdaX86::TryBorlandThrow(this, assignment);
}/*}}}*/


