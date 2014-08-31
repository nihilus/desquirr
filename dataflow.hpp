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
// $Id: dataflow.hpp,v 1.3 2005/10/15 23:54:51 wjhengeveld Exp $
#ifndef _DATAFLOW_HPP
#define _DATAFLOW_HPP

#include "desquirr.hpp"
#include "analysis.hpp"

class DataFlowAnalysis : public Analysis/*{{{*/
{
	public:
		DataFlowAnalysis(Node_list& nodes)
			: mNodeList(nodes)
		{}
		
		/**
		 * Analyze a list of nodes
		 */
		void AnalyzeNodeList()/*{{{*/
		{
			for (Node_list::iterator n = mNodeList.begin();
					n != mNodeList.end();
					n++)
			{
				Node(*n);
				AnalyzeNode();
			}
		}/*}}}*/

		void CollectParameters(CallExpression* call);
	
	private:
		/**
		 * Analyze an individual node (in mNode)
		 */
		void AnalyzeNode()/*{{{*/
		{
			AnalyzeInstructionList();
		}/*}}}*/

		virtual AnalysisResult OnInstruction()/*{{{*/
		{
//			message("%p\n", Instr()->Address());
			
			if (INSTRUCTION_REMOVED == RemoveUnusedDefinition())
				return INSTRUCTION_REMOVED; 

			GetFunctionParametersFromStack();
			return CONTINUE;
		}/*}}}*/
		
		/**
		 * Handle an ASSIGNMENT instruction
		 */
		virtual void OnAssignment(Assignment* assignment);

		/**
		 * Handle a PUSH instruction
		 */
		virtual void OnPush(Push*)/*{{{*/
		{
			Stack().push( Iterator() );
		}/*}}}*/

		/**
		 * Handle a POP instruction
		 */
		virtual void OnPop(Pop*)/*{{{*/
		{
			if (Stack().empty())
			{
				message("%p Error! Can't POP from empty stack!\n", 
						Instr()->Address());
				return;
			}		

			//TryConvertPushPopToAssignment();

			Stack().pop();
		}/*}}}*/

		/** 
		 * Remove unused definitions from instruction
		 *
		 * Returns true if the whole instruction was removed!
		 */		
		bool RemoveUnusedDefinition();
		
		/** Get function parameters */
		void GetFunctionParametersFromStack();

		/** Try to convert a push-pop pair to an assignment */
		void TryConvertPushPopToAssignment();

		/** Find iterator for instruction at a certain address */
		Instruction_list::iterator FindInstructionAtAddress(
				Instruction_list::iterator item, Addr address);

		/** Replace uses of a register with the definition of the register */
		AnalysisResult ReplaceUseWithDefinition(Assignment* assignment);
		AnalysisResult ReplaceUseWithDefinition2(Assignment* assignment);
		
		//AnalysisResult TryIncDec(Assignment* assignment);

		/** Get instruction iterator stack */
		Instruction_list_iterator_stack& Stack() { return mStack; }

		/** Get node */
		Node_list& NodeList() { return mNodeList; }

		/** Get node */
		Node_ptr Node() { return mNode; }

		/** Set node */
		void Node(Node_ptr node)
		{
			mNode = node;
			Instructions(&mNode->Instructions());
		}

	private:
		Node_list& mNodeList;
		Node_ptr mNode;
		Instruction_list_iterator_stack mStack;
	
};/*}}}*/

#endif // _DATAFLOW_HPP

