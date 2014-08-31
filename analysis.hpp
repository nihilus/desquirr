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
// $Id: analysis.hpp,v 1.3 2005/10/15 23:54:30 wjhengeveld Exp $
#ifndef _ANALYSIS_HPP
#define _ANALYSIS_HPP

#include "desquirr.hpp"
#include "node.hpp"

class Analysis/*{{{*/
{
	protected:
		Analysis()
			: mInstructions(NULL)
		{}

    public:
		virtual ~Analysis() {}

	public:
		enum AnalysisResult
		{
			CONTINUE,
			INSTRUCTION_REMOVED
		};
	
		/**
		 * Analyze an instruction list (call Instructions() to get it)
		 */
		void AnalyzeInstructionList()/*{{{*/
		{
			Instruction_list& list = Instructions();

			for (Instruction_list::iterator i = list.begin();
					i != list.end();
					i++)
			{
				Iterator(i);
				AnalyzeInstruction();
			}
		}/*}}}*/

		/**
		 * Analyze an individual instruction (call Instr() to get it)
		 */
		void AnalyzeInstruction()/*{{{*/
		{
			if (Instr()->Type() == Instruction::TO_BE_DELETED)
			{
				return;
			}
			
			if (INSTRUCTION_REMOVED == OnInstruction())
				return;
			
			switch (Instr()->Type())
			{
				case Instruction::ASSIGNMENT:
					OnAssignment( static_cast<Assignment*>(Instr().get()) );
					break;

				case Instruction::LOW_LEVEL:    // this calls the processor specific handling
					OnLowLevel( Instr().get() );
					break;

				case Instruction::POP:
					OnPop( static_cast<Pop*>(Instr().get()) );
					break;

				case Instruction::PUSH:
					OnPush( static_cast<Push*>(Instr().get()) );
					break;

				default:
					break;
			}
		}/*}}}*/

		/**
		 * Handle non-specific things for all instructions
		 *
		 * \return true to continue to specific instruction
		 */
		virtual AnalysisResult OnInstruction()
		{
			return CONTINUE;
		}
		
		/**
		 * Handle an Assignment instruction
		 */
		virtual void OnAssignment(Assignment* assignment)
		{ }

		/**
		 * Handle a Push instruction
		 */
		virtual void OnPush(Push* push)
		{ }

		/**
		 * Handle a Pop instruction
		 */
		virtual void OnPop(Pop* pop)
		{ }

		/**
		 * Handle a LowLevel instruction
		 */
		virtual void OnLowLevel(Instruction* lowLevel)
		{ }

		Instruction_list::iterator Insert(Instruction_ptr instruction)/*{{{*/
		{
			return Instructions().insert(Iterator(), instruction);
		}/*}}}*/
		
		Instruction_list::iterator Replace(Instruction_ptr instruction)/*{{{*/
		{
			Erase(Iterator());
			return Insert(instruction);
		}/*}}}*/
		
		Instruction_list::iterator Insert(Instruction* instruction)/*{{{*/
		{
			return Insert( Instruction_ptr(instruction) );
		}/*}}}*/

		Instruction_list::iterator Replace(Instruction* instruction)/*{{{*/
		{
			return Replace( Instruction_ptr(instruction) );
		}/*}}}*/

		void EraseInstructions(int count)/*{{{*/
		{
			for(Instruction_list::iterator item = Iterator();
					count > 0 && item != Instructions().end();
					item++)
			{
				Erase(item);
				count--;
			}
		}/*}}}*/

		/** Add an instruction iterator to erase pool */
		void Erase(Instruction_list::iterator i) { mErasePool->Erase(i); }

		/** Get instruction */
		Instruction_ptr Instr() { return *mIterator; }

		/** Set instruction list */
		void Instructions(Instruction_list* instructions)
		{
			mInstructions = instructions;
			if (instructions)
			{
				mErasePool.reset( new ErasePool(*instructions) );
			}
			else
			{
				mErasePool.reset();
			}
		}
		
		/** Get instruction list */
		Instruction_list& Instructions() { return *mInstructions; }

		/** Get instruction iterator */
		Instruction_list::iterator Iterator() { return mIterator; }

		/** Set instruction iterator */
		void Iterator(Instruction_list::iterator i) { mIterator = i; }

	private:
		Instruction_list* mInstructions;
		ErasePool_ptr mErasePool;
		Instruction_list::iterator mIterator;
};/*}}}*/



#endif

