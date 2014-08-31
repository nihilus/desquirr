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
// $Id: instruction.hpp,v 1.9 2007/01/30 09:49:30 wjhengeveld Exp $
#ifndef _INSTRUCTION_HPP
#define _INSTRUCTION_HPP
/*
 *
Instruction   ... ea
    LowLevel  ... insn_t
    Label     ... name
    Case      ... case_value
    Throw     ... exception_expr, datatype
    UnaryInstruction  ... operand
        Push              ... operand
        Pop               ... operand
        Jump              ... target=opnd
        Return            ... returnvalue=opnd
        Switch            ... switchvalue=opnd, ???
---     Call              ... target=opnd
    BinaryInstruction  ... first, second
        ConditionalJump   ... cond=first, target=second
        Assignment        ... dest=first, src=second
 */
#include <sstream>
#include "desquirr.hpp"

#include "kernwin.hpp"
// Local includes

#include "expression.hpp"

class Expression;

typedef std::list<Expression*> ExpressionList;

std::ostream& operator<< (std::ostream& os, const RegisterToAddress_map& vs);

//typedef std::list<op_t> OperandList;

/**
 * For Defined and Used 
 */
class BoolArray/*{{{*/
{
	protected:
		typedef unsigned long BITFIELD;

		BoolArray(BITFIELD bitfield)
			: mBitfield(bitfield)
		{}
		
	public:
		enum
		{
			SIZE = 22   // XXX: the size is just a nice number
		};
		
		BoolArray()
		{
			Clear();
		}

		BoolArray(const BoolArray& other)
			: mBitfield(other.mBitfield)
		{
		}


		BoolArray operator ~ () const
		{
			return BoolArray(~mBitfield);
		}

		bool operator != (const BoolArray& other) const
		{
			return other.mBitfield != mBitfield;
		}

		void operator |= (const BoolArray& other) 
		{
			mBitfield |= other.mBitfield;
		}

		BoolArray operator | (const BoolArray& other) const
		{
			return BoolArray(mBitfield | other.mBitfield);
		}

		BoolArray operator & (const BoolArray& other) const
		{
			return BoolArray(mBitfield & other.mBitfield);
		}

		bool Get(int i) const
		{ 
			if (i >= 0 && i < SIZE) 
				return 0 != (mBitfield & POWER_OF_2[i]);
			else
				return false;
		}				

		void Set(int i) 
		{ 
			if (i >= 0 && i < SIZE)
				mBitfield |= POWER_OF_2[i];
		}

		void Clear(int i) 
		{ 
			mBitfield &= ~POWER_OF_2[i]; 
		}

		void Clear()
		{
			mBitfield = 0;
		}
			
		void Or(BoolArray& other)
		{
			mBitfield |= other.mBitfield;
		}

		int CountSet() const
		{
			int count = 0;
			for (int i = 0; i < SIZE; i++)
				if (mBitfield & POWER_OF_2[i])
					count++;
			return count;
		}
        friend std::ostream& operator<< (std::ostream& os, const BoolArray& ba)
		{
			bool first = true;
			os << '{';
			for (int i = 0; i < SIZE; i++)
			{
				if (ba.Get(i))
				{
					if (first)
						first = false;
					else
						os << ", ";

					os << Register::Name(i);
				}
			}
			os << '}';
            return os;
		}
	private:
		BITFIELD mBitfield;

		static const int POWER_OF_2[SIZE];
};/*}}}*/

class Assignment;
class Case;
class ConditionalJump;
class Jump;
class Label;
class LowLevel;
class Push;
class Pop;
class Return;
class Switch;
class Throw;

/**
 * Abstract base class for Instruction visitors
 */
class InstructionVisitor
{
	public:
        virtual ~InstructionVisitor() {}

		virtual void Visit(Assignment&)      = 0;
		virtual void Visit(Case&)            = 0;
		virtual void Visit(ConditionalJump&) = 0;
		virtual void Visit(Jump&)            = 0;
		virtual void Visit(Label&)           = 0;
		virtual void Visit(LowLevel&)        = 0;
		virtual void Visit(Push&)            = 0;
		virtual void Visit(Pop&)             = 0;
		virtual void Visit(Return&)          = 0;
		virtual void Visit(Switch&)          = 0;
		virtual void Visit(Throw&)           = 0;

		// Helper functions when accepting node lists
		virtual void NodeBegin(Node_ptr) {}
		virtual void NodeEnd() {}
};

void Accept(Node_list& nodes, InstructionVisitor& visitor);
void Accept(Instruction_list& instructions, InstructionVisitor& visitor);


/**
 * an instruction
 */
class Instruction/*{{{*/
{
	public:
		enum InstructionType
		{
			ASSIGNMENT,
			CALL,
			CASE,
			CONDITIONAL_JUMP,
			JUMP,
			LABEL,
			LOW_LEVEL,
			PUSH,
			POP,
			RETURN,
			SWITCH,
			THROW,
			TO_BE_DELETED
		};

		enum OperandTypeValue
		{
			INVALID,
			DEFINITION,
			USE,
			USE_AND_DEFINITION
		};
		
		virtual ~Instruction()
		{}

#if 1
		virtual int OperandCount()
		{ 
			// Default implementation
			return 0; 
		}
		
		virtual Expression_ptr Operand(int index)
		{
			// Default implementation
			Expression_ptr result;
			msg("ERROR: default implementation for Instruction::Operand called\n");
			return result;
		}

		virtual void Operand(int index, Expression_ptr e)
		{
			// Default implementation
		}

		virtual OperandTypeValue OperandType(int index)
		{
			return INVALID;
		}
#endif
	
		virtual Addr Address() const { return mAddress; }
		virtual InstructionType Type() const { return mType; }
		
		virtual bool IsType(InstructionType type)
		{
			return Type() == type;
		}

		virtual void Accept(InstructionVisitor& visitor) = 0;

		/**
		 * Return true if the whole instruction can be removed
		 */
		virtual bool RemoveDefinition(unsigned short reg)
		{
			// Do nothing by default
			return false;
		}
		
		BoolArray& Definitions()      { return mDefinitions; }
		BoolArray& Uses()             { return mUses; }
		BoolArray& LastDefinitions()  { return mLastDefinitions; }
		BoolArray& FlagDefinitions()  { return mFlagDefinitions; }

		RegisterToAddress_map& DuChain() { return mDuChain; }

		void AddToDuChain(unsigned short reg, Addr address)
		{
			mDuChain.insert(
					RegisterToAddress_pair(reg, address)
					);
		}

		bool DefinitionHasNoUses(unsigned short reg)
		{
			return mDuChain.count(reg) == 0;
		}

		void SetLastDefinition(unsigned short reg)
		{
			mLastDefinitions.Set(reg);
		}
		
		bool IsLastDefinition(unsigned short reg)
		{
			return mLastDefinitions.Get(reg);
		}

		bool MarkForDeletion()/*{{{*/
		{
			if (TO_BE_DELETED == mType)
			{
				return false;
			}
			else
			{			
				mType = TO_BE_DELETED;
				return true;
			}
		}/*}}}*/

		static void FindDefintionUseChains(Instruction_list& instructions);
        static void DumpInstructionList(Instruction_list& insns);

        friend std::ostream& operator<< (std::ostream& os, Instruction& insn)
        {
            insn.print(os);
            return os;
        }

        virtual void print(std::ostream& os)
        {
            os << boost::format("   insn %08lx")
                    % Address();
            os << " use=" << Uses();
            os << " def=" << Definitions();
            os << " last=" << LastDefinitions();
            os << " flag=" << FlagDefinitions();
            os << " chain=" << DuChain();
        }
	protected:
		Instruction(InstructionType type, Addr ea)
			: mType(type), mAddress(ea)
		{}
		
	private:
		InstructionType mType;
		Addr mAddress;
		BoolArray mDefinitions;
		BoolArray mUses;
		BoolArray mLastDefinitions;
		BoolArray mFlagDefinitions;
		RegisterToAddress_map mDuChain;
};/*}}}*/

/*
 * No-operand instructions
 */

class Label : public Instruction/*{{{*/
{
	public:
		Label(Addr ea, const char* name)
			: Instruction(LABEL, ea), mName(name)
		{}
        virtual void print(std::ostream& os)
        {
            Instruction::print(os);
            os << boost::format("LABEL %s\n")
                    % Name();
        }

		const std::string& Name() const { return mName; }

		virtual void Accept(InstructionVisitor& visitor)
		{
			visitor.Visit(*this);
		}
	private:
		std::string mName;
};/*}}}*/

/**
 * Abstract base class for single-operand instructions
 */
class UnaryInstruction : public Instruction/*{{{*/
{
	public:
		void Operand(Expression_ptr operand) { mOperand = operand; }
		Expression_ptr Operand() { return mOperand; }

#if 1
		virtual int OperandCount()
		{ 
			return 1; 
		}
		
		virtual Expression_ptr Operand(int index)
		{
			Expression_ptr result;
			if (0 == index)
				result = mOperand;
			else
				msg("ERROR: UnaryInstruction::Operand(%d) -> NULL\n", index);
			return result;
		}

		virtual void Operand(int index, Expression_ptr e)
		{
			if (0 == index)
				mOperand = e;
			else
				msg("ERROR: UnaryInstruction(%d, %08lx)\n", index, e.get());
		}
#endif
	
	protected:
		UnaryInstruction(InstructionType type, Addr ea, Expression_ptr operand)
			: Instruction(type, ea), mOperand(operand)
		{}

	private:
		Expression_ptr mOperand;
};/*}}}*/

/**
 * Abstract base class for double-operand instructions
 */
class BinaryInstruction : public Instruction/*{{{*/
{
	public:
		void First(Expression_ptr first) { mFirst = first; }
		Expression_ptr First() { return mFirst; }

		void Second(Expression_ptr second) { mSecond = second; }
		Expression_ptr Second() { return mSecond; }

#if 1
		virtual int OperandCount()
		{ 
			return 2; 
		}
		
		virtual Expression_ptr Operand(int index)
		{
			Expression_ptr result;
			if (0 == index)
				result = mFirst;
			else if (1 == index)
				result = mSecond;
			else
				msg("ERROR: BinaryInstruction::Operand(%d) -> NULL\n", index);
			return result;
		}

		virtual void Operand(int index, Expression_ptr e)
		{
			if (0 == index)
				mFirst = e;
			else if (1 == index)
				mSecond = e;
			else
				msg("ERROR: BinaryInstruction(%d, %08lx)\n", index, e.get());
		}
#endif
	
	protected:
		BinaryInstruction(InstructionType type, Addr ea, 
				Expression_ptr first, Expression_ptr second)
			: Instruction(type, ea), mFirst(first), mSecond(second)
		{}

	private:
		Expression_ptr mFirst;
		Expression_ptr mSecond;
};/*}}}*/

/*
 * Single-operand instructions
 */

class Push : public UnaryInstruction/*{{{*/
{
	public:
		Push(Addr ea, Expression_ptr operand)
			: UnaryInstruction(PUSH, ea, operand)
		{}
        virtual void print(std::ostream& os)
        {
            Instruction::print(os);
            os << "PUSH " << *Operand(0) << "\n";
        }

		virtual void Accept(InstructionVisitor& visitor)
		{
			visitor.Visit(*this);
		}

		virtual OperandTypeValue OperandType(int index)
		{
			return USE;
		}
};/*}}}*/

class Pop : public UnaryInstruction/*{{{*/
{
	public:
		Pop(Addr ea, Expression_ptr operand)
			: UnaryInstruction(POP, ea, operand)
		{}
        virtual void print(std::ostream& os)
        {
            Instruction::print(os);
            os << "POP " << *Operand(0) << "\n";
        }

		virtual void Accept(InstructionVisitor& visitor)
		{
			visitor.Visit(*this);
		}
		
		virtual OperandTypeValue OperandType(int index)
		{
			return DEFINITION;
		}
		
		virtual bool RemoveDefinition(unsigned short reg)
		{
			if (!Operand().get())
			{
				message("%p Error: no operand!\n", Address());
				return false;
			}
			
			if (!Operand()->IsType(Expression::REGISTER))
			{
				message("Error: trying to remove non-register defintion in POP\n");
				return false;
			}

			Register* expression = static_cast<Register*>(Operand().get());
			
			if (reg != expression->Index())
			{
				message("Error: trying to remove a non-existing defintion in POP\n");
				return false;
			}

			Operand( Dummy::Create() );

			Definitions().Clear(reg);

			return false;
		}
};/*}}}*/

class Jump : public UnaryInstruction/*{{{*/
{
	public:
		Jump(Addr ea, Expression_ptr destination)
			: UnaryInstruction(JUMP, ea, destination)
		{}
        virtual void print(std::ostream& os)
        {
            Instruction::print(os);
            os << "JUMP " << *Operand(0) << "\n";
        }

		virtual void Accept(InstructionVisitor& visitor)
		{
			visitor.Visit(*this);
		}

		virtual OperandTypeValue OperandType(int index)
		{
			return USE;
		}
};/*}}}*/

class Return : public UnaryInstruction/*{{{*/
{
	public:
		Return(Addr ea, Expression_ptr value)
			: UnaryInstruction(RETURN, ea, value)
		{}
        virtual void print(std::ostream& os)
        {
            Instruction::print(os);
            os << "RETURN " << *Operand(0) << "\n";
        }

		virtual void Accept(InstructionVisitor& visitor)
		{
			visitor.Visit(*this);
		}

		virtual OperandTypeValue OperandType(int index)
		{
			return USE;
		}

};/*}}}*/

/*
 * Double-operand instructions
 */

class ConditionalJump : public BinaryInstruction/*{{{*/
{
	public:
		ConditionalJump(Addr ea, 
				Expression_ptr condition, Expression_ptr destination)
			: BinaryInstruction(CONDITIONAL_JUMP, ea, condition, destination)
		{}
        virtual void print(std::ostream& os)
        {
            Instruction::print(os);
            os << "CONDITIONAL (" << *Operand(0) << ")  goto " << *Operand(1) << "\n";
        }

		virtual void Accept(InstructionVisitor& visitor)
		{
			visitor.Visit(*this);
		}

		virtual OperandTypeValue OperandType(int index)
		{
			return USE;
		}

};/*}}}*/

class Assignment : public BinaryInstruction/*{{{*/
{
	public:
		Assignment(Addr ea, Expression_ptr destination, Expression_ptr source)
			: BinaryInstruction(ASSIGNMENT, ea, destination, source)
		{}
        virtual void print(std::ostream& os)
        {
            Instruction::print(os);
            os << "ASSIGN " << *Operand(0) << " := " << *Operand(1) << "\n";
        }

		bool IsCall()
		{
			// TODO: make proper implementation
			return Second()->IsType(Expression::CALL);
		}

		virtual void Accept(InstructionVisitor& visitor)
		{
			visitor.Visit(*this);
		}

		virtual OperandTypeValue OperandType(int index)
		{
			if (0 == index)
			{
				if (Operand(0)->IsType(Expression::UNARY_EXPRESSION))
				{
					// TODO: verify that the Operand is UnaryExpression("*", Register())
					// This is an indirect store, so we use the operand, not define it!
					return USE;
				}
				
				return DEFINITION;
			}
			else
				return USE;
		}

		virtual bool RemoveDefinition(unsigned short reg)
		{
			if (!First()->IsType(Expression::REGISTER))
			{
				message("%p Error: trying to remove non-register defintion in assignment\n",
						Address());
				return false;
			}

			Register* expression = static_cast<Register*>(First().get());
			
			if (reg != expression->Index())
			{
				message("%p Error: trying to remove a non-existing defintion: %d/%d\n",Address(),reg,expression->Index());
				return false;
			}

			// Replace defintion with dummy instruction
			First( Dummy::Create() );
			Definitions().Clear(reg);

			// TODO: if the second operand does not contain a CALL expression we can 
			// return true here
			return !IsCall();
		}
};/*}}}*/


/*
 * Switch/case instructions
 */

class Switch : public UnaryInstruction/*{{{*/
{
	public:
		Switch(Addr ea, Expression_ptr value/*, switch_info_t& si*/)
			: UnaryInstruction(SWITCH, ea, value)//, mSwitchInfo(si)
		{}
        virtual void print(std::ostream& os)
        {
            Instruction::print(os);
            os << "SWITCH " << *Operand(0) << "\n";
        }

		virtual void Accept(InstructionVisitor& visitor)
		{
			visitor.Visit(*this);
		}

		virtual OperandTypeValue OperandType(int index)
		{
			return USE;
		}

	private:
		//switch_info_t mSwitchInfo;	
};/*}}}*/


class Case : public Instruction/*{{{*/
{
	public:
		Case(Addr ea, unsigned int value)
			: Instruction(CASE, ea), mValue(value)
		{}
        virtual void print(std::ostream& os)
        {
            Instruction::print(os);
            os << boost::format("CASE %08lx\n") % Value();
        }

		unsigned int Value() { return mValue; }
		
		virtual void Accept(InstructionVisitor& visitor)
		{
			visitor.Visit(*this);
		}

	private:
		unsigned int mValue;
};/*}}}*/

/**
 * A throw instruction can have either zero or one parameters
 */
class Throw : public Instruction/*{{{*/
{
	public:
		Throw(Addr ea, Expression_ptr exception, const std::string& dataType)
			: Instruction(THROW, ea), mException(exception), mDataType(dataType)
		{}
        virtual void print(std::ostream& os)
        {
            Instruction::print(os);
            os << "THROW " << mDataType << " " << *mException << "\n";
        }

		Throw(Addr ea)
			: Instruction(THROW, ea)
		{}

		virtual void Accept(InstructionVisitor& visitor)
		{
			visitor.Visit(*this);
		}

		virtual int OperandCount()
		{ 
			return IsRethrow() ? 0 : 1; 
		}
		
		virtual Expression_ptr Operand(int index)
		{
			Expression_ptr result;
			if (0 == index)
				result = mException;
			else
				msg("ERROR: Throw(%d) -> NULL\n", index);
			return result;
		}

		virtual void Operand(int index, Expression_ptr e)
		{
			if (0 == index)
				mException = e;
			else
				msg("ERROR: Throw(%d, %08lx)\n", index, e.get());
		}

		bool IsRethrow()
		{
			return NULL == mException.get();
		}

		Expression_ptr Exception()
		{
			return mException;
		}
		
		std::string DataType() { return mDataType; }

	private:
		Expression_ptr mException;
		std::string mDataType;
};/*}}}*/


class ErasePool/*{{{*/
{
	private:
		typedef std::list<Instruction_list::iterator> IteratorList;

		IteratorList mIterators;
		Instruction_list& mInstructions;

		struct EraseHelper
		{
			EraseHelper(Instruction_list& instructions)
				: mInstructions(instructions)
			{}
		
			Instruction_list& mInstructions;
			
			void operator () (Instruction_list::iterator item)
			{
				mInstructions.erase(item);
			}
		};
			
	public:
		ErasePool(Instruction_list& instructions)
			: mInstructions(instructions)
		{}
			
		~ErasePool()
		{
			for_each(mIterators.begin(), mIterators.end(), EraseHelper(mInstructions));
		}

		void Erase(Instruction_list::iterator item)
		{
			if ((**item).MarkForDeletion())
			{
				mIterators.push_back(item);
			}
		}
};/*}}}*/

#endif // _INSTRUCTION_HPP

