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
// $Id: expression.hpp,v 1.9 2007/01/30 09:48:11 wjhengeveld Exp $
#ifndef _EXPRESSION_HPP
#define _EXPRESSION_HPP

#include <ida.hpp>

#include "desquirr.hpp"
/*
Expression    [ SubExpressionCount, SubExpression, GenerateCode, Accept, AcceptDepthFirst ]
    UnaryExpression   ... operation, operand
    BinaryExpression  ... first, operation, second
    TernaryExpression ... cond, thenval, elseval
    CallExpression    ... function
    NumericLiteral    ... value
    StringLiteral     ... value, type{unicode,ascii}
    Register          ... regnr
    Dummy
    Location          ... name, index
        GlobalVariable... address
        StackVariable

 */

#if 0
class TypeInformation/*{{{*/
{
	public:
		TypeInformation()
		{
			mDataType = (type_t*)qalloc(1);
			mDataType[0] = BT_UNK;
		}

		TypeInformation& operator=(TypeInformation& other)
		{
			Set(other.mDataType);	
			return *this;
		}

		bool operator==(TypeInformation& other)
		{
			return ::equal_types(::idati, mDataType, other.mDataType);
		}
		
		TypeInformation(type_t* dataType)
		{
			Set(dataType);
		}

		~TypeInformation()
		{
			Clear();
		}

		void Set(type_t* dataType) 
		{
			Clear();
			mDataType = ::typdup(dataType);
		}

		void Clear()
		{
			::qfree(mDataType);
			mDataType = NULL;
		}

		void Write(std::ostream& os)/*{{{*/
		{
			char buffer[MAXSTR]; 
			buffer[0] = '\0';
			::print_type_to_one_line(buffer, sizeof(buffer), ::idati, mDataType);

			os << buffer;
		}/*}}}*/

		bool IsVoid(int i = 0)
		{ return ::is_type_void  (mDataType[i]); }
		
		bool IsPointer(int i = 0)  
		{ return ::is_type_ptr   (mDataType[i]); }
		
		type_t BaseType(int i = 0) 
		{ return ::get_base_type (mDataType[i]); }
		
		type_t Flags(int i = 0)    
		{ return ::get_type_flags(mDataType[i]); }

		void Flags(type_t flags, int i = 0)    
		{ 
			mDataType[i] &= ~TYPE_FLAGS_MASK;
			mDataType[i] |= (flags & TYPE_FLAGS_MASK);
		}

		int Size() { return ::typlen(mDataType); }

		void Signness(type_t signness, int i = 0)/*{{{*/
		{
			switch (BaseType(i))
			{
				case BT_INT8:
				case BT_INT16:
				case BT_INT32:
				case BT_INT64:
				case BT_INT128:
				case BT_INT:
					Flags(signness, i);
					break;
			}
		}/*}}}*/

		type_t Signness(int i = 0)/*{{{*/
		{
			switch (BaseType(i))
			{
				case BT_INT8:
				case BT_INT16:
				case BT_INT32:
				case BT_INT64:
				case BT_INT128:
				case BT_INT:
					return Flags(i);

				default:
					return BTMT_UNKSIGN;
			}
		}/*}}}*/

		int PointerHeaderSize(int i = 0)/*{{{*/
		{
			if (IsPointer())
				return ::skip_ptr_type_header(mDataType + i) - (mDataType + i);
			else
				return 0;
		}/*}}}*/

		bool IsCharPointer()/*{{{*/
		{
			if (IsPointer())
			{
				int i = PointerHeaderSize();	
				return BaseType(i) == BT_INT8 && Flags(i) == BTMT_CHAR;
			}
			return false;
		}/*}}}*/

		void MakeCharPointer()
		{
			// TODO
		}

		void MakeBasicType(type_t type)/*{{{*/
		{
			Clear();
			mDataType = (type_t*)qalloc(2);
			mDataType[0] = type;
			mDataType[1] = 0;
		}/*}}}*/
		
		void MakeInt(type_t signness = BTMT_UNKSIGN)/*{{{*/
		{
			MakeBasicType(BT_INT | signness);
		}/*}}}*/
	
	private:
		type_t* mDataType;
};/*}}}*/
#endif

class BinaryExpression;
class CallExpression;
class Dummy;
class GlobalVariable;
class NumericLiteral;
class Register;
class StackVariable;
class StringLiteral;
class TernaryExpression;
class UnaryExpression;

class BinaryOpPrecedences: public std::map<std::string, int> {
	int lowest_;
    int highest_;
public:
    BinaryOpPrecedences()
		: lowest_(0), highest_(0)
    {
        int prec= lowest_;
        // ternary -1
        insert(value_type("||",   prec));
        insert(value_type("&&", ++prec));
        insert(value_type("|",  ++prec));
        insert(value_type("^",  ++prec));
        insert(value_type("&",  ++prec));

        insert(value_type("==", ++prec));
        insert(value_type("!=",   prec));

        insert(value_type(">=", ++prec));
        insert(value_type("<=",   prec));
        insert(value_type(">",    prec));
        insert(value_type("<",    prec));

        insert(value_type("<<", ++prec));
        insert(value_type(">>",   prec));

        insert(value_type("+",  ++prec));
        insert(value_type("-",    prec));

        insert(value_type("*",  ++prec));
        insert(value_type("/",    prec));
        insert(value_type("%",    prec));

        // unary ops

        highest_= prec;
    }
    int binaryprecedence(const std::string& op)
    {
        iterator i= find(op);
        if (i==end()) {
            message("ERROR: unknown binary operator used: %s\n", op.c_str());
            return -1;
        }
		return (*i).second;
    }
	int ternaryprecedence() {
		return lowest_-1;
	}
    int unaryprecedence() {
        return highest_+1;
    }
    int callprecedence() {
        return highest_+2;
    }
    int atomprecedence() {
        return highest_+2;
    }

};
extern BinaryOpPrecedences precedencemap;

/**
 * Abstract base class for expression visitors
 */
class ExpressionVisitor
{
	public:
		virtual void Visit(BinaryExpression&)  = 0;
		virtual void Visit(CallExpression&)              = 0;
		virtual void Visit(Dummy&)             = 0;
		virtual void Visit(GlobalVariable&)            = 0;
		virtual void Visit(NumericLiteral&)    = 0;
		virtual void Visit(Register&)          = 0;
		virtual void Visit(StackVariable&)     = 0;
		virtual void Visit(StringLiteral&)     = 0;
		virtual void Visit(TernaryExpression&) = 0;
		virtual void Visit(UnaryExpression&)   = 0;
};


/**
 * Abstract base class for all expressions
 */
class Expression/*{{{*/
{
	public:
		enum ExpressionType
		{
			BINARY_EXPRESSION,
			CALL,
			DUMMY,
			GLOBAL,
			NUMERIC_LITERAL,
			REGISTER,
			STACK_VARIABLE,
			STRING_LITERAL,
			TERNARY_EXPRESSION,
			UNARY_EXPRESSION
		};

		ExpressionType Type() const throw() { return mType; }
		bool IsType(ExpressionType type) const throw() { return Type() == type; }

        friend std::ostream& operator<< (std::ostream& os, Expression& e)
        {
            e.print(os);
            return os;
        }
        virtual void print(std::ostream& os)
        {
            os << "expr";
        }
//		TypeInformation& DataType()              { return mDataType; }

        virtual int Precedence() const = 0;
		virtual int SubExpressionCount()
		{
			return 0;
		}

		virtual Expression_ptr SubExpression(int index)
		{
			Expression_ptr e;
			return e;
		}

		virtual void SubExpression(int index, Expression_ptr e)
		{
		}

		virtual void GenerateCode(std::ostream& os)
		{
			os << "NYI";
		}

		virtual void Accept(ExpressionVisitor& visitor) = 0;

		/**
		 * Apply visitor to all sub-expressions with depth-first search
		 */
		virtual void AcceptDepthFirst(ExpressionVisitor& visitor)
		{
			for (int i = 0; i < SubExpressionCount(); i++)
				SubExpression(i)->AcceptDepthFirst(visitor);
			Accept(visitor);
		}

		static bool Equal(Expression_ptr a, Expression_ptr b);

	protected:
		Expression(ExpressionType type)
			: mType(type)
		{
		}
    public:
        virtual ~Expression() {}

	private:
		ExpressionType mType;
//		TypeInformation mDataType;
};/*}}}*/

class UnaryExpression : public Expression/*{{{*/
{
	public:
		UnaryExpression(const char* operation, Expression_ptr operand)
			: Expression(UNARY_EXPRESSION), mOperation(operation),
				mOperand(operand)
		{}
        virtual void print(std::ostream& os)
        {
            os << "uop_" << mOperation << "(" << *mOperand << ")";
        }

		virtual void Accept(ExpressionVisitor& visitor)
		{
			visitor.Visit(*this);
		}

        virtual int Precedence() const 
        {
            return precedencemap.unaryprecedence();
        }

		virtual int SubExpressionCount()
		{
			return 1;
		}

		virtual Expression_ptr SubExpression(int /*index*/)
		{
			return mOperand;
		}

		virtual void SubExpression(int /*index*/, Expression_ptr e)
		{
			mOperand = e;
		}

		void Operand(Expression_ptr operand) { mOperand = operand; }
		Expression_ptr Operand() { return mOperand; }

        const std::string& Operation() const { return mOperation; }

#if 0
		virtual void DepthFirst(ExpressionVisitor& visitor)
		{
			mOperand->DepthFirst(visitor);
			Expression::DepthFirst(visitor);
		}
#endif
		
		virtual void GenerateCode(std::ostream& os)
		{
            bool bUseParentheses= mOperand->Precedence() < Precedence();
			os << mOperation << ' ';
            if (bUseParentheses)
                os << '(';
			mOperand->GenerateCode(os);
            if (bUseParentheses)
                os << ')';
		}

	private:
		std::string mOperation;
		Expression_ptr mOperand;
};/*}}}*/

class BinaryExpression : public Expression/*{{{*/
{
	public:
		BinaryExpression(Expression_ptr first, const char* operation, 
				Expression_ptr second)
			: Expression(BINARY_EXPRESSION), mFirst(first), mOperation(operation),
				mSecond(second)
		{}
        virtual void print(std::ostream& os)
        {
            os << "bop_" << mOperation << "(" << *mFirst << ", " << *mSecond << ")";
        }

		virtual void Accept(ExpressionVisitor& visitor)
		{
			visitor.Visit(*this);
		}

        virtual int Precedence() const {
            return precedencemap.binaryprecedence(mOperation);
        }
           
		virtual int SubExpressionCount()
		{
			return 2;
		}

		virtual Expression_ptr SubExpression(int index)
		{
			if (0 == index)
				return mFirst;
			else
				return mSecond;
		}

		virtual void SubExpression(int index, Expression_ptr e)
		{
			if (0 == index)
				mFirst = e;
			else
				mSecond = e;
		}

		void First(Expression_ptr first) { mFirst = first; }
		Expression_ptr First() { return mFirst; }

		void Second(Expression_ptr second) { mSecond = second; }
		Expression_ptr Second() { return mSecond; }

		const std::string& Operation() const { return mOperation; }

#if 0
		virtual void DepthFirst(ExpressionVisitor& visitor)
		{
			mFirst->DepthFirst(visitor);
			mSecond->DepthFirst(visitor);
			Expression::DepthFirst(visitor);
		}
#endif
		
		virtual void GenerateCode(std::ostream& os)
		{
			bool bUseParentheses;
            bUseParentheses= mFirst->Precedence() < Precedence();
            if (bUseParentheses) os << '(';
			mFirst->GenerateCode(os);
            if (bUseParentheses) os << ')';

			os << ' ' << mOperation << ' ';

            bUseParentheses= mSecond->Precedence() < Precedence();
            if (bUseParentheses) os << '(';
			mSecond->GenerateCode(os);
            if (bUseParentheses) os << ')';
		}

	private:
		Expression_ptr mFirst;
		std::string mOperation;
		Expression_ptr mSecond;
};/*}}}*/

/**
 * Used for the question-mark-colon operator
 */
class TernaryExpression : public Expression/*{{{*/
{
	public:
		TernaryExpression(Expression_ptr a, Expression_ptr b, Expression_ptr c)
			: Expression(TERNARY_EXPRESSION) 
		{
			mOperands[0] = a;
			mOperands[1] = b;
			mOperands[2] = c;
		}
        virtual void print(std::ostream& os)
        {
            os << "ternaryop" << "(" << *mOperands[0] << ", " << *mOperands[1] << ", " << *mOperands[2] << ")";
        }

		virtual void Accept(ExpressionVisitor& visitor)
		{
			visitor.Visit(*this);
		}

        virtual int Precedence() const {
            return precedencemap.ternaryprecedence();
        }

		virtual int SubExpressionCount()
		{
			return 3;
		}

		virtual Expression_ptr SubExpression(int index)
		{
			return mOperands[index];
		}

		virtual void SubExpression(int index, Expression_ptr e)
		{
			mOperands[index] = e;
		}
		
		virtual void GenerateCode(std::ostream& os)
		{
			mOperands[0]->GenerateCode(os);
			os << " ? ";
			mOperands[1]->GenerateCode(os);
			os << " : ";
			mOperands[2]->GenerateCode(os);
		}

		static Expression_ptr Create(Expression_ptr a, Expression_ptr b, Expression_ptr c)
		{
			return Expression_ptr( new TernaryExpression(a, b, c) );
		}
		
	private:
		Expression_ptr mOperands[3];
};/*}}}*/

class CallExpression : public Expression/*{{{*/
{
	private:
	
		struct GenerateCodeHelper
		{
			GenerateCodeHelper(std::ostream& os)
				: mOs(os), mFirst(true)
			{}
			
			void operator() (Expression_ptr e)
			{
				if (mFirst)
					mFirst = false;
				else
					mOs << ", ";

				e->GenerateCode(mOs);
			}

			std::ostream& mOs;
			bool mFirst;
		};
	
	public:

		enum
		{
			UNKNOWN_PARAMETER_COUNT = -1,
			MAX_PARAMETERS = 15
		};
		
		CallExpression(Expression_ptr function);
		virtual ~CallExpression();

        virtual void print(std::ostream& os)
        {
            os << "CALLEXPR(";
            printvector(os, mSubExpressions);
            os << ")";
        }

		virtual void Accept(ExpressionVisitor& visitor)
		{
			visitor.Visit(*this);
		}

        virtual int Precedence() const {
            return precedencemap.callprecedence();
        }

		virtual int SubExpressionCount()
		{
			return mSubExpressions.size();
		}

		virtual Expression_ptr SubExpression(int index)
		{
			return mSubExpressions[index];
		}

		virtual void SubExpression(int index, Expression_ptr e)
		{
			mSubExpressions[index] = e;
		}

		int ParameterCount() const { return mParameterCount; }

		void ParameterCountFromStack(int parameterCount)
		{
			if (ParameterCount() == UNKNOWN_PARAMETER_COUNT)
			{
				ParameterCount(parameterCount);
				CallingConvention(CALLING_STDCALL);
			}
			else
			{
				message("Warning: Ignoring parameter count from stack (previous=%i, suggestion=%i)\n",
						ParameterCount(), parameterCount);
			}
		}

		void ParameterCountFromCall(int parameterCount)
		{
			if (ParameterCount() == UNKNOWN_PARAMETER_COUNT)
			{
				ParameterCount(parameterCount);
				CallingConvention(CALLING_CDECL);
			}
			else if (ParameterCount() == parameterCount)
			{
				// do nothing
			}
			else if (CALLING_ELLIPSIS == mCallingConvention)
			{
				if (ParameterCount() > parameterCount)
					message("Error: will not decrease number of parameters to ellipsis function (previous=%i, suggestion=%i)\n",
						ParameterCount(), parameterCount);
				else
					ParameterCount(parameterCount);
			}
			else
			{
				message("Ignoring parameter count from call to %p (previous=%i, suggestion=%i)\n",
						Address(), ParameterCount(), parameterCount);
			}
		}
	
#if 0
		void ParameterCount(int parameterCount) 
		{ 
			if (UNKNOWN_PARAMETER_COUNT != mParameterCount &&
					mParameterCount != parameterCount)
			{
				if (CALLING_ELLIPSIS == mCallingConvention)
					message("CALLING_ELLIPSIS: "); /*&&
							parameterCount < mParameterCount)
				else*/
				{
					message("Warning: changing call parameter count from %i to %i\n",
							mParameterCount, parameterCount);
				}
			}
			
			mParameterCount = parameterCount; 
			mSubExpressions.reserve(1+mParameterCount);
		}
#endif

		void AddParameter(Expression_ptr param)
		{
			if (mFinishedAddingParameters)
				message("Warning! Adding parameters but were supposed to be finished\n");
			if (mSubExpressions.size() > (unsigned int)mParameterCount)
				message("Warning! Adding more parameters than parameter count\n");
			mSubExpressions.push_back(param);
		}

		bool IsFinishedAddingParameters()
		{
			return mFinishedAddingParameters;
		}

		void SetFinishedAddingParameters()
		{
			mFinishedAddingParameters = true;
		}

		void SetDataTypes();

		Calling CallingConvention() const { return mCallingConvention; }
		void CallingConvention(Calling cm) { mCallingConvention = cm & CALLING_MASK; }

		bool IsCdecl() const
		{
			switch (mCallingConvention)
			{
				case CALLING_UNKNOWN:		/* possibly CDECL */
				case CALLING_CDECL:
				case CALLING_ELLIPSIS:
					return true;
	
				default:
					return false;
			}
		}

		/** special overloaded version */
		virtual void AcceptDepthFirst(ExpressionVisitor& visitor)
		{
			// First subexpression is function, but we want it to be examined last
			for (int i = 1; i < SubExpressionCount(); i++)
				SubExpression(i)->AcceptDepthFirst(visitor);
		  SubExpression(0)->AcceptDepthFirst(visitor);
			Accept(visitor);
		}

		virtual void GenerateCode(std::ostream& os)
		{
#if DUMP_DATA_TYPES
			os << '(';
			DataType().Write(os);
			os << ')';
#endif
			
			Function()->GenerateCode(os);
			os << '(';
			std::for_each(mSubExpressions.begin()+1, mSubExpressions.end(), 
					GenerateCodeHelper(os));
			os << ')';
		}

		Addr Address() { return mFunctionAddress; }

		void ParameterCount(int parameterCount)
		{
			mParameterCount = parameterCount; 
			mSubExpressions.reserve(1+mParameterCount);
		}

	private:
		Expression_ptr Function() { return mSubExpressions[0]; }
		Addr mFunctionAddress;
		int mParameterCount;
		Expression_vector mSubExpressions;
		/* CALLING_CDECL etc, from TYPEINF.HPP */
		Calling mCallingConvention;
		bool mFinishedAddingParameters;

		void LoadTypeInformation();
		void LoadFunctionInformation();
};/*}}}*/

class NumericLiteral : public Expression/*{{{*/
{
	public:
		NumericLiteral(unsigned long value)
			: Expression(NUMERIC_LITERAL), mValue(value)
		{
			//DataType().MakeInt();
		}
        virtual void print(std::ostream& os)
        {
            os << boost::format("NUMLITERAL:%08lx") % Value();
        }

		virtual void Accept(ExpressionVisitor& visitor)
		{
			visitor.Visit(*this);
		}

		unsigned long Value() { return mValue; }

		virtual void GenerateCode(std::ostream& os)
		{
#if DUMP_DATA_TYPES
			os << '(';
			DataType().Write(os);
			os << ')';
#endif
			
			if (mValue >= 0xfffffff0)
				os << (signed long)mValue;
			else
			{
				if (mValue < 0x10)
					os << boost::format("%d") % mValue;
				else
					os << boost::format("0x%x") % mValue;
			}
		}

		static Expression_ptr Create(unsigned long value)
		{
			return Expression_ptr(new NumericLiteral(value));
		}

        virtual int Precedence() const {
            return precedencemap.atomprecedence();
        }

	private:
		unsigned long mValue;
};/*}}}*/

class StringLiteral : public Expression/*{{{*/
{
	public:
		StringLiteral(const std::string& value, unsigned long type)
			: Expression(STRING_LITERAL), mValue(value), mStringType(type)
		{
			//DataType().MakeCharPointer();
		}
        virtual void print(std::ostream& os)
        {
            os << boost::format("STRINGLITERAL:%s:'%s'") 
                % (mStringType==STRING_UNICODE? "L":
                    mStringType==STRING_ULEN2? "2":
                    mStringType==STRING_ULEN4? "4":"")
                % mValue;
        }

		virtual void Accept(ExpressionVisitor& visitor)
		{
			visitor.Visit(*this);
		}

		virtual void GenerateCode(std::ostream& os)
		{
#if DUMP_DATA_TYPES
			os << '(';
			DataType().Write(os);
			os << ')';
#endif
				
			switch (mStringType)
			{
				case STRING_UNICODE:
				case STRING_ULEN2:
				case STRING_ULEN4:
					os << "L";
					break;
			}
			os << '"' << EscapeAsciiString(mValue) << '"';
		}

		static Expression_ptr CreateFrom(ea_t address);
		static std::string GetString(ea_t address, ulong type);

		static std::string EscapeAsciiString(const std::string& str);

        virtual int Precedence() const {
            return precedencemap.atomprecedence();
        }

	private:
		std::string mValue;
		unsigned long mStringType;
};/*}}}*/

class Register : public Expression/*{{{*/
{
	public:
		Register(RegisterIndex reg)
			: Expression(REGISTER), mRegister(reg)
		{
//			DataType().MakeInt();
		}
        virtual void print(std::ostream& os)
        {
            os << boost::format("REGISTER:%s") % Register::Name(Index());
        }

		virtual void Accept(ExpressionVisitor& visitor)
		{
			visitor.Visit(*this);
		}

		unsigned short Index() { return (unsigned short)mRegister; }

		unsigned short SimpleIndex()
		{
			// XXX: this is supposed to return AX for AL, etc
			return (unsigned short)(mRegister & 31);
		}

		virtual void GenerateCode(std::ostream& os)
		{
#if DUMP_DATA_TYPES
			os << '(';
			DataType().Write(os);
			os << ')';
#endif
	
			os << Name(mRegister);
		}

		static std::string Name(RegisterIndex index);

		static Expression_ptr Create(RegisterIndex reg)
		{
			return Expression_ptr(new Register(reg));
		}

		static unsigned short Index(Expression_ptr e)
		{
			if (e->IsType(REGISTER))
				return static_cast<Register*>(e.get())->Index();
			else
				return (unsigned short)-1;
		}

        virtual int Precedence() const {
            return precedencemap.atomprecedence();
        }


	private:
		RegisterIndex mRegister;
};/*}}}*/

/**
 * Abstract base class for GlobalVariable and StackVariable
 */
class Location : public Expression/*{{{*/
{
	public:
		Location(ExpressionType type, const std::string& name, int index=0)
			: Expression(type), mIndex(index), mName(name)
		{}
        virtual void print(std::ostream& os)
        {
            os << boost::format("LOCATION:%s") % mName;
            if (mIndex)
                os << boost::format("[%d]") % mIndex;
        }

		std::string Name() const throw() { return mName; }

		virtual void GenerateCode(std::ostream& os)
		{
#if DUMP_DATA_TYPES
			os << '(';
			DataType().Write(os);
			os << ')';
#endif
	
			os << mName;
			if (mIndex)
			{
				os << '[' << mIndex << ']';
			}
		}

	private:
		int mIndex;
		std::string mName;
};/*}}}*/

class GlobalVariable : public Location/*{{{*/
{
	public:
		GlobalVariable(const std::string& name, int index=0, Addr address=INVALID_ADDR)
			: Location(GLOBAL, name, index), mAddress(address)
		{
			//DataType().MakeInt();
		}
        virtual void print(std::ostream& os)
        {
            os << boost::format("GLOBAL:%s") % Name();
//            if (mIndex)
//                os << boost::format("[%d]") % mIndex;
        }

		virtual void Accept(ExpressionVisitor& visitor)
		{
			visitor.Visit(*this);
		}

		Addr Address();
	
        virtual int Precedence() const {
            return precedencemap.atomprecedence();
        }

		static Expression_ptr CreateFrom(ea_t ea, ea_t from = INVALID_ADDR);
		static std::string GetName(ea_t ea, ea_t from = INVALID_ADDR);

	private:
		Addr mAddress;
};/*}}}*/

class StackVariable : public Location/*{{{*/
{
	public:
		StackVariable(const std::string& name, int index=0)
			: Location(STACK_VARIABLE, name, index)
		{
			//DataType().MakeInt();
		}
        virtual void print(std::ostream& os)
        {
            os << boost::format("LOCAL:%s") % Name();
//            if (mIndex)
//                os << boost::format("[%d]") % mIndex;
        }

		virtual void Accept(ExpressionVisitor& visitor)
		{
			visitor.Visit(*this);
		}
        virtual int Precedence() const {
            return precedencemap.atomprecedence();
        }

};/*}}}*/

class Dummy : public Expression/*{{{*/
{
	public:
		Dummy()
			: Expression(DUMMY)
		{}
        virtual void print(std::ostream& os)
        {
            os << "DUMMY";
        }

		virtual void Accept(ExpressionVisitor& visitor)
		{
			visitor.Visit(*this);
		}

		virtual void GenerateCode(std::ostream& os)
		{
			// empty
		}

		static Expression_ptr Create()
		{
			return Expression_ptr(new Dummy());
		}
        virtual int Precedence() const {
            return precedencemap.atomprecedence();
        }

};/*}}}*/

#endif

