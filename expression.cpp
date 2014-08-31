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
// $Id: expression.cpp,v 1.9 2007/01/30 09:47:53 wjhengeveld Exp $

//
// C++ headers
//
#include <sstream>

//
// IDA headers
//
#include <ida.hpp>
#include <idp.hpp>
#include <typeinf.hpp>
#include <funcs.hpp>
#include <struct.hpp>
#include <frame.hpp>

//
// Local headers
//
#include "desquirr.hpp"
#include "instruction.hpp"
#include "expression.hpp"
#include "frontend.hpp"
#include "idapro.hpp"

BinaryOpPrecedences precedencemap;

std::string Register::Name(RegisterIndex index)/*{{{*/
{
	return Frontend::Get().RegisterName(index);
}/*}}}*/

CallExpression::CallExpression(Expression_ptr function)/*{{{*/
	: Expression(CALL), mFunctionAddress(BADADDR),
		mParameterCount(UNKNOWN_PARAMETER_COUNT), 
		mCallingConvention(CM_CC_UNKNOWN),
		mFinishedAddingParameters(false)
{
//	memset(mReturnType,     0, sizeof(mReturnType));

	mSubExpressions.push_back(function);
	
	if (function->IsType(GLOBAL))
	{
		// Get address from name of function
		mFunctionAddress = static_cast<GlobalVariable*>(function.get())->Address();
	}

	LoadFunctionInformation();
	LoadTypeInformation();
}/*}}}*/

CallExpression::~CallExpression()/*{{{*/
{
}/*}}}*/

void CallExpression::LoadFunctionInformation()/*{{{*/
{
	if (BADADDR == mFunctionAddress)
		return;
	
	func_t* func = get_func(mFunctionAddress);
	if (func)
	{
		if (func->argsize > 0)
		{
//			msg("Function at %p purges %i bytes\n", mFunctionAddress, func->argsize);

			// XXX: this is for 32-bit code
			ParameterCount(func->argsize >> 2);
		}
	}
	else
	{
		ulong purge = get_ind_purged(mFunctionAddress);
		if (purge != (ulong)-1)
		{
//			msg("Function at %p purges %i bytes\n", mFunctionAddress, purge);
		
			// XXX: this is for 32-bit code
			ParameterCount(purge >> 2);
		}
	}
}/*}}}*/

#if 0
int mymsg(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	int result = vmsg(format, ap);
	va_end(ap);
	return result;
}
#endif

void CallExpression::LoadTypeInformation()/*{{{*/
{
	IdaPro::LoadCallTypeInformation(this);
}/*}}}*/

ea_t DataSeg()
{
	for(int i = 0; i < get_segm_qty(); i++)
	{
		segment_t* s = getnseg(i);
		if (SEG_DATA == s->type)
			return get_segm_base(s);
	}
	return 0;
}

#if 0
void CallExpression::SetDataTypes()/*{{{*/
{
	ea_t base = DataSeg();
	
	for (int i = 0; i < mParameterCount; i++)
	{
		if (mDataTypes[i])
		{
			Expression_ptr e = SubExpression(i+1);

#if 0
			char buffer[MAXSTR]; 
			buffer[0] = '\0';
			print_type_to_one_line(buffer, sizeof(buffer), idati, mDataTypes[i]);
			msg("Parameter %i type: %s\n", i, buffer);
#endif
			
			e->DataType().Set(mDataTypes[i]);
			
			if (e->IsType(Expression::NUMERIC_LITERAL) &&
					e->DataType().IsCharPointer())
			{
				// This is an immediate that is a string pointer... aha!
				Expression_ptr str = StringLiteral::CreateFrom(
						base + static_cast<NumericLiteral*>(e.get())->Value() 
						);

				if (str.get())
				{
					str->DataType().Set(mDataTypes[i]);
					SubExpression(i+1, str);
				}
			}
		}
	}
}/*}}}*/
#endif

Expression_ptr StringLiteral::CreateFrom(ea_t address)/*{{{*/
{
	Expression_ptr result;
	
	ulong type = get_str_type(address);

    std::string value = GetString(address, type);
	if (!value.empty())
		result.reset(new StringLiteral(value, type));
	else
		msg("ERROR: StringLiteral::CreateFrom(%08lx) -> NULL\n", address);

	return result;
}/*}}}*/

std::string StringLiteral::GetString(ea_t address, ulong type)/*{{{*/
{
	size_t len = get_max_ascii_length(address, type, false);
	boost::shared_array<char> str(new char[len+1]);
	get_ascii_contents(address, len, type, str.get(), len+1);
	return str.get();
}/*}}}*/

std::string StringLiteral::EscapeAsciiString(const std::string& ascstr)/*{{{*/
{
    std::string esc;
    for (std::string::const_iterator i= ascstr.begin() ; i!=ascstr.end() ; ++i) {
             if ((*i)=='\n') esc += "\\n";    // 0x0a newline
        else if ((*i)=='\r') esc += "\\r";    // 0x0d carriage return
        else if ((*i)=='\t') esc += "\\t";    // 0x09 tab
        else if ((*i)=='\\') esc += "\\\\";   // 0x5c backslash
        else if ((*i)=='\v') esc += "\\v";    // 0x0b vertical tab
        else if ((*i)=='\b') esc += "\\b";    // 0x08 backspace
        else if ((*i)=='\f') esc += "\\f";    // 0x0c form feed
        else if ((*i)=='\a') esc += "\\a";    // 0x07 bell
        else if ((*i)=='\"') esc += "\\\"";   // 0x22 double quote
        else if (isprint(*i))
            esc += (*i);
        else
            esc += str(boost::format("\\x%02x") % (int)(*i));
    }
    return esc;
}/*}}}*/

Addr GlobalVariable::Address()
{
	if (mAddress == INVALID_ADDR)
		mAddress = Frontend::Get().AddressFromName(Name().c_str());
	return mAddress;
}

#if 1
bool Expression::Equal(Expression_ptr a, Expression_ptr b)
{
//	msg("Comparing two expressions\n");
	
	if (a->Type() != b->Type() ||
			a->SubExpressionCount() != b->SubExpressionCount())
		return false;

	for (int i = 0; i < a->SubExpressionCount(); i++)
	{
		if (!Equal(a->SubExpression(i), b->SubExpression(i)))
			return false;
	}

	switch (a->Type())
	{
		case UNARY_EXPRESSION:
		case BINARY_EXPRESSION:
		case TERNARY_EXPRESSION:
			// TODO: check operators
			return false;

		case REGISTER:
			return 
				static_cast<Register*>(a.get())->Index() ==
				static_cast<Register*>(b.get())->Index();

		case NUMERIC_LITERAL:
			return 
				static_cast<NumericLiteral*>(a.get())->Value() ==
				static_cast<NumericLiteral*>(b.get())->Value();

			// TODO: handle all types
	}

	return false;
}
#endif

