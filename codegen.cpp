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
// $Id: codegen.cpp,v 1.6 2007/01/30 09:48:02 wjhengeveld Exp $
#include "codegen.hpp"
#include "instruction.hpp"
#include "node.hpp"

#include "idainternal.hpp"  // for LowLevel
/**
 * Instruction visitor for code generation
 */
class CodeGenerator : public InstructionVisitor
{
	public:
		CodeGenerator(CodeStyle style)
			: mStyle(style)
		{}

		virtual ~CodeGenerator()
		{
			static const int  MAX_LINE_LEN   = 80;
			char              tmp[MAX_LINE_LEN + 1];
			int               len;
			std::string       outstring = mOut.str();
            const char      * pos = outstring.c_str();
			for ( size_t i = 0; i < mOut.str().size() + 1; i += MAX_LINE_LEN )
			{
				len = mOut.str().size() - i;
				if ( len >= MAX_LINE_LEN )
				{
					len = MAX_LINE_LEN;
				}
				memcpy(tmp, pos, len);
				tmp[len] = 0;
				message("%s", tmp);
				pos += len;
			}
		}

		//
		// Implementation of InstructionVisitor interface follows
		//
		
		virtual void Visit(Assignment& instruction)
		{
			Prefix(instruction);
			if (!instruction.First()->IsType(Expression::DUMMY))
			{
				instruction.First()->GenerateCode(mOut);
				mOut << " = ";
			}
			instruction.Second()->GenerateCode(mOut);
			mOut << ';' << std::endl;
		}

		virtual void Visit(Case& instruction)
		{
			Prefix(instruction);
			mOut << "case " << instruction.Value() << ':' << std::endl;
		}

		virtual void Visit(ConditionalJump& instruction)
		{
			Prefix(instruction);
			mOut << "if (";
			instruction.First()->GenerateCode(mOut);
			mOut << ") goto ";
			instruction.Second()->GenerateCode(mOut);
			mOut << ';' << std::endl;
		}

		virtual void Visit(Jump& instruction)
		{
			Prefix(instruction);
			mOut << "goto ";
			instruction.Operand()->GenerateCode(mOut);
			mOut << ';' << std::endl;
		}

		virtual void Visit(Label& instruction)
		{
			Prefix(instruction, NO_INDENT);
			mOut << instruction.Name() << ':' << std::endl;
		}

		virtual void Visit(LowLevel& instruction)
		{
			Prefix(instruction);
			mOut << "/* Low-level instruction of type " 
				<< instruction.Insn().itype
				<< " */" << std::endl;
		}

		virtual void Visit(Push& instruction)
		{
			Prefix(instruction);
			mOut << "/* push ";
			instruction.Operand()->GenerateCode(mOut);
			mOut << " */" << std::endl;
		}

		virtual void Visit(Pop& instruction)
		{
			Prefix(instruction);
			mOut << "/* pop ";
			instruction.Operand()->GenerateCode(mOut);
			mOut << " */" << std::endl;
		}

		virtual void Visit(Return& instruction)
		{
			Prefix(instruction);
			mOut << "return ";
			instruction.Operand()->GenerateCode(mOut);
			mOut << ';' << std::endl;
		}

		virtual void Visit(Switch& instruction)
		{
			Prefix(instruction);
			mOut << "switch (";
			instruction.Operand()->GenerateCode(mOut);
			mOut << ')' << std::endl;
		}
		
		virtual void Visit(Throw& instruction)
		{
			Prefix(instruction);
			if (instruction.IsRethrow())
			{
				mOut << "throw;" << std::endl;
			}
			else
			{
				mOut << "throw ";
				instruction.Exception()->GenerateCode(mOut);
				mOut << "; // " << instruction.DataType() << std::endl;
			}
		}
		
		virtual void NodeEnd()
		{
			mOut << std::endl;
		}


	private:
		enum Indent
		{
			NO_INDENT, INDENT
		};

		void Prefix(Instruction& instruction, Indent indent = INDENT)
		{
			if (LISTING_STYLE == mStyle)
			{
				mOut << boost::format("%08x ") % instruction.Address();
			}

			if (indent == INDENT)
				mOut << "  ";
		}

	private:

		CodeStyle mStyle;
		std::ostringstream mOut;
};

/**
 * Generate code for a list of instructions
 */
void GenerateCode(Instruction_list& instructions, CodeStyle style)
{
	CodeGenerator code_generator(style);
	Accept(instructions, code_generator);
}

/**
 * Generate code for list of nodes
 */
void GenerateCode(Node_list& nodes, CodeStyle style)
{
	CodeGenerator code_generator(style);
	Accept(nodes, code_generator);
}


