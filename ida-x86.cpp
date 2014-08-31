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
// $Id: ida-x86.cpp,v 1.4 2007/01/30 09:48:51 wjhengeveld Exp $
#include "idainternal.hpp"
#include "ida-x86.hpp"
#include "analysis.hpp"
#include "expression.hpp"

#if IDP_INTERFACE_VERSION<76
// backward compatibility
ssize_t get_switch_info(ea_t ea, switch_info_t *buf, size_t bufsize)
{
    switch_info_t *si= get_switch_info(ea);
    if (si) {
        memcpy(buf, si, bufsize);
        return bufsize;
    }
    return -1;
}
#endif
// 70 = ida4.70, 75 = ida4.80
#if IDP_INTERFACE_VERSION<75
int get_func_bits(func_t *function)
{
	if (is_32bit_func(function))
		return 32;
	else
		return 16;
}
#endif



Expression_ptr RegTimesValue(unsigned short reg, unsigned long value)/*{{{*/
{
	switch (value)
	{
		case 0:
			return NumericLiteral::Create(0);

		case 1:
			return Register::Create(reg);
			
		default:
			return Expression_ptr( new BinaryExpression(
						Register::Create(reg),
						"*",
						NumericLiteral::Create(value)
						));
	}
}/*}}}*/

Expression_ptr RegPlusReg(unsigned short reg1,unsigned short reg2)/*{{{*/
{
	return Expression_ptr( new BinaryExpression(
				Register::Create(reg1),
				"+",
				Register::Create(reg2)
				));
}/*}}}*/

Expression_ptr RegPlusRegTimesValue(unsigned short reg1,unsigned short reg2, unsigned long value)/*{{{*/
{
	if (0 == value)
		return Register::Create(reg1);
	else
		return Expression_ptr( new BinaryExpression(
					Register::Create(reg1),
					"+",
					RegTimesValue(reg2, value)
					));
}/*}}}*/

Expression_ptr GetSibExpression(insn_t& insn, int operand)/*{{{*/
{
	Expression_ptr result;
	
	unsigned char sib = insn.Operands[operand].sib & 0xff;
	
#if 0
	switch (sib & 0xff)
	{
		case 0x02:
			result = RegPlusReg(REG_DX, REG_AX);
			break;

		case 0x0a:
			result = RegPlusReg(REG_DX, REG_CX);
			break;

		case 0x0f:
			result = RegPlusReg(REG_DI, REG_CX);
			break;

		case 0x10:
			result = RegPlusReg(REG_AX, REG_DX);
			break;

		case 0x16:
			result = RegPlusReg(REG_SI, REG_DX);
			break;

		case 0x19:
			result = RegPlusReg(REG_CX, REG_BX);
			break;

		case 0x2b:
			result = RegPlusReg(REG_BX, REG_BP);
			break;

		case 0x31:
			result = RegPlusReg(REG_CX, REG_SI);
			break;

		case 0x32:
			result = RegPlusReg(REG_DX, REG_SI);
			break;

		case 0x33:
			result = RegPlusReg(REG_BX, REG_SI);
			break;

		case 0x41: // [ecx+eax*2]
			result = RegPlusRegTimesValue(REG_CX, REG_AX, 2);
			break;
		
		case 0x50: // [eax+edx*2]
			result = RegPlusRegTimesValue(REG_AX, REG_DX, 2);
			break;

		case 0x51: // [ecx+edx*2]
			result = RegPlusRegTimesValue(REG_CX, REG_DX, 2);
			break;

		case 0x71: // [ecx+esi*2]
			result = RegPlusRegTimesValue(REG_CX, REG_SI, 2);
			break;
				
		case 0x85: // [eax*4]
			result = RegTimesValue(REG_AX, 4);
			break;

		case 0xb6: // [esi+esi*4] -> esi*5
			result = RegTimesValue(REG_SI, 5);
			break;

		default:
			msg("%p Unknown SIB: %p\n", insn.ea, op.sib);
			result.reset( new Dummy() );
			break;
	}
#endif

  unsigned short scale = 1 << (sib >> 6);
  unsigned short index_reg = (sib >> 3) & 0x07;
  unsigned short base_reg = sib & 0x07;

	if (base_reg == 5)
	{
		result = RegTimesValue(index_reg, scale);

		msg("%p SIB: base=%i, %s*%i\n", insn.ea, 
				base_reg, Register::Name(index_reg).c_str(), scale);
	}
	else
	{
		result = RegPlusRegTimesValue(base_reg, index_reg, scale);
	}

	return result;
}/*}}}*/

/*{{{ Expression_ptr FromOperand */
static Expression_ptr FromOperand(insn_t& insn, int operand/*,
				TypeInformation* type = NULL*/)
{
	Expression_ptr result;

	flags_t flags = ::getFlags(insn.ea);
	if (::isStkvar(flags, operand))
	{
		result = CreateStackVariable(insn, operand);
		if (NN_lea == insn.itype)
		{
			result.reset( new UnaryExpression("&", result) );
		}
	}
	else if (::isEnum(flags, operand))
	{
		msg("%p TODO: handle enum!!\n", insn.ea);
	}
	
	if (!result.get())
	{
		op_t op = insn.Operands[operand];
		refinfo_t refinfo;

#if 0
		if (op.hasSIB)
		{
			msg("%p Operand %i of type %i has SIB=%p\n", 
					insn.ea, operand, op.type, op.sib);
		}
#endif

		switch (op.type)
		{
			case o_reg:
				result.reset( new Register(op.reg) );
				break;

			case o_imm:
				if (::get_refinfo(insn.ea, operand, &refinfo))
				{
					ea_t address = refinfo.base + op.value;
					flags_t flags = ::getFlags(address);

					if (isASCII(flags))
					{
						result = StringLiteral::CreateFrom(address);
						break;
					}
					else
					{
						// XXX: maybe use & operator for result?
						result = CreateGlobalVariable(insn, operand);
						if (result.get())
							break;
					}
				}
				result.reset( new NumericLiteral(op.value) );
				break;

			case o_near:
				if (!(insn.auxpref & aux_ad_is_32))
				{
					// Copy current segment value for 16-bit adresses
					op.addr |= insn.ea & 0xffff0000;
				}
				// fall though
				
			case o_mem:
			case o_far:
				{
				insn_t insxx= insn;
				insxx.Operands[operand].addr = op.addr;
				result = CreateVariable(insxx, operand);
				}
				if (result.get())
				{
					if (NN_lea == insn.itype)
					{
						result.reset(
								new UnaryExpression(
								"&",
								result));
					}
				}

				if (op.hasSIB)
				{
					if (!result.get())
					{
						result.reset(new NumericLiteral(op.addr));
					}

					result.reset(
							new BinaryExpression(
								result,
								"+",
								GetSibExpression(insn, operand)
								));
					break;
				}

				if (!result.get())
				{
					if (0x14 == op.segrg && 0 == op.addr)
					{
						 // Operand is "large fs:0"
						 msg("%p This instruction uses the FS segment register and should probably be handled special\n", insn.ea);
					}
					else
					{
						msg("%p [FromOperand] UNEXPECTED MEMORY ADDRESS", insn.ea);
						msg(", phrase=%i, addr=%08x, value=%i, specval=%x\n", 
								op.phrase, op.addr, op.value, op.specval);
					}
					result.reset( new Dummy() );
				}
				break;

			case o_phrase:
				// fall through

			case o_displ:
				if (op.hasSIB)
				{
					result = GetSibExpression(insn, operand);
				}
				else
				{
					unsigned short reg = (unsigned short)-1;

				
					switch (op.phrase)
					{
						case 0: reg = REG_AX; break;
						case 1: reg = REG_CX; break;
						case 2: reg = REG_DX; break;
						case 3: reg = REG_BX; break;
            case 5: reg = REG_BP; break;  // probably!
						case 6: reg = REG_SI; break;
						case 7: reg = REG_BX; break;

						default:
							msg("%p Warning! CHECK OUT OPERAND %i of type %i (o_displ). op.phrase=%i\n", 
									insn.ea, operand, op.type, op.phrase);
							break;
					}
							
					result.reset(new Register(reg));
				}

				if (0 != op.addr)
				{
					result.reset( new BinaryExpression(
								result,
								"+",
								Expression_ptr( new NumericLiteral(op.addr) ))
							);
				}

				if (NN_lea != insn.itype)
				{
					result.reset( new UnaryExpression("*", result) );
				}
				break;

			default:
				msg("Warning: %p Unknown operand type %i\n", insn.ea, op.type);
				result.reset( new Dummy() );
				break;
		}
	}

#if 0
	if (result.get() && NULL != type)
	{
		result->DataType() = *type;
	}
#endif
	if (!result)
		msg("ERROR: FromOperand -> NULL\n");
	return result;
}/*}}}*/

/**
 * Create an Assignment instruction from instruction and operation.
 * If the last parameter is present, use it as second operand.
 */
Instruction_ptr AssignFromBinaryExpression(insn_t& insn, const char* operation,/*{{{*/
		Expression* secondOperand = NULL)
{
	Expression_ptr second;

	if (secondOperand)
		second.reset(secondOperand);
	else
		second = FromOperand(insn, 1);

	return Instruction_ptr(
			new Assignment(
				insn.ea,
				FromOperand(insn, 0), 
				Expression_ptr(new BinaryExpression(
					FromOperand(insn, 0), 
					operation,
					second)
					)
				)
			);
}/*}}}*/

Expression_ptr CreateCondition(insn_t& condition, const char* operation)/*{{{*/
{
	return Expression_ptr(new BinaryExpression(
				FromOperand(condition, 0), 
				operation,
				FromOperand(condition, 1)
				));
}/*}}}*/

Instruction_ptr CreateConditionalJump(insn_t& condition, insn_t& destination,/*{{{*/
		const char* operation)
{
	return Instruction_ptr(
			new ConditionalJump(
				destination.ea,
				CreateCondition(condition,operation),
				FromOperand(destination, 0)
				)
			);
}/*}}}*/

#define DUMP_FLAG(flag) if (insn.auxpref & (flag)) msg(", " # flag );

void IdaX86::DumpInsn(insn_t& insn)/*{{{*/
{
	msg("ea=%p, itype=%i", insn.ea, insn.itype);

	DUMP_FLAG(aux_lock)
	DUMP_FLAG(aux_rep)
	DUMP_FLAG(aux_repne)
	DUMP_FLAG(aux_use32)
	DUMP_FLAG(aux_large)
	DUMP_FLAG(aux_short)
	DUMP_FLAG(aux_prefix)
	DUMP_FLAG(aux_op32)
	DUMP_FLAG(aux_ad32)
	DUMP_FLAG(aux_basess)
	DUMP_FLAG(aux_op_is_32)
	DUMP_FLAG(aux_ad_is_32)
	DUMP_FLAG(aux_fpemu)
	
	if (insn.segpref)
		msg(", segpref=%p", insn.segpref);

	msg("\n");
	
	for (int i = 0; i < UA_MAXOP; i++)
	{
		op_t& op = insn.Operands[i];
		
		if (op.type == o_void)
			break;

	
		msg("  Operands[%i]={type=%s, dtyp=%i, reg/phrase=%s/%i, value=%i, addr=%08x",
				i, GetOptypeString(op), op.dtyp, 
				RegisterName(op.reg).c_str(),
				op.reg, op.value, op.addr);
		if (op.specval)
			msg(", specval=%p", op.specval);
		if (op.hasSIB)
			msg(", sib=%p", op.sib);
		if (op.specflag3)
			msg(", specflag3=%p", op.specflag3);
		if (op.specflag4)
			msg(", specflag4=%p", op.specflag4);
		msg("}\n");
	}
}/*}}}*/

bool OperandIsRegister(insn_t& insn, int operand, int reg)/*{{{*/
{
	return 
		o_reg == insn.Operands[operand].type && 
		reg   == insn.Operands[operand].reg;
}/*}}}*/

bool OperandIsImmediate(insn_t& insn, int operand, unsigned value)/*{{{*/
{
	return 
		o_imm == insn.Operands[operand].type && 
		value == insn.Operands[operand].value;
}/*}}}*/

bool Equals(op_t& a, op_t& b)/*{{{*/
{
	if (a.type != b.type || a.dtyp != b.dtyp)
		return false;

	switch (a.type)
	{
		case o_reg:
			return a.reg == b.reg;

		case o_mem:
		case o_far:
		case o_near:
			return a.addr == b.addr;

		case o_phrase:
			return a.reg == b.reg &&
				a.phrase == b.phrase;

		case o_displ:
			return a.reg == b.reg &&
				a.phrase == b.phrase &&
				a.addr == b.addr &&
				a.flags == b.flags;

		case o_imm:
			return a.value == b.value;

		default:
			msg("Unknown operand type\n");
			break;
	}

	return false;
}/*}}}*/

class X86Analysis : public Analysis/*{{{*/
{
	public:
		X86Analysis()
		{
		}
		
		void AnalyzeFunction(func_t* function, Instruction_list& instructions)/*{{{*/
		{
			Instructions(&instructions);
			MakeLowLevelList(function);

			memset(&mFlagUpdate, 0, sizeof(mFlagUpdate));
			mFlagUpdateItem = Instructions().end();

			AnalyzeInstructionList();
			Instructions(NULL);
		}/*}}}*/

	protected:
		enum
		{
			SAVE_INSN,
			SAVE_INSN_AND_ITERATOR,
		} FlagSave;

		
		// this creates a list of LowLevel(insn_t)
		// and Label(address, labelname) objects.
		void MakeLowLevelList(func_t* function)/*{{{*/
		{
			Instructions().clear();

			if (get_func_bits(function)==32)
				setbits(IS_32_BIT);
			else
				setbits(IS_16_BIT);

			for(ea_t address = function->startEA; 
					address < function->endEA;
					address = get_item_end(address))
			{
				flags_t flags = getFlags(address);

				if (hasRef(flags) /*|| has_any_name(flags)*/)
				{
                    int index;
                    std::string name = GetLocalCodeLabel(address, &index);
					if (name.empty() || index)
					{
						msg("%p Warning: referenced offset without name\n", address);
					}
					else
					{
						//msg("%p Name=%s\n", address, name.c_str());
						Instruction_ptr label(new Label(address, name.c_str()));
						Instructions().push_back(label);
					}
				}

				if (!isCode(flags))
				{
					if (isUnknown(flags))
					{
						msg("Warning, converting non-code bytes in function at offset %p\n", 
								address);

						ua_code(address);
						flags = getFlags(address);
						if (!isCode(flags))
						{
							msg("Error, could not convert non-code bytes in function at offset %p\n", 
									address);
							break;
						}
					}
					else
					{
						msg("Warning, skipping byte with flags %p at offset %p\n",
								flags,
								address);
						//						address++;
						continue;
					}
				}

				Instructions().push_back( Instruction_ptr(
							new LowLevel( GetLowLevelInstruction(address) )
							));
			}
		}/*}}}*/

		void DumpInsn(insn_t& insn)
		{
			static_cast<IdaPro&>(Frontend::Get()).DumpInsn(insn);
		}
		
		/**
		 * Handle a LowLevel instruction
		 */
		virtual void OnLowLevel(Instruction* lowLevel)/*{{{*/
		{
			insn_t insn = static_cast<LowLevel*>(lowLevel)->Insn();
			//msg("%p OnLowLevel\n", insn.ea);

#if 0
			for (int i = 0; i < UA_MAXOP; i++)
			{
				op_t& op = insn.Operands[i];

				if (op.type == o_void)
					break;

				if (op.specval)
				{
					DumpInsn(insn);
					break;
				}
			}
#endif

			switch_info_t si;
			if (get_switch_info(insn.ea, &si, sizeof(si))>=0)
			{
				if (OnSwitchInfo(insn, si))
					return;
			}
			
			switch (insn.itype)
			{
				case NN_and:
					OnAnd(insn);
					break;

				case NN_not:
					mFlagUpdate = insn;
					mFlagUpdateItem = Replace(
							new Assignment(
								insn.ea,
								FromOperand(insn, 0),
								Expression_ptr(new UnaryExpression(
										"~",
										FromOperand(insn, 0)))));
					break;

				case NN_or:
          mFlagUpdate = insn;
          //DumpInsn(insn);
          if ((insn.Operands[0].type == o_mem ||
              insn.Operands[0].type == o_displ) &&
              insn.Operands[1].type == o_imm &&
              (int)insn.Operands[1].value == -1)
          {
            //
            // or memory, -1
            //
            mFlagUpdateItem = Replace( 
                new Assignment(
                  insn.ea,
                  FromOperand(insn, 0),
                  Expression_ptr (new NumericLiteral(BADADDR))
                  ) 
                );
            //msg("%p 'or' is really assignment of -1 to memory?\n", insn.ea);
          }
          else
          {
            mFlagUpdateItem = Replace( AssignFromBinaryExpression(insn, "|") );
          }
					break;

				case NN_xor:
					OnXor(insn);
					break;

				case NN_cdq:
					OnCdq(insn);
					break;

				case NN_cld:
					OnCld(insn);
					break;

				case NN_div:
					OnDiv(insn, UNSIGNED_INT);
					break;
			
				case NN_idiv:
					OnDiv(insn, SIGNED_INT);
					break;

				case NN_mul:
					OnMul(insn, UNSIGNED_INT);
					break;
					
				case NN_imul:
					OnMul(insn, SIGNED_INT);
					break;

				case NN_call:
				case NN_callni:
				case NN_callfi:
					OnCall(insn);
					break;

				case NN_cmp:
					EraseInstructions(1);
					mFlagUpdate = insn;
					mFlagUpdateItem = Instructions().end();
					break;
				
				case NN_test:
					OnTest(insn);
					break;

				case NN_enter:
				case NN_leave:
					EraseInstructions(1);
					break;

				case NN_add:
					mFlagUpdate = insn;
					mFlagUpdateItem = Replace(
							AssignFromBinaryExpression(insn, "+")
							);
					break;

				case NN_sub:
					mFlagUpdate = insn;
					mFlagUpdateItem = Replace(
							AssignFromBinaryExpression(insn, "-")
							);
					break;

				case NN_inc:
					mFlagUpdate = insn;
					mFlagUpdateItem = Replace(
							AssignFromBinaryExpression(insn, "+", new NumericLiteral(1))
							);
					break;

				case NN_dec:
					mFlagUpdate = insn;
					mFlagUpdateItem = Replace(
							AssignFromBinaryExpression(insn, "-", new NumericLiteral(1))
							);
					break;

				case NN_ja:	// above -> unsigned
					OnConditionalJump(insn, ">", UNSIGNED_INT);
					break;
				case NN_jg:	// greater -> signed
					OnConditionalJump(insn, ">", SIGNED_INT);
					break;
				case NN_jb:	// below -> unsigned
					OnConditionalJump(insn, "<", UNSIGNED_INT);
					break;
				case NN_jbe:	// below -> unsigned
					OnConditionalJump(insn, "<=", UNSIGNED_INT);
					break;
				case NN_jnb:
					OnConditionalJump(insn, ">=", UNSIGNED_INT);
					break;
				case NN_jge:
					OnConditionalJump(insn, ">=", SIGNED_INT);
					break;
				case NN_jl:
					OnConditionalJump(insn, "<", SIGNED_INT);
					break;
				case NN_jle:
					OnConditionalJump(insn, "<=", SIGNED_INT);
					break;
				case NN_jz:
					OnConditionalJump(insn, "==");
					break;
				case NN_jnz:
					OnConditionalJump(insn, "!=");
					break;

				case NN_js: // < 0
					OnConditionalJump(insn, "<", SIGNED_INT);
					break;
				case NN_jns: // >= 0
					OnConditionalJump(insn, ">=", SIGNED_INT);
					break;

				case NN_jmp:
				case NN_jmpni:
					Replace(
							new Jump(insn.ea, FromOperand(insn, 0))
							);
					break;

				case NN_mov:
					if (TryBorlandClass(insn))
						break;
					if (TryMemcpy(insn))
						break;
					if (TryMemcpy4(insn, false))
						break;
					// fall through

				case NN_lea:
//					msg("mov/movzx/lea: ");
//					DumpInsn(insn);
					OnMov(insn);
					break;

				case NN_movsx:
					OnMov(insn, SIGNED_INT);
					break;

				case NN_movzx:
					OnMov(insn, UNSIGNED_INT);
					break;

				case NN_neg:
					OnNeg(insn);
					break;

				case NN_nop:
					Erase(Iterator());
					break;

				case NN_pop:
					Replace(
							new Pop(insn.ea, FromOperand(insn, 0)));
					break;

				case NN_push:
					OnLowLevelPush(insn);
					break;

				case NN_retn:
				case NN_retf:
					Replace( 
							new Return(insn.ea, Register::Create(REG_AX)) 
							);
					break;

				case NN_setz:
					OnSet(insn, "==");
					break;
				case NN_setnz:
					OnSet(insn, "!=");
					break;
				case NN_setnb:
					OnSet(insn, ">=");
					break;

				case NN_shl:
					Replace( AssignFromBinaryExpression(insn, "<<") );
					break;

				case NN_sar:	// signed
				case NN_shr:	// unsigned
					Replace( AssignFromBinaryExpression(insn, ">>") );
					break;

				case NN_xchg:
#if 0
					if (TryXchgMov(insn))
						break;
					// fall through
#endif
					OnXchg(insn);
					break;

				default:
					DumpInsn(insn);
					msg("%p Unhandled instruction: %p\n", insn.ea, insn.itype);
					break;
			}
		}/*}}}*/

		bool GetInstructions(int count, insn_vector& instructions)/*{{{*/
		{
			for(Instruction_list::iterator item = Iterator();
					count > 0 && item != Instructions().end();
					item++)
			{
				if ((**item).IsType(Instruction::LOW_LEVEL))
				{
					instructions.push_back(
							static_cast<LowLevel*>(item->get())->Insn());
				}
				else
					break;

				count--;
			}
	
			// Fill with empty elements if needed
			if (0 < count)
			{
				insn_t empty;
				memset(&empty, 0, sizeof(empty));
				while (count--)
					instructions.push_back(empty);
			}
			
			return 0 == count;
		}/*}}}*/

		bool TryNegSbb(insn_t& insn)/*{{{*/
		{
			/*
				neg eax
				sbb eax,eax
				and eax, 8
					->
				eax = -eax									; The carry flag is set to 1, unless the 
																		; operand is zero, in which case the 
																		; carry flag is cleared to 0. 
				eax = eax - (eax + carry)
				eax &= 8
					->
				eax = {0 if eax == 0 | 8 if eax != 0}
					->
				eax ? 8 : 0
			*/
			if (o_reg != insn.Operands[0].type)
				return false;

			insn_vector idiom;
			if (!GetInstructions(3, idiom))
				return false;
				
			unsigned short reg = insn.Operands[0].reg;

			if (NN_sbb == idiom[1].itype &&
					OperandIsRegister(idiom[1], 0, reg) &&
					OperandIsRegister(idiom[1], 1, reg))
			{
				//msg("%p Found idiom: neg eax; sbb eax,eax\n", insn.ea);

				Expression_ptr e;

				if (NN_and == idiom[2].itype &&
						(OperandIsRegister(idiom[2], 0, reg) ||
						 OperandIsRegister(idiom[2], 0, reg + 8)))  // AL<->AX
				{
					//msg("%p Idiom followed by AND\n", insn.ea);	
					e = TernaryExpression::Create(
									Register::Create(reg),
									FromOperand(idiom[2], 1),
									NumericLiteral::Create(0)
									);
					EraseInstructions(3);
				}
				else
				{
					//msg("%p Idiom NOT followed by AND\n", insn.ea);	
					e = TernaryExpression::Create(
								Register::Create(reg),
								NumericLiteral::Create(0xffffffff),
								NumericLiteral::Create(0)
								);
					EraseInstructions(2);
				}

				Insert( new Assignment(insn.ea, Register::Create(reg), e) ); 

				return true;
			}
			return false;
		}/*}}}*/

		bool TryMemcpy(insn_t& insn)/*{{{*/
		{
			insn_vector idiom;
			if (!GetInstructions(6, idiom))
				return false;

			/*
				 0 mov     eax, ecx
				 1 shr     ecx, 2
				 2 repe movsd
				 3 mov     ecx, eax
				 4 and     ecx, 3
				 5 repe movsb

				 ->

				 memcpy(edi, esi, ecx);
			*/

			if (OperandIsRegister (idiom[0], 0, REG_AX) &&
					OperandIsRegister (idiom[0], 1, REG_CX) &&
					NN_shr ==          idiom[1].itype &&
					OperandIsRegister (idiom[1], 0, REG_CX) &&
					OperandIsImmediate(idiom[1], 1, 2) &&
					(idiom[2].auxpref & aux_rep) &&					
					NN_movs ==         idiom[2].itype &&			// check more here
					NN_mov ==          idiom[3].itype &&
					OperandIsRegister (idiom[3], 0, REG_CX) &&
					OperandIsRegister (idiom[3], 1, REG_AX) &&
					NN_and ==          idiom[4].itype &&
					OperandIsRegister (idiom[4], 0, REG_CX) &&
					OperandIsImmediate(idiom[4], 1, 3) &&
					(idiom[5].auxpref & aux_rep) &&
					NN_movs ==         idiom[5].itype			// check more here
				 )
			{
				msg("%p Found memcpy\n", insn.ea);

				CallExpression* call = new CallExpression( Expression_ptr( new GlobalVariable("memcpy") ) );

				call->AddParameter( Expression_ptr( new Register(REG_DI) ) );
				call->AddParameter( Expression_ptr( new Register(REG_SI) ) );
				call->AddParameter( Expression_ptr( new Register(REG_CX) ) );
				call->SetFinishedAddingParameters();

				Insert(
						new Assignment(
							insn.ea,
							Expression_ptr( new Register(REG_DI) ), // XXX: really return DI?
							Expression_ptr(call)
							));

				EraseInstructions(6);
				return true;
			}
			return false;
		}/*}}}*/ 

		bool TryMemcpy4(insn_t& insn, bool haveCld = true)/*{{{*/
		{
			insn_vector idiom;
			if (!GetInstructions(5, idiom))
				return false;

			int index = 0;

			if (haveCld)
				index++;

			/*
				 cld
				 mov ecx, 125
				 repe movsd
				 movsw        ; maybe
				 movsb        ; maybe

				 ->

				 memcpy(edi, esi, 125*4);
			*/

			if (OperandIsRegister (idiom[index+0], 0, REG_CX) &&
					o_imm   ==         idiom[index+0].Operands[1].type &&
					NN_movs ==         idiom[index+1].itype &&
					(idiom[index+1].auxpref & aux_rep)
				 )
			{
				/*msg("%p Found memcpy4\n", insn.ea);

				for (int i = 0; i < 5; i++)
				{
					DumpInsn(idiom[i]);
				}*/
				
				unsigned long value = idiom[index+0].Operands[1].value * 4;
				int used_instructions = index+2;

				//
				// If the instruction is followed by movsw/movsb...
				//
				for (int i = index+2; i < (index+4); i++)
				{
					if (NN_movs == idiom[i].itype)
					{
						if (dt_byte == idiom[i].Operands[0].dtyp)
							value++;
						else if (dt_word == idiom[i].Operands[0].dtyp)
							value += 2;
						else
							break;
					}
					else
						break;

					used_instructions++;
				}

				CallExpression* call = new CallExpression( Expression_ptr( new GlobalVariable("memcpy") ) );

				call->AddParameter( Expression_ptr( new Register(REG_DI) ) );
				call->AddParameter( Expression_ptr( new Register(REG_SI) ) );
				call->AddParameter( Expression_ptr( new NumericLiteral(
								value) 
							) );
				call->SetFinishedAddingParameters();

				Insert(
						new Assignment(
							insn.ea,
							Expression_ptr( new Register(REG_DI) ),
							Expression_ptr(call)
							));

				EraseInstructions(used_instructions);
				return true;
			}
			return false;
		}/*}}}*/ 

		bool TryProlog(insn_t& insn)/*{{{*/
		{
			/*
				push ebp
				mov ebp, esp
				sub esp, ?     ; optional
				push edi		; optional
				push esi		; optional
			*/
			
			insn_vector idiom;
			if (!GetInstructions(5, idiom))
				return false;

			if (OperandIsRegister(idiom[0], 0, REG_BP) &&
					NN_mov ==         idiom[1].itype &&
					OperandIsRegister(idiom[1], 0, REG_BP) &&
					OperandIsRegister(idiom[1], 1, REG_SP)
					)
			{
				int prologue_size = 2;

				if (NN_sub ==         idiom[2].itype &&
						OperandIsRegister(idiom[2], 0, REG_SP) &&
						o_imm ==          idiom[2].Operands[1].type)
				{
					prologue_size++;
				}

				for (int i = prologue_size; i < 5; i++)
				{
					if (NN_push == idiom[i].itype && 
                            o_imm != idiom[i].Operands[0].type)
					{
						msg("%p Register variable: %s\n", idiom[i].ea, 
								Register::Name(idiom[i].Operands[0].reg).c_str());
						prologue_size++;
					}
					else
						break;
				}
					
				EraseInstructions(prologue_size);
				return true;
			}
			
			return false;
		}/*}}}*/
    
		bool TryPushPop(insn_t& insn)/*{{{*/
		{
			/*
				push register|immediate
        pop register
			*/
			
			insn_vector idiom;
			if (!GetInstructions(2, idiom))
				return false;

      if (NN_pop == idiom[1].itype &&
          o_reg  == idiom[1].Operands[0].type
					)
			{
				Insert( new Assignment(
								insn.ea,
								Register::Create(idiom[1].Operands[0].reg),
								FromOperand(idiom[0], 0)
								));
					
				EraseInstructions(2);
				return true;
			}
			
			return false;
		}/*}}}*/


		bool TryXorCmpSet(insn_t& insn)/*{{{*/
		{
			/*
					xor edx,edx
					cmp X,Y
					set(n)z dl

					-> 

					edx = (X == Y)   or    edx = (X != Y)
			*/
			insn_vector idiom;
			if (!GetInstructions(3, idiom))
				return false;

			// We already know that the first operation is XOR reg,reg
			
			unsigned short reg = idiom[0].Operands[0].reg;

			if ((REG_AX == reg || REG_BX == reg || REG_CX == reg || REG_DX == reg) &&
					NN_cmp ==   idiom[1].itype &&
					(NN_setz == idiom[2].itype || NN_setnz == idiom[2].itype) &&
					OperandIsRegister(idiom[2], 0, reg + 8))
			{
				msg("%p Found xor/cmp/set(n)z idiom\n", insn.ea);

				const char* operation;
				if (NN_setz == idiom[2].itype)
					operation = "==";
				else // NN_setnz
					operation = "!=";

				Insert( new Assignment(
								insn.ea,
								Register::Create(reg),
								CreateCondition(idiom[1], operation) 
								));
				EraseInstructions(3);

				return true;
			}
			
			return false;
		}/*}}}*/

		bool TryStrlen(insn_t& insn)/*{{{*/
		{
			/*
					; xor al,al
					; mov edi, ?
					cld
					mov ecx, -1
					repne scasb
					mov eax, ecx
					not eax
					dec eax

					-> 

					eax = strlen(edi)	; assumes al is zero on entry
			*/
			insn_vector idiom;
			if (!GetInstructions(6, idiom))
				return false;

			// We already know that the first operation is CLD
			
			if (NN_mov == idiom[1].itype &&
					OperandIsRegister(idiom[1], 0, REG_CX) &&
					OperandIsImmediate(idiom[1], 1, 0xffffffff) &&
					NN_scas == idiom[2].itype &&
					NN_mov == idiom[3].itype &&
					OperandIsRegister(idiom[3], 0, REG_AX) &&
					OperandIsRegister(idiom[3], 1, REG_CX) &&
					NN_not == idiom[4].itype &&
					OperandIsRegister(idiom[4], 0, REG_AX) &&
					NN_dec == idiom[5].itype &&
					OperandIsRegister(idiom[5], 0, REG_AX)
				)
			{
				msg("%p Found strlen idiom\n", insn.ea);

				CallExpression* call = new CallExpression( Expression_ptr( new GlobalVariable("strlen") ) );

				call->AddParameter( Expression_ptr( new Register(REG_DI) ) );
				call->SetFinishedAddingParameters();

				Insert(
						new Assignment(
							insn.ea,
							Expression_ptr( new Register(REG_AX) ),
							Expression_ptr(call)
							));

				EraseInstructions(6);
				return true;
			}
			
			return false;
		}/*}}}*/

		bool TryStrcmpWithLiteral(insn_t& insn)/*{{{*/
		{
			/*
					; mov esi, ?
					; mov edi, ?
					; mov ecx, ?
					cld
					xor eax, eax  <->  test eax, 0
					repe cmpsb
					jz ?					; optional
					sbb eax, eax	; optional
					or al, 1			; optional
			*/

			insn_vector idiom;
			if (!GetInstructions(4, idiom))
				return false;

			// We already know that the first operation is CLD
			if ((
						(NN_xor == idiom[1].itype && 
						 OperandIsRegister(idiom[1], 0, REG_AX) &&
						 OperandIsRegister(idiom[1], 1, REG_AX))
						||
						(NN_test == idiom[1].itype &&
						 OperandIsRegister(idiom[1], 0, REG_AL) &&
						 OperandIsImmediate(idiom[1], 1, 0))
					) &&
					(idiom[2].auxpref & aux_rep) &&
					NN_cmps == idiom[2].itype &&
					dt_byte == idiom[2].Operands[0].dtyp &&
					NN_jz == idiom[3].itype
				 )
			{
				msg("%p Found strcmp with literal idiom\n", insn.ea);
				/*for (int i = 0; i < 5; i++)
				{
					DumpInsn(idiom[i]);
				}*/

				CallExpression* call = new CallExpression( Expression_ptr( new GlobalVariable("strncmp") ) );

				call->AddParameter( Expression_ptr( new Register(REG_DI) ) );
				call->AddParameter( Expression_ptr( new Register(REG_SI) ) );
				call->AddParameter( Expression_ptr( new Register(REG_CX) ) );
				call->SetFinishedAddingParameters();

				if (NN_sbb == idiom[4].itype &&
						OperandIsRegister(idiom[4], 0, REG_AX) &&
						OperandIsRegister(idiom[4], 1, REG_AX) &&
						NN_or == idiom[5].itype &&
						OperandIsRegister(idiom[5], 0, REG_AL) &&
						OperandIsImmediate(idiom[5], 1, 1))
				{
					Insert(
							new Assignment(
								insn.ea,
								Expression_ptr( new Register(REG_AX) ),
								Expression_ptr(call)
								));
					EraseInstructions(6);
				}
				else
				{
					Insert(new ConditionalJump(
									insn.ea,
									Expression_ptr(new BinaryExpression(
											Expression_ptr(call), 
											"==",
											NumericLiteral::Create(0)
											)),
									FromOperand(idiom[3], 0)
									));
					EraseInstructions(4);
				}
				
				return true;
			}
			
			return false;
		}/*}}}*/

		bool TryCdqIdiv(insn_t& insn)/*{{{*/
		{
			/*
					cdq
					idiv  ecx

					-> 

					eax = eax / ecx
					edx = eax % ecx
			*/
			insn_vector idiom;
			if (!GetInstructions(2, idiom))
				return false;

			// We already know that the first operation is CDQ
			
			if (NN_idiv == idiom[1].itype)
			{
				//msg("%p Found cdq/idiv idiom\n", insn.ea);

				// the following div will be handled on the next iteration

				Erase(Iterator());
				return true;
			}
			
			return false;
		}/*}}}*/

#if 0
		bool TryXchgMov(insn_t& insn)/*{{{*/
		{
			/*
					xchg al, ah
					mov [esi+4], ax

					-> 

					*(esi+4) = ah;
					*(esi+5) = al;
			*/
			insn_vector idiom;
			if (!GetInstructions(2, idiom))
				return false;

			// We already know that the first operation is XCHG
			
			if (OperandIsRegister(idiom[0], 0, REG_AL) &&
					OperandIsRegister(idiom[0], 1, REG_AH) &&
					NN_mov  == idiom[1].itype &&
					o_displ == idiom[1].Operands[0].type &&
					dt_word == idiom[1].Operands[0].dtyp &&
					0 == idiom[1].Operands[0].value &&
	 				OperandIsRegister(idiom[1], 1, REG_AX)
					)
			{
				msg("%p Maybe found xchg/mov idiom\n", insn.ea);

				// *(reg+x) = ah
				Insert(new Assignment(
							insn.ea,
							FromOperand(idiom[1], 0),
							FromOperand(idiom[0], 1)));

				// (*reg+x+1) = al
				idiom[1].Operands[0].addr++;
				Insert(new Assignment(
							insn.ea,
							FromOperand(idiom[1], 0),
							FromOperand(idiom[0], 0)));

				DumpInsn(idiom[0]);
				DumpInsn(idiom[1]);

				EraseInstructions(2);
				return true;
			}
			
			return false;
		}/*}}}*/
#endif

		bool TryBorlandClass(insn_t& insn)/*{{{*/
		{
			insn_vector idiom;
			if (!GetInstructions(2, idiom))
				return false;

			// We know that the first instruction is MOV
			if (o_reg   == idiom[0].Operands[0].type &&
					o_imm   == idiom[0].Operands[1].type &&
					NN_mov  == idiom[1].itype &&
					o_reg   == idiom[1].Operands[1].type &&
					idiom[0].Operands[0].reg == idiom[1].Operands[1].reg)
			{
				ea_t vtbl = idiom[0].Operands[1].value;

				flags_t vtbl_flags = getFlags(vtbl);
				if (isData(vtbl_flags))
				{
					msg("%p Possible Borland class here\n", insn.ea);
				
					for(;;)
					{
						if (vtbl != idiom[0].Operands[1].value && hasRef(getFlags(vtbl)))
						{
							break;
						}
						
						ea_t offset = get_long(vtbl);
						if (0 == offset || 0xffffffff == offset)
							break;
			
						flags_t flags = getFlags(offset);

						if (isFunc(flags))
						{
							//msg("Function: %p\n", offset);
						}
						else if (isStruct(flags))
						{
							ushort tpName = get_word(offset + 6);
							ea_t name_offset = offset + tpName;
							if (isASCII(get_item_flag(BADADDR, 0, name_offset, 0)))
							{
								ulong type = get_str_type(name_offset);
                                std::string name =  StringLiteral::GetString(name_offset, type);
								msg("Name: \"%s\"\n", name.c_str());
							}
							else
							{
								msg("Unknown struct: %p\n", offset);
							}
						}
						else
						{
							msg("%p Unknown", vtbl);
						}

						vtbl += 4;
					}
				}
			}
	
			return false;
		}/*}}}*/
		
		void OnCall(insn_t& insn)/*{{{*/
		{
			Expression_ptr e;

#if 1
			netnode n("$ vmm functions");
			// get the callee address from the database
			ea_t callee = n.altval(insn.ea)-1;

			if (BADADDR != callee)
			{
				e = CreateGlobalCodeLabel(callee);
			}
#endif

			if (!e.get())
			{
				e = FromOperand(insn, 0);
			}

			// Borland C++ special
			if (e->IsType(Expression::GLOBAL))
			{
				GlobalVariable* global = static_cast<GlobalVariable*>(e.get());

				if (global->Name() == "@__InitExceptBlockLDTC")
				{
					// TODO: Get EAX from previous instruction...
				}
			}

			CallExpression* call = new CallExpression(e);

			if (call->IsCdecl())
			{
				Instruction_list::iterator next_item = ++Iterator();
				insn_t next;

				if (next_item != Instructions().end() && 
						LowLevel::Insn(*next_item, next))
				{
					/*
						 call ?
						 pop cx
						 pop cx   ; optional, same register again
						 */
					if (NN_pop == next.itype &&
							o_reg == next.Operands[0].type && 
							REG_BP != next.Operands[0].reg)
					{
						//msg("%p found idiom: call/pop\n", insn.ea);
						Erase(next_item);

						int pop_count = 1;
						unsigned short reg = next.Operands[0].reg;

						next_item++;
						if (next_item != Instructions().end() && 
								LowLevel::Insn(*next_item, next))
						{
							if (NN_pop == next.itype &&
									OperandIsRegister(next, 0, reg))
							{
								Erase(next_item);
								pop_count++;
							}
						}
						
						// This is a POP right after a CALL
						// Assume it clears the stack after a one-parameter C-style call
						call->ParameterCountFromCall(pop_count);
					}

					/*
					 * call ?
					 * add sp, ?
					 */
					else if (NN_add ==         next.itype &&
									 OperandIsRegister(next, 0, REG_SP) &&
							     o_imm ==          next.Operands[1].type)
					{
						//msg("%p found idiom: call/add sp\n", insn.ea);
						int shift = -1;

						if (dt_word == next.Operands[0].dtyp)
							shift = 1;
						else if (dt_dword == next.Operands[0].dtyp)
							shift = 2;	
						else
							msg("%p Unexpected word size\n", next.ea);

						if (shift >= 0)
						{
							if (next.Operands[1].value > 0x100)
							{
								msg("%p Error! Very large or negative stack change: %i\n", 
										next.ea,
										next.Operands[1].value);
							}
							else
							{
								call->ParameterCountFromCall(next.Operands[1].value >> shift);
								Erase(next_item);
							}
						}
					}
                    else {
                        msg("WARNING: unhandled call instruction\n");
                    }
				}
			}

			Expression_ptr result;
/*			if (call->DataType().IsVoid())
				result.reset(new Dummy());
			else*/
			{
				// TODO: handle return in DX:AX and only AL too
				result.reset(new Register(REG_AX));
			}

			Replace(new Assignment(
						insn.ea, 
						result, 
						Expression_ptr(call)));
		}/*}}}*/

		void OnNeg(insn_t& insn)/*{{{*/
		{
			if (TryNegSbb(insn))
				return;

			mFlagUpdate = insn;
			mFlagUpdateItem = Replace(
					new Assignment(
						insn.ea,
						FromOperand(insn, 0),
						Expression_ptr(new UnaryExpression(
								"-",
								FromOperand(insn, 0)))));
		}/*}}}*/

		void OnAnd(insn_t& insn)/*{{{*/
		{
			if (o_imm == insn.Operands[1].type && 
					0     == insn.Operands[1].value)
			{
				// AND x, 0  ->  x = 0
				Replace(new Assignment(
							insn.ea,
							FromOperand(insn, 0),
							NumericLiteral::Create(0)));
			}
			else
			{
				mFlagUpdate = insn;
				mFlagUpdateItem = Replace( AssignFromBinaryExpression(insn, "&") );
			}
		}/*}}}*/

		void OnLowLevelPush(insn_t& insn)/*{{{*/
		{
			if (TryProlog(insn))
				return;

			if (TryPushPop(insn))
				return;

			Replace( new Push(insn.ea, FromOperand(insn, 0)) ); 
		}/*}}}*/

		void ReplaceFromFlagUpdate(insn_t& insn, const char* operation, /*{{{*/
				Signness signness = UNKNOWN_SIGN)
		{
#if 0
			TypeInformation data_type;
			data_type.MakeInt(signness);
#endif
			
			Replace(
					new ConditionalJump(
						insn.ea,
						Expression_ptr(new BinaryExpression(
								FromOperand(mFlagUpdate, 0/*, &data_type*/),
								operation,
								NumericLiteral::Create(0)
								)),
						FromOperand(insn, 0)
						)
					);
		}/*}}}*/

		void OnConditionalJump(insn_t& insn, const char* operation, /*{{{*/
				Signness signness = UNKNOWN_SIGN)
		{
			switch (mFlagUpdate.itype)
			{
				case NN_null:
					msg("%p Error! Conditional jump but no flags set!\n", insn.ea);
					return;

				case NN_dec:
				case NN_add:
				case NN_sub:
					if (NN_jz == insn.itype || NN_jnz == insn.itype ||
							NN_js == insn.itype || NN_jns == insn.itype)
					{
						/**
							dec eax
							jz ?
							*/
						ReplaceFromFlagUpdate(insn, operation, signness);
#if 0
						Replace(
								new ConditionalJump(
									insn.ea,
									Expression_ptr(new BinaryExpression(
											FromOperand(mFlagUpdate, 0, &data_type), 
											operation,
											NumericLiteral::Create(0)
											)),
									FromOperand(insn, 0)
									)
								);
#endif
					}
					else
					{
						msg("%p Conditional jump after dec/sub but not jz/jnz. Flag update:\n", insn.ea);
						DumpInsn(mFlagUpdate);
					}
					return;

				case NN_cmp:
					Replace( CreateConditionalJump(mFlagUpdate, insn, operation) );
					return;

				case NN_or:
					if ((NN_jz == insn.itype || NN_jnz == insn.itype) &&
							Equals(mFlagUpdate.Operands[0], mFlagUpdate.Operands[1]))
					{
						msg("%p jz/jnz after or-with-self\n", insn.ea);
						ReplaceFromFlagUpdate(insn, operation, signness);
						Erase(mFlagUpdateItem);
					}
					return;
					
				case NN_test:
					if (Equals(mFlagUpdate.Operands[0], mFlagUpdate.Operands[1]))
					{
						/*
						  	test eax, eax
								jnz ?

								->

								if (eax != 0) goto ?
						*/
						ReplaceFromFlagUpdate(insn, operation, signness);
#if 0
						Replace(
								new ConditionalJump(
									insn.ea,
									Expression_ptr(new BinaryExpression(
											FromOperand(mFlagUpdate, 0, &data_type), 
											operation,
											NumericLiteral::Create(0)
											)),
									FromOperand(insn, 0)
									)
								);
#endif
						return;
					}
			}

			msg("%p Conditional jump. Flag update:\n", insn.ea);
			DumpInsn(mFlagUpdate);
		}/*}}}*/

		void OnXor(insn_t& insn)/*{{{*/
		{
			mFlagUpdate = insn;

			if (Equals(insn.Operands[0], insn.Operands[1]))
			{
				if (TryXorCmpSet(insn))
					return;
				
				// XOR AX, AX  ->  AX = 0
				mFlagUpdateItem = Replace(new Assignment(
							insn.ea,
							FromOperand(insn, 0),
							Expression_ptr(new NumericLiteral(0))));
			}
			else
			{
				mFlagUpdateItem = Replace( AssignFromBinaryExpression(insn, "xor") );
			}
		}/*}}}*/

		void OnSet(insn_t& insn, const char* operation)/*{{{*/
		{
			switch (mFlagUpdate.itype)
			{
				case NN_null:
					msg("%p Error! Conditional jump but no flags set!\n", insn.ea);
					return;

				case NN_cmp:
					Replace( new Assignment(
								insn.ea,
								FromOperand(insn, 0),
								CreateCondition(mFlagUpdate, operation) 
								));
					break;
				
				default:
					msg("%p Set. Flag update:\n", insn.ea);
					DumpInsn(mFlagUpdate);
					break;
			}

		}/*}}}*/

		void OnTest(insn_t& insn)/*{{{*/
		{
			mFlagUpdate = insn;
			mFlagUpdateItem = Instructions().end();
			EraseInstructions(1);
		}/*}}}*/

		/** used for LEA, MOV, MOVSX, MOVZX */
		void OnMov(insn_t& insn, Signness signness = UNKNOWN_SIGN)/*{{{*/
		{
			/*if (insn.ea == 0x102D5)
			{
				DumpInsn(insn);
				insn_t tmp = Instruction::GetLowLevelInstruction(insn.ea);
				DumpInsn(tmp);
			}*/
			
			if (UNKNOWN_SIGN == signness)
			{
				Replace(new Assignment(
							insn.ea,
							FromOperand(insn, 0),
							FromOperand(insn, 1)));
			}
			else
			{
#if 0
				TypeInformation data_type;
				data_type.MakeInt(signness);
#endif
				Replace(new Assignment(
							insn.ea,
							FromOperand(insn, 0/*, &data_type*/),
							FromOperand(insn, 1/*, &data_type*/)));
			}
		}/*}}}*/

		void OnDiv(insn_t& insn, Signness signness = UNKNOWN_SIGN)/*{{{*/
		{
			// First modulus, then divide, because divide redefined eax
			Insert(
					new Assignment(
						insn.ea,
						Register::Create(REG_DX),
						Expression_ptr(new BinaryExpression(
								FromOperand(insn, 0),
								"%",
								FromOperand(insn, 1)))));
			Insert( AssignFromBinaryExpression(insn, "/") );
			Erase(Iterator());
		}/*}}}*/

		void OnMul(insn_t& insn, Signness signness = UNKNOWN_SIGN)/*{{{*/
		{
#if 0
			Insert(
					new Assignment(
						insn.ea,
						Expression_ptr(new BinaryExpression(
								Register::Create(REG_DX), 
								":",
								Register::Create(REG_AX))
							),
						Expression_ptr(new BinaryExpression(
								FromOperand(insn, 0), 
								"*",
								FromOperand(insn, 1))
							)
						)
					);
#else
			msg("%p Warning! Desquirr does not handle multiplication results that are > 32 bit\n", insn.ea);
			Insert( AssignFromBinaryExpression(insn, "*") );
#endif
			Erase(Iterator());
		}/*}}}*/

		void OnCld(insn_t& insn)/*{{{*/
		{
			if (TryStrlen(insn))
				return;

			if (TryMemcpy4(insn))
				return;

			if (TryStrcmpWithLiteral(insn))
				return;

			DumpInsn(insn);
		}/*}}}*/

		void OnCdq(insn_t& insn)/*{{{*/
		{
			if (TryCdqIdiv(insn))
				return;

			DumpInsn(insn);
		}/*}}}*/
	
		void OnXchg(insn_t& insn)/*{{{*/
		{
			if (o_reg == insn.Operands[0].type &&
					o_reg == insn.Operands[1].type &&
					insn.Operands[0].dtyp == insn.Operands[1].dtyp)
			{
				// xchg ah, al -> bswap_16(ax)
				if (dt_byte == insn.Operands[0].dtyp &&
						(insn.Operands[0].reg & 3) == (insn.Operands[1].reg & 3))
				{
					CallExpression* call = new CallExpression( Expression_ptr( new GlobalVariable("bswap_16") ) );

					call->AddParameter( Expression_ptr( new Register(REG_AX) ) );
					call->SetFinishedAddingParameters();

					Insert(
							new Assignment(
								insn.ea,
								Expression_ptr( new Register(REG_AX) ),
								Expression_ptr(call)
								));

					Erase(Iterator());
					return;
				}
			}

			DumpInsn(insn);
		}/*}}}*/
		
		bool OnSwitchInfo(insn_t& insn, switch_info_t& si)/*{{{*/
		{
			if (NN_jmpni == insn.itype &&
					o_mem    == insn.Operands[0].type &&
					si.jumps == insn.Operands[0].addr &&
					insn.Operands[0].hasSIB &&
					(insn.Operands[0].sib & 0xff) == 0x85)
			{
				// Erase instructions in switch header
				for (Instruction_list::iterator item = Iterator(); 
						(**item).Address() >= si.startea;
						item--)
				{
					Erase(item);
				}

				int i = 0;
				ulong address = get_long(si.jumps);

				// Find case statements
				for (Instruction_list::iterator item = Iterator(); 
						item != Instructions().end();
						item++)
				{
					if ((**item).Address() == address &&
							(**item).IsType(Instruction::LABEL))
					{
						//msg("%p case %i statement here\n", address, i);
						Erase(item);

						Instructions().insert(item, 
								Instruction_ptr(new Case(address, i)));

						if (++i == si.ncases)
							break;
						
						address = get_long(si.jumps + 4*i);
					}
				}

				Insert(new Switch(
							si.startea, 
							Register::Create(REG_AX)/*,
							si*/));

				return true;
			}
			else
			{
				msg("%p Unexpected type of switch\n", insn.ea);
				DumpInsn(insn);
				msg("%p switch_info:", insn.ea);

				msg(" flags=%p",  si.flags);
				msg(" ncases=%i", si.ncases);
				msg(" jumps=%p",  si.jumps);
				if (si.flags & SWI_SPARSE)
					msg(" values=%p", si.values);
				else
					msg(" lowcase=%i", si.lowcase);
				msg(" defjump=%p",  si.defjump);
				msg(" startea=%p",  si.startea);
				msg("\n");

				return false;
			}
		}/*}}}*/
		
		insn_t mFlagUpdate;
		Instruction_list::iterator mFlagUpdateItem;

};/*}}}*/



void IdaX86::FillList(func_t* function, Instruction_list& instructions)/*{{{*/
{
	X86Analysis lla;
	lla.AnalyzeFunction(function, instructions);
}/*}}}*/

static const char* const mName_x86_16bit[] = 
{
	"ax","cx","dx","bx","sp","bp","si","di",
	"al","cl","dl","bl","ah","ch","dh","bh"
};

static const char* const mName_x86_32bit[] = 
{
	"eax","ecx","edx","ebx","esp","ebp","esi","edi",
	"al","cl","dl","bl","ah","ch","dh","bh"
};

std::string IdaX86::RegisterName(RegisterIndex index) const/*{{{*/
{
	if (index >= 0)
	{
		if (mIs32Bit && (index < (sizeof(mName_x86_32bit)/sizeof(char*)) ))
			return mName_x86_32bit[index];
		else if (index < (sizeof(mName_x86_16bit)/sizeof(char*)))
			return mName_x86_16bit[index];
	}
	
	std::ostringstream os;
	os << boost::format("REGISTER_%d") % index;
	return os.str();
}/*}}}*/

void IdaX86::TryBorlandThrow(DataFlowAnalysis* /*analysis*/, /*{{{*/
		Assignment* /*assignment*/)
{
#if 0
	if (assignment->Second()->IsType(Expression::CALL))
	{
		CallExpression* call = static_cast<CallExpression*>(assignment->Second().get());

		// 1 function + 9 parameters
		if (call -> SubExpressionCount() == 10 &&
				call->SubExpression(0)->IsType(Expression::GLOBAL) &&
				call->SubExpression(1)->IsType(Expression::GLOBAL) &&
				call->SubExpression(2)->IsType(Expression::UNARY_EXPRESSION))
		{
			GlobalVariable* global = static_cast<GlobalVariable*>(call->SubExpression(0).get());

			if (global->Name() == "@_ThrowExceptionLDTC$qpvt1t1t1uiuiuipuct1")
			{
				// This seems to be a Borland C++ throw instruction
				
				message("%p Borland C++ throw instruction\n", Instr()->Address());
				
				//
				// Parameters:
				//
				// 1: RTTI data about the type we throw
				// 2: Address of the exception value/pointer we throw
				// 3: 0
				// 4: 0 or pointer to constructor
				// 5: 0 or 1
				// 6: 0
				// 7: 0
				// 8: 0
				// 9: 0 or some value
				//

				GlobalVariable* rtti = 
					static_cast<GlobalVariable*>(call->SubExpression(1).get());
				Addr offset = rtti->Address();

				UnaryExpression* exception_address = 
					static_cast<UnaryExpression*>(call->SubExpression(2).get());
				
				if (0 == strcmp(exception_address->Operation(), "&") &&
						INVALID_ADDR != offset)
				{
					flags_t flags = getFlags(offset);
					flags_t type_flags;
					Addr type_offset = offset + get_word(offset + 6);

					if (isStruct(flags))
					{
						type_flags = get_item_flag(INVALID_ADDR, 0, type_offset, 0);
					}
					else
					{
						if (isData(flags))
						{
							do_unknown(type_offset, true);
						}
						
						// TODO: convert to struct, not just string
						make_ascii_string(type_offset, 0, ASCSTR_C);
						type_flags = getFlags(type_offset);
					}

					if (isASCII(type_flags))
					{
						ulong string_type = get_str_type(type_offset);
                        std::string data_type = 
							StringLiteral::GetString(type_offset, string_type);

						Insert(
								new Throw(
									Instr()->Address(), 
									exception_address->Operand(), 
									data_type));
						
						Erase(Iterator());
					}
				}
			}

		}
		else if (call->SubExpressionCount() == 3 &&
				call->SubExpression(0)->IsType(Expression::GLOBAL))
		{
			GlobalVariable* global = static_cast<GlobalVariable*>(call->SubExpression(0).get());

			if (global->Name() == "@_ReThrowException$quipuc")
			{
				message("%p Borland C++ rethrow instruction\n", Instr()->Address());
				Insert( new Throw( Instr()->Address() ) );
				Erase(Iterator());
			}
		}

	}
#endif
}/*}}}*/


