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
// $Id: ida-arm.cpp,v 1.6 2007/01/30 09:48:28 wjhengeveld Exp $
#include "idainternal.hpp"
#include "ida-arm.hpp"
#include "analysis.hpp"
#include "ida-arm2.hpp"

std::string IdaArm::RegisterName(RegisterIndex index) const/*{{{*/
{
	char buffer[16];
	switch (index)
	{
		case IdaArm::SP : return "SP"; 
		case IdaArm::LR : return "LR";
		case IdaArm::PC : return "PC";
		case IdaArm::CPSR : return "CPSR";
		case IdaArm::CPSR_flg: return "CPSR_flg";
		case IdaArm::SPSR: return "SPSR";
		case IdaArm::SPSR_flg: return "SPSR_flg";

			// helper register to deal with condition codes. 
			// Should be replaced by either the above status registers
			// or specific flags
		case IdaArm::Cond: return "Cond";

			// helper register to perform the SWP instruction
		case IdaArm::Temp: return "Temp";

		default:
			qsnprintf(buffer, sizeof(buffer), "R%i", index);
			break;
	}
	return std::string(buffer);
}/*}}}*/

const char* const IdaArm::ConditionOp(int condition)/*{{{*/
{
	switch (condition)
	{
		case cEQ: return "=="; // 0000 Z                        Equal
		case cNE: return "!="; // 0001 !Z                       Not equal
		case cCS: return ">="; // 0010 C                        Unsigned higher or same
		case cCC: return "<";  // 0011 !C                       Unsigned lower
		case cMI: return "<";  // 0100 N                        Negative
		case cPL: return ">="; // 0101 !N                       Positive or Zero
		case cVS: return ">="; // 0110 V                        Overflow
		case cVC: return ">="; // 0111 !V                       No overflow
		case cHI: return ">";  // 1000 C & !Z                   Unsigned higher
		case cLS: return "<="; // 1001 !C & Z                   Unsigned lower or same
		case cGE: return ">="; // 1010 (N & V) | (!N & !V)      Greater or equal
		case cLT: return "<";  // 1011 (N & !V) | (!N & V)      Less than
		case cGT: return ">";  // 1100 !Z & ((N & V)|(!N & !V)) Greater than
		case cLE: return "<="; // 1101 Z | (N & !V) | (!N & V)  Less than or equal
		case cAL:              // 1110 Always
		case cNV:              // 1111 Never
		default:
			msg("ERROR: unexpected condition call\n");
			return "ERROR";
	}
}/*}}}*/

void IdaArm::DumpInsn(insn_t& insn)/*{{{*/
{
	msg("ea=%p, itype=\"%s\" (%i)", insn.ea, ::ph.instruc[insn.itype].name, insn.itype);

	if (insn.auxpref) msg(", auxpref=%p", insn.auxpref);
	msg(", condition=%X", insn.segpref);

	msg("\n");
	
	for (int i = 0; i < UA_MAXOP; i++)
	{
		op_t& op = insn.Operands[i];
		
		if (op.type == o_void)
			break;

	
		msg("  Operands[%i]={type=%s, dtyp=%i, reg/phrase=%s/%i", //, value=%i, addr=%08x",
				i, GetOptypeString(op), op.dtyp, 
				RegisterName(op.reg).c_str(),
				op.reg/*, op.value, op.addr*/);

		if (op.value) msg(", value=%i", op.value);
		if (op.addr) msg(", addr=%08x", op.addr);

		if (o_idpspec2 == op.type)
		{
			// This is a register list
			bool first = true;
			msg(", registers={");
			for (int i = 0; i < NR_NORMAL_REGISTERS ; i++)
				if (op.specval & (1 << i))
				{
					if (first)
						first=false;
					else
						msg(",");
					msg("%s", RegisterName(i).c_str());
				}
			msg("}");
		}
		else if (op.specval)
			msg(", specval=%p", op.specval);
		if (op.specflag1)
			msg(", specflag1=%02x", op.specflag1);
		if (op.specflag2)
			msg(", specflag2=%02x", op.specflag2);
		if (op.specflag3)
			msg(", specflag3=%02x", op.specflag3);
		if (op.specflag4)
			msg(", specflag4=%02x", op.specflag4);
		msg("}\n");
	}
}/*}}}*/

/*{{{ Expression_ptr FromOperand */
static Expression_ptr FromOperand(insn_t& insn, int operand/*,
				TypeInformation* type = NULL*/)
{
	Expression_ptr result;
	flags_t flags = ::getFlags(insn.ea);

	// BUG: isStkvar==true with operand==1  also can mean operand 2 is stkvar.
	// this causes 'add r0, sp, #0x10'  to be incorrectly processed
	if ( ::isStkvar(flags, operand) )
	{
		result = ::CreateStackVariable(insn, operand);
		if (result)
			return result;
	}

	op_t op = insn.Operands[operand];
	
	switch (op.type)
	{
		case o_idpspec0: // ARM module specific: o_shreg
			// reg             - register
			// specflag2       - shift type
			// specflag1       - shift register
			// value           - shift counter
			//msg("%p: idpspec0 detected!\n",insn.ea);

			if (op.specflag2==LSL && op.value==0)
			{
				result.reset( new Register(op.reg) );
			}
			else {
				// LSL : PSR.C= high bit, <<
				// LSR : PSR.C= low bit, >>
				// ASR : PSR.C= low bit, >>, highbit=oldhighbit ( signed )
				// ROR : PSR.C= low bit, >>, highbit=oldlowbit
				// RRX : PSR.C= low bit, >>, highbit= old PSR.C
				result.reset( new BinaryExpression(
						Expression_ptr( new Register(op.reg)),
						op.specflag2==LSL ? "<<" : ">>",
						Expression_ptr( new NumericLiteral(
								op.specflag2==RRX ? 1 : op.value))
					));
			}
			break;

		case o_displ:
			if (op.addr) {
				result.reset( new BinaryExpression(
						Expression_ptr( new Register(op.reg)),
						"+",
						Expression_ptr( new NumericLiteral(op.addr))));
			} else result.reset( new Register(op.reg) );
			result.reset( new UnaryExpression("*", result));
			break;
			
		case o_reg:
			result.reset( new Register(op.reg) );
			break;

		case o_imm:
			result.reset( new NumericLiteral(op.value) );
			break;

		case o_mem:
			{
				//msg("entering o_mem decoding: %d/%d\n", has_ti0(insn.ea), has_ti1(insn.ea));
				ea_t arg = insn.Operands[operand].addr;
				flags_t flags = getFlags(arg);
				//msg("addr flags: %0lx\n",flags);
				if (isOff0(flags)) {
					ea_t ptr = get_long(arg);
					flags = getFlags(ptr);
					//msg("flags of ptr: %0lx\n", flags);
					if (isASCII(flags)) {
						result = StringLiteral::CreateFrom(ptr);
					}
					else
					{
						insn_t insxx= insn;
						insxx.Operands[operand].addr= ptr;
						// XXX: maybe use & operator for result?
						result = CreateGlobalVariable(insxx, operand);
						if ( !result.get() )
						{
							msg("%p no name found for for o_mem operand %i\n", insn.ea, operand);
						}
					}
				} else {
					long value = get_long(arg);
					//msg("not offset\n");
					result.reset(new NumericLiteral(value));
				}
			}
			break;

		case o_near:
			result = CreateVariable(insn, operand);
			if (!result.get())
			{
				msg("%p no name found for for o_near operand %i\n", 
						insn.ea, operand);
			}
			break;

		case o_idpspec2: // ARM module specific: o_reglist
			// reglist is in op.specval
			// specflag1 = PSR & force user bit
			//  LDMxx R, {list}^  ... ld/st usermode regs.
			msg("%p type o_idpspec2 for operand %i should not be handled in FromOperand()\n", 
					insn.ea, operand);
			break;

		case o_phrase:
			// second register in specflag1
			// shifttype in specflag2
			// shiftcount in shcnt
			result.reset( new BinaryExpression(
					Expression_ptr( new Register(op.reg)),
					"+",
					Expression_ptr( new Register(op.specflag1))));
			result.reset( new UnaryExpression("*", result));
			break;

		case o_idpspec1: // ARM module specific: o_tworeg - MLA
			// reg       = firstreg
			// specflag1 = secreg
			msg("ERROR: MLA o_tworeg should handled in OnMLA\n");
			break;
		case o_idpspec3: // ARM module specific: o_creglist - CDP
			// reg = CRd
			// specflag1 = CRn
			// specflag2 = CRm
			break;
		case o_idpspec4: // ARM module specific: o_creg - LDC/STC
			// specflag1 = procnum
			break;

		default:
			msg("%p unexpected type for operand %i\n", insn.ea, operand);
			break;
	}
	if (!result) 
		msg("ERROR: FromOperand(type=%d, i=%d)  -> NULL\n", op.type, operand);
	return result;
}/*}}}*/

bool OperandIsRegister(insn_t& insn, int operand)/*{{{*/
{
	return 
		o_reg == insn.Operands[operand].type;
}/*}}}*/

bool OperandIsImmediate(insn_t& insn, int operand)/*{{{*/
{
	return 
		o_imm == insn.Operands[operand].type;
}/*}}}*/

class ArmAnalysis : public Analysis/*{{{*/
{
	public:

		void AnalyzeFunction(func_t* function, Instruction_list& instructions)/*{{{*/
		{
			Instructions(&instructions);
			MakeLowLevelList(function);

			//memset(&mFlagUpdate, 0, sizeof(mFlagUpdate));
			//mFlagUpdateItem = Instructions().end();

			AnalyzeInstructionList();
			Instructions(NULL);
		}/*}}}*/

	
		void MakeLowLevelList(func_t* function)/*{{{*/
		{
			Instructions().clear();

			for(ea_t address = function->startEA; 
					address < function->endEA;
					address = get_item_end(address))
			{
				flags_t flags = getFlags(address);

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
					else if (isData(flags)) {
						continue;
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

				if (hasRef(flags) /*|| has_any_name(flags)*/)
				{
					int index;
					std::string name= GetLocalCodeLabel(address, &index);
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

				Instructions().push_back( Instruction_ptr(
							new LowLevel( GetLowLevelInstruction(address) )
							));
			}
		}/*}}}*/

		void DumpInsn(insn_t& insn)
		{
			static_cast<IdaPro&>(Frontend::Get()).DumpInsn(insn);
		}

		const char* const NotConditionOp(int condition)/*{{{*/
		{
			switch (condition)
			{
				case cEQ:					// 0000 Z                        Equal
					condition = cNE;
					break;
				case cNE:					// 0001 !Z                       Not equal
					condition = cEQ;
					break;
				case cCS:					// 0010 C                        Unsigned higher or same
					condition = cCC;
					break;
				case cCC:					// 0011 !C                       Unsigned lower
					condition = cCS;
					break;
				case cMI:					// 0100 N                        Negative
					condition = cPL;
					break;
				case cPL:					// 0101 !N                       Positive or Zero
					condition = cMI;
					break;
				case cVS:					// 0110 V                        Overflow
					condition = cVC;
					break;
				case cVC:					// 0111 !V                       No overflow
					condition = cVS;
					break;
				case cHI:					// 1000 C & !Z                   Unsigned higher
					condition = cLS;
					break;
				case cLS:					// 1001 !C & Z                   Unsigned lower or same
					condition = cHI;
					break;
				case cGE:					// 1010 (N & V) | (!N & !V)      Greater or equal
					condition = cLT;
					break;
				case cLT:					// 1011 (N & !V) | (!N & V)      Less than
					condition = cGE;
					break;
				case cGT:					// 1100 !Z & ((N & V)|(!N & !V)) Greater than
					condition = cLE;
					break;
				case cLE:					// 1101 Z | (N & !V) | (!N & V)  Less than or equal
					condition = cGT;
					break;
				case cAL:					// 1110 Always
					condition = cNV;
				case cNV:					// 1111 Never
					condition = cAL;
			}
			return IdaArm::ConditionOp(condition);
		}

		void InsertLabel(insn_t& insn)
		{
			ea_t ea = get_item_end(insn.ea);
			Instruction_ptr label= CreateLocalCodeLabel(ea);
			if (label.get())
				Insert(label);
		}

		void InsertConditional(insn_t& insn)
		{
			int op1, op2;
			std::string name("Cond");

			op_t op = mFlagUpdate.Operands[2];

			if (op.type == o_void) {
				op1 = 0; op2 = 1;
			} else {
				op1 = 1; op2 = 2;
			}

			msg("%p - using conditional: %d \n", insn.ea, insn.segpref);
			Insert(new ConditionalJump(
								insn.ea,
								Expression_ptr(new BinaryExpression(
//										Expression_ptr( new BinaryExpression(
//											FromOperand(mFlagUpdate, op1), 
//											mFlagUpdateOp,
//											FromOperand(mFlagUpdate, op2)
//											)),
										Expression_ptr(new Register(IdaArm::Cond)),
										NotConditionOp(insn.segpref),
										NumericLiteral::Create(0)
										)),
								CreateLocalCodeReference(get_item_end(insn.ea))
								));
		}



		/**
		 * Handle a LowLevel instruction
		 */
		virtual void OnLowLevel(Instruction* lowLevel)/*{{{*/
		{
			insn_t insn = static_cast<LowLevel*>(lowLevel)->Insn();

			// insn.segpref contains the condition code in the arm module.
			if (cNV == insn.segpref)
			{
				msg("%p Warning! Will never execute instruction:\n");
				DumpInsn(insn);
				return;
			}

//		if (cAL != insn.segpref)
//		{
//			msg("%p Condition code= %x:\n", insn.ea, insn.segpref);
//		}
			
			switch (insn.itype)
			{
				case ARM_b:   OnB  (insn); break;
				case ARM_bl:  OnBl (insn); break;
				case ARM_bx:  OnBx (insn); break;

				case ARM_and: OnOperator(insn, "&", 1, 2); break;
				case ARM_eor: OnOperator(insn, "^", 1, 2); break;
				case ARM_sub: OnOperator(insn, "-", 1, 2); break;
				case ARM_rsb: OnOperator(insn, "-", 2, 1); break;
				case ARM_add: 
						if (TryAddSp(insn))
							break;
						if (TryAddMov(insn)) 
							break;
						OnOperator(insn, "+", 1, 2); 
						break;
				case ARM_adc: OnOperator(insn, "+", 1, 2); break;
				case ARM_sbc: OnOperator(insn, "-", 1, 2); break;
				case ARM_rsc: OnOperator(insn, "-", 2, 1); break;
				case ARM_orr: OnOperator(insn, "|", 1, 2); break;
				case ARM_bic: OnBic(insn); break;

				case ARM_movl:
				case ARM_mov:
						if (TryMovBx(insn))
							break;
						OnMov(insn);
						break;
				case ARM_mvn: OnMvn(insn); break;

				case ARM_teq: OnTestOperator(insn, "^"); break;
				case ARM_tst: OnTestOperator(insn, "&"); break;
				case ARM_cmp: OnTestOperator(insn, "-"); break;
				case ARM_cmn: OnTestOperator(insn, "+"); break;

				case ARM_ldrpc:	// both handled by OnLdr
				case ARM_ldr: OnLdr(insn); break;
				case ARM_str: OnStr(insn); break;

				case ARM_ldm: OnLdm(insn); break;
				case ARM_stm: OnStm(insn); break;
				
				case ARM_mrs: OnMov(insn); break;
				case ARM_msr: OnMov(insn); break;

				case ARM_mul: OnOperator(insn, "|", 1, 2); break;
				case ARM_mla: OnMla(insn); break;
//				case ARM_smull: OnSmull(insn); break;
//				case ARM_smlal: OnSmlal(insn); break;
//				case ARM_umull: OnUmull(insn); break;
//				case ARM_umlal: OnUmlal(insn); break;

				case ARM_swp: OnSwp(insn); break;

//				case ARM_swi: OnSwi(insn); break;

//				case ARM_cdp: OnCdp(insn); break;

//				case ARM_ldc: OnLdc(insn); break;
//				case ARM_stc: OnStc(insn); break;

//				case ARM_mrc: OnMrc(insn); break;
//				case ARM_mcr: OnMcr(insn); break;


				// Thumb additional
				case ARM_asr: OnOperator(insn, ">>", 1, 2); break;
				case ARM_lsr: OnOperator(insn, ">>", 1, 2); break;
				case ARM_lsl: 
						if (TryAnd(insn))
							break;
						OnOperator(insn, "<<", 1, 2); 
						break;
				case ARM_ror: OnOperator(insn, ">>", 1, 2); break;

				case ARM_pop: OnPop(insn); break;
				case ARM_push: OnPush(insn); break;

//				case ARM_ldmia: OnLdmia(insn); break;
//				case ARM_stmia: OnStmia(insn); break;

				case ARM_neg: OnNeg(insn); break;

				case ARM_ret: OnRet(insn);break;

				default:
					msg("%p Unhandled instruction\n", insn.ea);
					DumpInsn(insn);
					break;
			}
		}/*}}}*/

		void OnOperator(insn_t& insn, const char* operation, int operand1, int operand2)/*{{{*/
		{
			op_t op = insn.Operands[operand2];

			if (op.type == o_void) {
				operand1 = 0; operand2 = 1;
			}

			if ((insn.auxpref & aux_cond)!=0) {
				msg("%p setting conditional for operator\n", insn.ea);
				mFlagUpdate = insn;
				mFlagUpdateOp = operation;
				mFlagUpdateItem = Instructions().end();
				Insert( new Assignment(
						insn.ea,
						Expression_ptr(new Register(IdaArm::Cond)),
						Expression_ptr(new BinaryExpression(
								::FromOperand(insn, operand1),
								operation,
								::FromOperand(insn, operand2)
								))
						));
			}

			if (insn.segpref != cAL)
				InsertConditional(insn);
			Replace(new Assignment(
						insn.ea,
						::FromOperand(insn, 0),
						Expression_ptr(new BinaryExpression(
								::FromOperand(insn, operand1),
								operation,
								::FromOperand(insn, operand2)
								))
						));

			if (insn.segpref != cAL)
				InsertLabel(insn);
		}/*}}}*/

		void OnTestOperator(insn_t& insn, const char* operation)/*{{{*/
		{
			if (insn.segpref != cAL)
				InsertConditional(insn);
//			EraseInstructions(1);
			mFlagUpdate = insn;
			mFlagUpdateOp = operation;
			mFlagUpdateItem = Instructions().end();

			if (insn.Operands[1].type == o_imm && insn.Operands[1].value == 0) {
				Replace( new Assignment(
					insn.ea,
					Expression_ptr(new Register(IdaArm::Cond)),
					::FromOperand(insn, 0)
					));
			} else {
				Replace( new Assignment(
					insn.ea,
					Expression_ptr(new Register(IdaArm::Cond)),
					Expression_ptr(new BinaryExpression(
							::FromOperand(insn, 0),
							operation,
							::FromOperand(insn, 1)
							))
					));
			}
			if (insn.segpref != cAL)
				InsertLabel(insn);
		}/*}}}*/

		void OnBic(insn_t& insn)/*{{{*/
		{
			if (insn.segpref != cAL)
				InsertConditional(insn);

			Replace(new Assignment(
						insn.ea,
						::FromOperand(insn, 0),
						Expression_ptr(new BinaryExpression(
								::FromOperand(insn, 1),
								"&",
								Expression_ptr(new UnaryExpression(
								"~",
								::FromOperand(insn, 2)))
								))
						));

			if (insn.segpref != cAL)
				InsertLabel(insn);
		}/*}}}*/

		void OnAddSp(insn_t& insn)/*{{{*/
		{
			if (insn.segpref != cAL)
				InsertConditional(insn);

			Replace(new Assignment(
						insn.ea,
						::FromOperand(insn, 0),
						Expression_ptr(new UnaryExpression(
								"&",
								FromOperand(insn, 2)))
			));

			if (insn.segpref != cAL)
				InsertLabel(insn);
		}/*}}}*/

		void OnMov(insn_t& insn)/*{{{*/
		{
			if ((insn.auxpref & aux_cond)!=0) {
				msg("%p setting conditional for MOVS\n", insn.ea);
				mFlagUpdate = insn;
				mFlagUpdateItem = Instructions().end();
				Insert( new Assignment(
						insn.ea,
						Expression_ptr(new Register(IdaArm::Cond)),
						::FromOperand(insn, 1)
						));
			}

			if (insn.segpref != cAL)
				InsertConditional(insn);

			if (insn.Operands[0].type == o_reg && insn.Operands[0].reg == REG_PC) {
				Replace(new Assignment(
						insn.ea,
						Expression_ptr(new Register(0)),
						Expression_ptr(new CallExpression(::FromOperand(insn, 1)))
						));
			} else {
				Replace(new Assignment(
						insn.ea,
						::FromOperand(insn, 0),
						::FromOperand(insn, 1)
						));
			}

			if (insn.segpref != cAL)
				InsertLabel(insn);
		}/*}}}*/

		void OnMvn(insn_t& insn)/*{{{*/
		{
			if (insn.segpref != cAL)
				InsertConditional(insn);

			Replace(new Assignment(
						insn.ea,
						::FromOperand(insn, 0),
						Expression_ptr(new UnaryExpression(
								"~",
								FromOperand(insn, 1)))
			));

			if (insn.segpref != cAL)
				InsertLabel(insn);
		}/*}}}*/

		void OnMla(insn_t& insn)/*{{{*/
		{

			if (insn.Operands[2].type!=o_idpspec1) {
				msg("ERROR: expected MLA op2=o_tworeg\n");
				return;
			}
			op_t op2= insn.Operands[2];
			// reg       = firstreg
			// specflag1 = secreg

			Replace(new Assignment(
						insn.ea,
						::FromOperand(insn, 0),
						Expression_ptr(new BinaryExpression(
								Expression_ptr(new Register(op2.specflag1)),
								"+",
								Expression_ptr(new BinaryExpression(
									::FromOperand(insn, 1),
									"*",
									Expression_ptr(new Register(op2.reg))))
								))
						));
		}/*}}}*/

		void OnNeg(insn_t& insn)
		{
			mFlagUpdate = insn;
			mFlagUpdateOp = "-";
			mFlagUpdateItem = Instructions().end();

			Replace(new Assignment(
						insn.ea,
						::FromOperand(insn, 0),
						Expression_ptr(new UnaryExpression(
								"-",
								FromOperand(insn, 1)))
						));
		}

		void OnB(insn_t& insn)/*{{{*/
		{
			// 
			// Branch
			//

			if (cAL == insn.segpref)
			{
				// Unconditional jump
				Replace(new Jump(insn.ea, ::FromOperand(insn, 0)));
			}
			else
			{
				int op1, op2;
				op_t op = mFlagUpdate.Operands[2];

				if (op.type == o_void) {
					op1 = 0; op2 = 1;
				} else {
					op1 = 1; op2 = 2;
				}
				Replace(new ConditionalJump(
									insn.ea,
									Expression_ptr(new BinaryExpression(
//											Expression_ptr( new BinaryExpression(
//												FromOperand(mFlagUpdate, op1), 
//												mFlagUpdateOp,
//												FromOperand(mFlagUpdate, op2)
//												)),
											Expression_ptr(new Register(IdaArm::Cond)),
											IdaArm::ConditionOp(insn.segpref),
											NumericLiteral::Create(0)
											)),
									::FromOperand(insn, 0)
									));
				
			}
			
		}/*}}}*/

		void OnBl(insn_t& insn)/*{{{*/
		{
			// 
			// Branch with link (function call)
			//
			if (insn.segpref != cAL)
				InsertConditional(insn);
			
			// Result in R0?
			// todo: some functions - like idiv, have result in R0, R1
			// todo: parametercount does not depend on stack with ARM.
			//  convention: R0, R1, R2, R3, [SP], [SP+4], [SP+8], ...
			Replace(new Assignment(
						insn.ea,
						Expression_ptr(new Register(0)),
						Expression_ptr(new CallExpression(::FromOperand(insn, 0)))
						));
							
			if (insn.segpref != cAL)
				InsertLabel(insn);
			
		}/*}}}*/

		void OnBx(insn_t& insn)/*{{{*/
		{
			// 
			// Branch with exchange
			// change ARM <-> THUMB
			//
			
			if (insn.segpref != cAL)
				InsertConditional(insn);
			// BX LR is return

			if (REG_LR == insn.Operands[0].reg) {
				Replace( 
						new Return(insn.ea, Register::Create(0)) 
						);
			} else {
				// Result in R0?
				Replace(new Assignment(
						insn.ea,
						Expression_ptr(new Register(0)),
						Expression_ptr(new CallExpression(::FromOperand(insn, 0)))
						));
			}			
			if (insn.segpref != cAL)
				InsertLabel(insn);
		}/*}}}*/

		void OnLdr(insn_t& insn)/*{{{*/
		{
			if (insn.segpref != cAL)
				InsertConditional(insn);

			if (insn.Operands[1].type == o_displ
					&& insn.Operands[1].reg == REG_SP
					&& insn.Operands[1].addr == 4
					&& (insn.auxpref & (aux_postidx))==aux_postidx) {
				// LDR     PC, [SP],#4
				int regnr= insn.Operands[0].reg;
				if (regnr == REG_PC) {
					// Return
					Replace( new Return(insn.ea, Expression_ptr(new Register(0))) );
				}
				else {
					Replace(new Pop( insn.ea, ::FromOperand(insn, 0) ));
				}
			}
			else if (insn.Operands[0].reg==REG_PC) {
				// jumptable
				message("ERROR - jumptable not yet implemented\n");
				DumpInsn(insn);
			}
			else {
				Replace(new Assignment(
							insn.ea,
							::FromOperand(insn, 0),
							::FromOperand(insn, 1)
							));
			}

			if (insn.segpref != cAL)
				InsertLabel(insn);
		}/*}}}*/

		void OnLdm(insn_t& insn)/*{{{*/
		{
			if (o_reg      != insn.Operands[0].type &&
					o_idpspec2 != insn.Operands[1].type)
			{
				msg("%p Malformed LDM instruction\n", insn.ea);
				DumpInsn(insn);
				return;
			}
			
			if ( (insn.auxpref & aux_postidx)!=0 &&		// means that the W and U bits are set, I hope
					REG_SP == insn.Operands[0].reg)
			{
				//
				// Push a bunch of registers on the stack
				//
				//  LDMFD   SP!, {R4-R7,LR}
				//  post-increment load
				//
				//  but also (without store) 
				//  LDMFD   SP, {R4-R11,SP,PC}
				//
				for (RegisterIndex i = 0; i < IdaArm::NR_NORMAL_REGISTERS ; i++)
					if (insn.Operands[1].specval & (1 << i))
					{
						if (i == IdaArm::PC) { // POP of PC equals return. Implicit return R0
							Insert( new Return( 
									insn.ea,
									Expression_ptr( new Register(0) )));
						} else {
							Insert(new Pop(
									insn.ea,
									Expression_ptr( new Register(i) )));
						}
					}

				Erase(Iterator());
			}
			else if ( (insn.auxpref & (aux_postidx|aux_negoff))==aux_negoff
				&& 11 == insn.Operands[0].reg 
				&& insn.Operands[1].type == o_idpspec2	// reglist
				&& (insn.Operands[1].specval&(1<<13)) // restores SP
					) {
				msg("%p ignoring end of function LDM R11, {..SP..}\n", insn.ea);
			}
			else
			{
				msg("%p Unexpected block store\n", insn.ea);
				DumpInsn(insn);
			}
		}/*}}}*/

		void OnStr(insn_t& insn)/*{{{*/
		{
			if (insn.segpref != cAL)
				InsertConditional(insn);

			if (insn.Operands[1].type == o_displ
					&& insn.Operands[1].reg == REG_SP
					&& insn.Operands[1].addr == -4
					&& (insn.auxpref & (aux_postidx|aux_wback))==aux_wback) {
				// STR     LR, [SP,#-4]!
				Replace(new Push( insn.ea, ::FromOperand(insn, 0) ));
			}
			else {
				Replace(new Assignment(
							insn.ea,
							::FromOperand(insn, 1),
							::FromOperand(insn, 0)
							));
			}

			if (insn.segpref != cAL)
				InsertLabel(insn);
		}/*}}}*/

		void OnStm(insn_t& insn)/*{{{*/
		{
			if (o_reg      != insn.Operands[0].type &&
					o_idpspec2 != insn.Operands[1].type)
			{
				msg("%p Malformed STM instruction\n", insn.ea);
				DumpInsn(insn);
				return;
			}
			
			if ((aux_wbackldm|aux_negoff)== insn.auxpref &&		// means that the W and P bits are set, I hope
					REG_SP == insn.Operands[0].reg)
			{
				//
				// Push a bunch of registers on the stack
				//
				//  STMFD   SP!, {R4-R7,LR}
				//  pre-decrement store
				//
				// note: i is unsigned, there for i< max ; i--
				for (RegisterIndex i = IdaArm::NR_NORMAL_REGISTERS-1 ; i < IdaArm::NR_NORMAL_REGISTERS ; i--)
				{
					if (insn.Operands[1].specval & (1 << i))
					{
						Insert(new Push(
									insn.ea,
									Expression_ptr( new Register(i) )));
					}
				}
				Erase(Iterator());
			}
			else
			{
				msg("%p Unexpected block store", insn.ea);
				DumpInsn(insn);
			}
		}/*}}}*/

		void OnRet(insn_t& insn)
		{
			if (insn.segpref != cAL)
				InsertConditional(insn);
			Replace( 
					new Return(insn.ea, Register::Create(0)) 
					);
			if (insn.segpref != cAL)
				InsertLabel(insn);
		}

		void OnPush(insn_t &insn)
		{
			msg("Enter OnPush\n");
			if (insn.Operands[0].type == o_idpspec2)
			{
				for (RegisterIndex i = 0; i < IdaArm::NR_NORMAL_REGISTERS ; i++)
					if (insn.Operands[0].specval & (1 << i))
					{
						msg("PUSH %d\n",i);
						Insert(new Push(
									insn.ea,
									Expression_ptr( new Register(i) )));
					}

//				Erase(Iterator());
			}
			else
			{
				msg("%p Unknown PUSH type\n", insn.ea);
				DumpInsn(insn);
			}
		}

		void OnPop(insn_t &insn)
		{
			if (insn.Operands[0].type == o_idpspec2)
			{
				for (RegisterIndex i = 0; i < IdaArm::NR_NORMAL_REGISTERS ; i++)
					if (insn.Operands[0].specval & (1 << i))
					{
						if (i == IdaArm::PC) { // POP of PC equals return. Implicit return R0
							Insert( new Return( 
									insn.ea,
									Expression_ptr( new Register(0) )));
						} else {
							Insert(new Pop(
									insn.ea,
									Expression_ptr( new Register(i) )));
						}
					}

				Erase(Iterator());
			}
			else
			{
				msg("%p Unknown PUSH type\n", insn.ea);
				DumpInsn(insn);
			}
		}

		void OnSwp(insn_t &insn)
		{
			if (insn.segpref != cAL)
				InsertConditional(insn);

			// Untested code. Interpreted from ARM manual.

			Insert( new Assignment(
					insn.ea,
					Expression_ptr(new Register(IdaArm::Temp)),
					::FromOperand(insn, 2)
					));
			Insert(new Assignment(
					insn.ea,
					::FromOperand(insn, 2),
					::FromOperand(insn, 1)
					));
			Replace(new Assignment(
					insn.ea,
					::FromOperand(insn, 0),
					Expression_ptr(new Register(IdaArm::Temp))
					));

			if (insn.segpref != cAL)
				InsertLabel(insn);
		}

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

		bool TryAnd(insn_t& insn)/*{{{*/
		{
			insn_vector idiom;

			msg("%p TryAnd\n", insn.ea);

			if (!GetInstructions(2, idiom))
				return false;

			if (ARM_lsl == idiom[0].itype &&
					ARM_lsr == idiom[1].itype &&
					OperandIsRegister(idiom[0], 0) &&
					OperandIsRegister(idiom[0], 1) &&
					OperandIsRegister(idiom[1], 0) &&
					OperandIsRegister(idiom[1], 1) &&
					OperandIsImmediate(idiom[0], 2) &&
					OperandIsImmediate(idiom[1], 2) &&
					idiom[0].Operands[0].reg == idiom[1].Operands[1].reg &&
					idiom[0].Operands[2].value == idiom[1].Operands[2].value)
			{
				msg("%p TryAnd: operand 2: %d, %x\n", insn.ea, idiom[0].Operands[2].type, idiom[0].Operands[2].value);
				Insert(new Assignment(
						insn.ea,
						::FromOperand(idiom[1], 0),
						Expression_ptr(new BinaryExpression(
								::FromOperand(idiom[0], 1),
								"&",
								NumericLiteral::Create((1<<(32-idiom[0].Operands[2].value))-1)
								))
						));
				EraseInstructions(2);
				return true;
			}

			return false;
		}


		// Sometimes ADD R3,R1,0 is used to move a value.
		// Recognize this and replace by a straight assignment

		bool TryAddMov(insn_t& insn)/*{{{*/
		{
			if (insn.Operands[2].type == o_imm && insn.Operands[2].value == 0) {
				OnMov(insn);
				return true;
			}
			return false;
		}
		bool TryAddSp(insn_t& insn)/*{{{*/
		{
			if (OperandIsRegister(insn, 1) && insn.Operands[1].reg == REG_SP
				&& insn.Operands[2].type == o_imm) {
				OnAddSp(insn);
				return true;
			}
			return false;
		}
		// Idiom for function call:
		// Mov subroutine address to R?
		// MOV LR, PC
		// BX  R?
		bool TryMovBx(insn_t& insn)/*{{{*/
		{
			insn_vector idiom;

			if (!GetInstructions(2, idiom))
				return false;

			if (ARM_bx == idiom[1].itype &&
					OperandIsRegister(idiom[0], 0) &&
					OperandIsRegister(idiom[0], 1) &&
					idiom[0].Operands[0].reg == REG_LR &&
					idiom[0].Operands[0].reg == REG_PC) 
			{
				// Result in R0?
				Insert(new Assignment(
							insn.ea,
							Expression_ptr(new Register(0)),
							Expression_ptr(new CallExpression(::FromOperand(idiom[1], 0)))
							));
				EraseInstructions(2);
				return true;
			}
			return false;
		}

		AnalysisResult OnInstruction()
		{
			msg("%p: Analysis: Instruction Type %d\n",Instr()->Address(), Instr()->Type());
			return CONTINUE;
		}

		insn_t mFlagUpdate;
		const char *mFlagUpdateOp;
		Instruction_list::iterator mFlagUpdateItem;
};/*}}}*/



void IdaArm::FillList(func_t* function, Instruction_list& instructions)
{
	ArmAnalysis lla;
	lla.AnalyzeFunction(function, instructions);
}


