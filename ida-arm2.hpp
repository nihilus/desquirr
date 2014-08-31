// 
// The contents of this file comes from IDA Pro.
//
// Copyright (c) 1990-99 by Ilfak Guilfanov, <ig@datarescue.com>
//
// $Id: ida-arm2.hpp,v 1.4 2007/01/30 09:48:43 wjhengeveld Exp $
#ifndef _IDA_ARM2_HPP
#define _IDA_ARM2_HPP

#define REG_SP 13		// stack pointer
#define REG_LR 14		// link register = return address
#define REG_PC 15		// program counter

//#define AUX_PRE_INDEX			0x10
//#define AUX_WRITE_BACK		0x40
//#define AUX_UP						0x80

//---------------------------------
// ARM cmd.auxpref bits
#define aux_cond        0x0001  // set condition codes (S postfix is required)
#define aux_byte        0x0002  // byte transfer (B postfix is required)
#define aux_npriv       0x0004  // non-privileged transfer (T postfix is required)
#define aux_regsh       0x0008  // shift count is held in a register (see o_shreg)
#define aux_negoff      0x0010  // memory offset is negated in LDR,STR
#define aux_wback       0x0020  // write back (! postfix is required)
#define aux_wbackldm    0x0040  // write back for LDM/STM (! postfix is required)
#define aux_postidx     0x0080  // post-indexed mode in LDR,STR
#define aux_ltrans      0x0100  // long transfer in LDC/STC (L postfix is required)
#define aux_badbit      0x0200  // The instruction has some illegal bits
#define aux_sb          0x0400  // signed byte (SB postfix)
#define aux_sh          0x0800  // signed halfword (SH postfix)
#define aux_h           0x1000  // halfword (H postfix)
#define aux_p           0x2000  // priviledged (P postfix)

enum cond_t
{
  cEQ,          // 0000 Z                        Equal
  cNE,          // 0001 !Z                       Not equal
  cCS,          // 0010 C                        Unsigned higher or same
  cCC,          // 0011 !C                       Unsigned lower
  cMI,          // 0100 N                        Negative
  cPL,          // 0101 !N                       Positive or Zero
  cVS,          // 0110 V                        Overflow
  cVC,          // 0111 !V                       No overflow
  cHI,          // 1000 C & !Z                   Unsigned higher
  cLS,          // 1001 !C & Z                   Unsigned lower or same
  cGE,          // 1010 (N & V) | (!N & !V)      Greater or equal
  cLT,          // 1011 (N & !V) | (!N & V)      Less than
  cGT,          // 1100 !Z & ((N & V)|(!N & !V)) Greater than
  cLE,          // 1101 Z | (N & !V) | (!N & V)  Less than or equal
  cAL,          // 1110 Always
  cNV,          // 1111 Never
};

// for op.type==o_idpspec0 -> specflag2 is shift_t
enum shift_t
{
  LSL,          // logical left         LSL #0 - don't shift
  LSR,          // logical right        LSR #0 means LSR #32
  ASR,          // arithmetic right     ASR #0 means ASR #32
  ROR,          // rotate right         ROR #0 means RRX
  RRX,          // extended rotate right
};
enum nameNum {

ARM_null = 0,           // Unknown Operation
ARM_ret,                // Return from Subroutine
ARM_nop,                // No Operation
ARM_b,                  // Branch
ARM_bl,                 // Branch with Link
ARM_asr,                // Arithmetic Shift Right
ARM_lsl,                // Logical Shift Left
ARM_lsr,                // Logical Shift Right
ARM_ror,                // Rotate Right
ARM_neg,                // Negate
ARM_and,                // 0 Rd = Op1 & Op2
ARM_eor,                // 1 Rd = Op1 ^ Op2
ARM_sub,                // 2 Rd = Op1 - Op2
ARM_rsb,                // 3 Rd = Op2 - Op1
ARM_add,                // 4 Rd = Op1 + Op2
ARM_adc,                // 5 Rd = Op1 + Op2 + C
ARM_sbc,                // 6 Rd = Op1 - Op2 + C - 1
ARM_rsc,                // 7 Rd = Op2 - Op1 + C - 1
ARM_tst,                // 8 Set cond. codes on Op1 & Op2
ARM_teq,                // 9 Set cond. codes on Op1 ^ Op2
ARM_cmp,                // A Set cond. codes on Op1 - Op2
ARM_cmn,                // B Set cond. codes on Op1 + Op2
ARM_orr,                // C Rd = Op2 | Op1
ARM_mov,                // D Rd = Op2
ARM_bic,                // E Rd = Op1 & ~Op2
ARM_mvn,                // F Rd = ~Op2
ARM_mrs,                // Transfer PSR to Register
ARM_msr,                // Transfer Register to PSR
ARM_mul,                // Multiply
ARM_mla,                // Multiply-Accumulate
ARM_ldr,                // Load from Memory
ARM_ldrpc,              // Indirect Jump
ARM_str,                // Store to Memory
ARM_ldm,                // Load Block from Memory
ARM_stm,                // Store Block to Memory
ARM_swp,                // Single Data Swap
ARM_swi,                // Software interrupt

// Version 4

ARM_smull,              // Signed Multiply long
ARM_smlal,              // Signed Multiply-Accumulate long
ARM_umull,              // Unsigned Multiply long
ARM_umlal,              // Unsigned Multiply-Accumulate long
ARM_bx,                 // Branch to/from Thumb mode
ARM_pop,                // Pop registers
ARM_push,               // Push registers
ARM_adr,                // Load address

// Version 5

ARM_bkpt,               // Breakpoint
ARM_blx1,               // Branch with Link and Exchange (immediate address)
ARM_blx2,               // Branch with Link and Exchange (register indirect)
ARM_clz,                // Count Leading Zeros

// Version 5E

ARM_ldrd,               // Load pair of registers
ARM_pld,                // Prepare to load
ARM_qadd,               // Saturated addition
ARM_qdadd,              // Saturated addition with doubling
ARM_qdsub,              // Saturated subtraction with doubling
ARM_qsub,               // Saturated subtraction
ARM_smlabb,             // Signed multiply-accumulate (bottom*bottom)
ARM_smlatb,             // Signed multiply-accumulate (top*bottom)
ARM_smlabt,             // Signed multiply-accumulate (bottom*top)
ARM_smlatt,             // Signed multiply-accumulate (top*top)
ARM_smlalbb,            // Long signed multiply-accumulate (bottom*bottom)
ARM_smlaltb,            // Long signed multiply-accumulate (top*bottom)
ARM_smlalbt,            // Long signed multiply-accumulate (bottom*top)
ARM_smlaltt,            // Long signed multiply-accumulate (top*top)
ARM_smlawb,             // Wide signed multiply-accumulate (bottom)
ARM_smulwb,             // Wide signed multiply (bottom)
ARM_smlawt,             // Wide signed multiply-accumulate (top)
ARM_smulwt,             // Wide signed multiply (top)
ARM_smulbb,             // Signed multiply (bottom*bottom)
ARM_smultb,             // Signed multiply (top*bottom)
ARM_smulbt,             // Signed multiply (bottom*top)
ARM_smultt,             // Signed multiply (top*top)
ARM_strd,               // Store pair of registers

// Intel xScale coprocessor instructions

xScale_mia,             // Multiply-Internal Accumulate
xScale_miaph,           // Multiply-Internal Accumulate Packed HalfWords
xScale_miabb,           // Multiply-Internal Accumulate Bottom-Bottom Halves
xScale_miabt,           // Multiply-Internal Accumulate Bottom-Top Halves
xScale_miatb,           // Multiply-Internal Accumulate Top-Bottom Halves
xScale_miatt,           // Multiply-Internal Accumulate Top-Top Halves
xScale_mar,             // Move To Internal Accumulator
xScale_mra,             // Move From Internal Accumulator

// Macro instructions

ARM_movl,               // Move immediate to register

// Coprocessor instructions (should be last in the list)

ARM_cdp,                // Coprocessor Data Processing
ARM_cdp2,               // Coprocessor Data Processing
ARM_ldc,                // Load Coprocessor Register
ARM_ldc2,               // Load Coprocessor Register
ARM_stc,                // Store Coprocessor Register
ARM_stc2,               // Store Coprocessor Register
ARM_mrc,                // Move from Coprocessor to ARM Register
ARM_mrc2,               // Move from Coprocessor to ARM Register
ARM_mcr,                // Move from ARM to Coprocessor Register
ARM_mcr2,               // Move from ARM to Coprocessor Register
ARM_mcrr,               // Copy pair of registers to coprocessor (5E)
ARM_mrrc,               // Copy pair of registers from coprocessor (5E)

ARM_last

    };

#endif // _IDA_ARM2_HPP


