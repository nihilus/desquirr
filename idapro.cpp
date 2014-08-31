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
// $Id: idapro.cpp,v 1.12 2007/01/30 09:49:12 wjhengeveld Exp $
#include "idainternal.hpp"
#include "idapro.hpp"
#include "instruction.hpp"
#include "analysis.hpp"

#include <memory>

#if IDP_INTERFACE_VERSION<76
// backward compatibility with ida480
size_t get_member_name(tid_t mid, char *buf, size_t bufsize)
{
    char *name= get_member_name(mid);
    if (name) {
        qstrncpy(buf, name, bufsize);
        return strlen(buf);
    }
    return -1;
}
#endif

#if IDP_INTERFACE_VERSION<75
// backward compatibility with ida470
bool get_ti(ea_t ea, type_t *buf, size_t bufsize, p_list *fnames, size_t fnsize)
{
    return get_ti(ea, buf, fnames);
}
#endif
std::string get_struct_path(struc_t *struc, int offset, int *pIndex)
{
	member_t* member = NULL;  /* must live here, not inside while */
	std::ostringstream buffer;
	bool first = true;

	// todo: this is not working as intended. needs fixing.
	int totalsoff= 0;
	while (struc)
	{
		member = get_member(struc, offset);
		if (member)
		{
			if (first)
				first = false;
			else
				buffer << '.';

			char tmp[256];
			if (get_member_name(member->id, tmp, 256)>0)
				buffer << tmp;
			else
				buffer << "NO_NAME";

			totalsoff = offset - member->soff;
			struc = get_sptr(member);
		}
		else
		{
			struc = NULL;
		}
	}

	//if (member && (offset - member->soff) != 0)
	if (totalsoff)
	{
		//message("%p Stack variable: offset=%i, member->soff=%i\n", ea, offset, member->soff);
		if (pIndex)
			*pIndex = totalsoff; // offset - member->soff;
	}

	return buffer.str();
}/*}}}*/

// used from CreateStackVariable
std::string GetStackVariableName(const insn_t &insn, int operand, int* pIndex)/*{{{*/
{
	if (pIndex)
		*pIndex = 0;
	
    ea_t ea= insn.ea;
	func_t* func = get_func(ea);
	if (func==NULL)
	{
		message("ERROR - get_func(%08lx)\n", ea);
		return "";
	}


	ulong offset = calc_stkvar_struc_offset(func, ea, operand);
	if (offset==BADADDR) {
		message("ERROR in calc_stkvar_struc_offset(%08lx, %08lx, %d)\n", func->startEA, ea, operand);
		return "";
	}

	struc_t* struc = get_frame(func);
	if (struc==NULL) {
		message("ERROR: function has no frame\n");
		return "";
	}
	return get_struct_path(struc, offset, pIndex);
}


// returns name such that get_func_name(ea) == name and get_func(ea).startEA+*pIndex == ea
// used by GetGlobalVariableName
std::string GetGlobalCodeLabel(ea_t ea, int *pIndex)/*{{{*/
{
    // return funcname + offset
    char name[MAXSTR];

    func_t *func= get_func(ea);
    if (func==NULL) {
        message("%p Warning: referenced code offset not in a function\n", ea);
        return "";
    }
    if (get_func_name(ea, name, MAXSTR)) {
        *pIndex= ea - func->startEA;
        return std::string(name);
    }
    else {
        message("%p Warning: referenced code offset not in a function\n", ea);
        return "";
    }
}

// returns name such that get_name_ea(ea - *pIndex) == name
std::string GetLocalCodeLabel(ea_t ea, int *pIndex)/*{{{*/
{
    char name[MAXSTR];

    func_t* pfn= get_func(ea);
    func_item_iterator_t fii;
    for ( bool ok=fii.set(pfn, ea); ok; ok=fii.prev_addr() ) {
        ea_t lea = fii.current();

        if (get_name(ea, lea, name, sizeof(name))) {
            *pIndex= ea-lea;
			if (*pIndex)
				message("Unexpected locallabel with name=%s index=%d\n", name, *pIndex);
            return std::string(name);
        }
		else {
			break;
			// message("%p %p -- fii next\n", ea, lea);
		}
    }
      
    message("%p Warning: label without name\n", ea);
    return "";
}/*}}}*/

Instruction_ptr CreateLocalCodeLabel(ea_t ea)
{
    int index;
    std::string name= GetLocalCodeLabel(ea, &index);
    if (index || name.empty()) {
        name.resize(32);
        name.resize(qsnprintf(&name[0], name.size(), "loc_%X", ea));
        message("NOTE: created new label %s\n", name.c_str());
    }
    Instruction_ptr instr;
    // todo: think of a better way to represent local function labels.
    instr.reset(new Label(ea, name.c_str()));
    return instr;
}

Expression_ptr CreateLocalCodeReference(ea_t ea)
{
    int index;
    std::string name= GetLocalCodeLabel(ea, &index);
    if (index || name.empty()) {
        name.resize(32);
        name.resize(qsnprintf(&name[0], name.size(), "loc_%X", ea));
        message("NOTE: created new label %s\n", name.c_str());
    }
    Expression_ptr expr;
    // todo: think of a better way to represent local function labels.
    expr.reset(new GlobalVariable(name, 0, ea));
    return expr;
}
Expression_ptr CreateGlobalCodeLabel(ea_t ea)
{
    int index;
    std::string name= GetGlobalCodeLabel(ea, &index);
    if (name.empty()) {
        name.resize(32);
        name.resize(qsnprintf(&name[0], name.size(), "proc_%X", ea));
        message("NOTE: created new function name %s\n", name.c_str());
    }
    else if (index!=0) {
        name.resize(name.size()+16);
        name.resize(qsnprintf(&name[0], name.size(), "%s+0x%X", name.c_str(), index));
        message("NOTE: using func+offs name: %s\n", name.c_str());
    }
    Expression_ptr expr;
    expr.reset(new GlobalVariable(name, 0, ea));
    return expr;
}

// todo: figure out how to get the structure type of the data at a specific offset.
std::string GetGlobalVariableName(ea_t ea, int* pIndex)/*{{{*/
{
	std::ostringstream buffer;

	if (pIndex)
		*pIndex = 0;

    flags_t flags= ::getFlags(ea);

    if (isCode(flags)) {
        return GetGlobalCodeLabel(ea, pIndex);
    }
/*
    else if (!isData(flags)) {
        message("%p Warning: referencing unknown item flags=%08lx\n", ea, flags);
    }
    else if (isStruct(flags)) {
        tid_t tid= 
        struc_t* struc = get_struc(tid);
        // get_stroff_path(ea_t ea, int n, tid_t *path, adiff_t *delta)
    }
*/
    else {
        char name[MAXSTR];
        if (get_name(BADADDR, ea, name, sizeof(name))) {
            return name;
        }
        else {
			ea_t head= prev_head(ea, 0);

			std::string headname; headname.resize(MAXSTR);
			if (!get_name(BADADDR, head, &headname[0], headname.size())) {
				headname.resize(qsnprintf(&headname[0], headname.size(), "gvar_%X", head));
			}
			else {
				headname.resize(strlen(&headname[0]));
			}
			tid_t tid= get_strid(head);
			struc_t *struc= get_struc(tid);
			return headname + "." + get_struct_path(struc, ea-head, pIndex);
        }
    }
}/*}}}*/
bool is_local_to_function(ea_t funcea, ea_t ea)
{
	func_t *func= get_func(funcea);
	return func_contains(func, ea);
}
Expression_ptr CreateVariable(const insn_t &insn, int operand)
{
	ea_t ea= insn.Operands[operand].addr;

	if (is_local_to_function(insn.ea, ea))
		return CreateLocalCodeReference(ea);
	else
		return CreateGlobalVariable(insn, operand);
}
Expression_ptr CreateGlobalVariable(const insn_t &insn, int operand)
{
    Expression_ptr expr;

    ea_t ea= insn.Operands[operand].addr;

    int index;
    std::string name= GetGlobalVariableName(ea, &index);

    if (name.empty()) {
        name.resize(32);
        name.resize(qsnprintf(&name[0], name.size(), "gvar_%X", ea));
        message("NOTE: created new globalvar %s\n", name.c_str());
    }

    expr.reset(new GlobalVariable(name, index, ea));

    return expr;
}



Expression_ptr CreateStackVariable(insn_t& insn, int operand)/*{{{*/
{
	Expression_ptr result;
	
	int index;
    std::string name = GetStackVariableName(insn, operand, &index);

	if (name.empty())
	{
		// Try to add a stack variable and try again!
//		message("%p Warning: trying to create stack variable\n", insn.ea);
		if (!add_stkvar(insn.Operands[operand], insn.Operands[operand].addr)) {
			message("error in add_stkvar(%08lx, %08lx)\n", insn.Operands[operand].dtyp, insn.Operands[operand].addr);
			return Expression_ptr();
		}
		if (!op_stkvar(insn.ea, operand)) {
			message("error in op_stkvar(%08lx, %08lx)\n", insn.ea, operand);
			return Expression_ptr();
		}
		name = GetStackVariableName(insn, operand, &index);
	}
	
	if (!name.empty()) {
		result.reset(new StackVariable(name, index));
	}
	else {
		message("ERROR: could not allocate stack var (%08lx, %d)\n", insn.ea, operand);
	}

	return result;
}/*}}}*/


static const char* const optype_string[] = {/*{{{*/
	"o_void",
	"o_reg",
	"o_mem",
	"o_phrase",
	"o_displ",
	"o_imm",
	"o_far",
	"o_near",
	"o_idpspec0",
	"o_idpspec1",
	"o_idpspec2",
	"o_idpspec3",
	"o_idpspec4",
	"o_idpspec5",
	"o_last"
};/*}}}*/

const char* IdaPro::GetOptypeString(op_t& op)/*{{{*/
{
//	if (op.type >= 0 && op.type <= o_last)
		return optype_string[op.type];
/*	else
		return "INVALID";*/
}/*}}}*/

insn_t GetLowLevelInstruction(ea_t address)/*{{{*/
{
	// note: ua_ana0  sets the global 'cmd' variable
	ua_ana0(address);
	return cmd;
}/*}}}*/

void IdaPro::DumpInsn(Addr address)/*{{{*/
{
	insn_t insn = ::GetLowLevelInstruction(address);
	DumpInsn(insn);
}/*}}}*/


int IdaPro::vmsg(const char *format, va_list va)
{
	return ::vmsg(format, va);
}

Addr IdaPro::AddressFromName(const char *name, Addr referer)
{
	return ::get_name_ea(referer, name);
}

void IdaPro::LoadCallTypeInformation(CallExpression* call)
{
	if (BADADDR == call->Address())
		return;

	type_t type[MAXSTR];
	p_list names[MAXSTR];
	
	if (!get_ti(call->Address(), type, MAXSTR, names, MAXSTR))
  {
    message("No type information for function at %p!\n", 
        call->Address());
		return;
  }

	// CM (calling convention & model)
	cm_t cm = type[1];
	call->CallingConvention(cm);

	ulong plocations[CallExpression::MAX_PARAMETERS];
	memset(plocations, 0, sizeof(plocations));

	type_t* DataTypes     [CallExpression::MAX_PARAMETERS];
	char*   ParameterNames[CallExpression::MAX_PARAMETERS];
	memset(DataTypes,      0, sizeof(DataTypes));
	memset(ParameterNames, 0, sizeof(ParameterNames));

	call->ParameterCount(
			build_funcarg_arrays(type, names, plocations, 
			(type_t**)DataTypes, (char**)ParameterNames, CallExpression::MAX_PARAMETERS, false));

#if 0
	char buffer[MAXSTR]; 
	for (int i = 0; i < mParameterCount; i++)
	{
		buffer[0] = '\0';
		print_type_to_one_line(buffer, sizeof(buffer), idati, mDataTypes[i]);
		msg("Parameter %i type: %s %s\n", i, buffer, mParameterNames[i]);
	}
#endif

	type_t return_type[MAXSTR];
	if (::extract_func_ret_type(type, return_type, sizeof(return_type)))
	{
		//DataType().Set(return_type);
#if 0
		buffer[0] = '\0';
		print_type_to_one_line(buffer, sizeof(buffer), idati, mReturnType);
		msg("Return type: %s\n", buffer);
#endif
	}

	free_funcarg_arrays(DataTypes, ParameterNames, CallExpression::MAX_PARAMETERS);
	
}

