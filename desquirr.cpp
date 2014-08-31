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
// $Id: desquirr.cpp,v 1.9 2007/01/30 09:47:46 wjhengeveld Exp $

// C++ headers

#include <sstream>
#include <algorithm>
#include <stack>
#include <memory>

// IDA headers

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <funcs.hpp>
#include <ua.hpp>
#include <name.hpp>
#include <frame.hpp>
#include <struct.hpp>

// Local headers

#include "instruction.hpp"
#include "node.hpp"
#include "dataflow.hpp"
#include "expression.hpp"
#include "codegen.hpp"
#include "usedefine.hpp"
#include "idapro.hpp"
#include "ida-x86.hpp"
#include "ida-arm.hpp"

// global flag, set to true to enable dumping of node structures
// after each processing step.
bool g_bDumpNodeContents= false;

int message(const char *format,...)
{
  va_list va;
  va_start(va, format);
  int nbytes = Frontend::Get().vmsg(format, va);
  va_end(va);
  return nbytes;
}
int message(const std::string& str)
{
    int nbytes=0;
    for (size_t i= 0 ; i<str.size() ; i+=1024)
        nbytes += message("%s", str.substr(i, 1024).c_str());
    return nbytes;
}

static LongSize s_size = UNKNOWN_LONG_SIZE;

void setbits(LongSize size)
{
	s_size = size;
}

bool is16bit() { return IS_16_BIT == s_size; };
bool is32bit() { return IS_32_BIT == s_size; };

//--------------------------------------------------------------------------
// This callback is called for UI notification events
static int sample_callback(void * /*user_data*/, int event_id, va_list /*va*/)
{
  if ( event_id != ui_msg )     // avoid recursion
    if ( event_id != ui_setstate
      && event_id != ui_showauto
      && event_id != ui_refreshmarked ) // ignore uninteresting events
                    msg("ui_callback %d\n", event_id);
  return 0;                     // 0 means "process the event"
                                // otherwise the event would be ignored
}

//--------------------------------------------------------------------------
// A sample how to generate user-defined line prefixes
static const int prefix_width = 8;

static void get_user_defined_prefix(ea_t ea,
                                    int lnnum,
                                    int indent,
                                    const char *line,
                                    char *buf,
                                    size_t bufsize)
{
  buf[0] = '\0';        // empty prefix by default

  // We want to display the prefix only the lines which
  // contain the instruction itself

  if ( indent != -1 ) return;           // a directive
  if ( line[0] == '\0' ) return;        // empty line
  if ( *line == COLOR_ON ) line += 2;
  if ( *line == ash.cmnt[0] ) return;   // comment line...

  // We don't want the prefix to be printed again for other lines of the
  // same instruction/data. For that we remember the line number
  // and compare it before generating the prefix

  static ea_t old_ea = BADADDR;
  static int old_lnnum;
  if ( old_ea == ea && old_lnnum == lnnum ) return;

  // Let's display the size of the current item as the user-defined prefix
  ulong our_size = get_item_size(ea);

  // seems to be an instruction line. we don't bother about the width
  // because it will be padded with spaces by the kernel

   qsnprintf(buf, bufsize, " %d", our_size);

  // Remember the address and line number we produced the line prefix for:
  old_ea = ea;
  old_lnnum = lnnum;

}

//--------------------------------------------------------------------------
//
//      Initialize.
//
//      IDA will call this function only once.
//      If this function returns PLGUIN_SKIP, IDA will never load it again.
//      If this function returns PLUGIN_OK, IDA will unload the plugin but
//      remember that the plugin agreed to work with the database.
//      The plugin will be loaded again if the user invokes it by
//      pressing the hotkey or selecting it from the menu.
//      After the second load the plugin will stay on memory.
//      If this function returns PLUGIN_KEEP, IDA will keep the plugin
//      in the memory. In this case the initialization function can hook
//      into the processor module and user interface notification points.
//      See the hook_to_notification_point() function.
//
//      In this example we check the input file format and make the decision.
//      You may or may not check any other conditions to decide what you do:
//      whether you agree to work with the database or not.
//
int idaapi init(void)
{
//	msg("Current processor: %s\n", inf.procName);
	
	if (PLFM_386 != ph.id &&
			PLFM_ARM != ph.id)
		return PLUGIN_SKIP;

	
 // if ( inf.filetype == f_ELF ) return PLUGIN_SKIP;

// Please uncomment the following line to see how the notification works
//  hook_to_notification_point(HT_UI, sample_callback, NULL);

// Please uncomment the following line to see how the user-defined prefix works
//  set_user_defined_prefix(prefix_width, get_user_defined_prefix);

  return PLUGIN_OK;
}

//--------------------------------------------------------------------------
//      Terminate.
//      Usually this callback is empty.
//      The plugin should unhook from the notification lists if
//      hook_to_notification_point() was used.
//
//      IDA will call this function when the user asks to exit.
//      This function won't be called in the case of emergency exits.

void idaapi term(void)
{
  unhook_from_notification_point(HT_UI, (hook_cb_t*)sample_callback);
  set_user_defined_prefix(0, NULL);
}

// arg & 1: decompile to C code (1) or normally (0)
// arg & 2: print instruction list before splitting into nodes
// arg & 4: dump current instruction
// arg & 8: process all functions
void idaapi run(int arg)
{
	msg("Running The Desquirr decompiler plugin\n");
	
	IdaPro* idapro;
	
	if (PLFM_386 == ph.id)
		idapro = new IdaX86();
	else if (PLFM_ARM == ph.id)
		idapro = new IdaArm();
	else
	{
		msg("Unexpected processor module\n");
		return;
	}
	
	Frontend_ptr frontend(idapro);
	Frontend::Set(frontend);

	if (arg & 4)
	{
		idapro->DumpInsn(get_screen_ea());
		return;
	}
	CodeStyle style = (arg & 1) ? C_STYLE : LISTING_STYLE;
	
	for (func_t *function= (arg&8)?get_next_func(0) : get_func(get_screen_ea()) ; function ; function= (arg&8)?get_next_func(function->startEA):0)
	{
		if (function->flags & FUNC_LIB)
			msg("Warning: Library function\n");
		
		Instruction_list instructions;

		msg("-> Creating instruction list\n");
		idapro->FillList(function, instructions);

		if (arg & 2)
		{
			msg("Instruction list:\n");
			GenerateCode(instructions, style);
			break;
		}

		Node_list nodes;
		msg("-> Creating node list\n");
		Node::CreateList(instructions, nodes);
        //if (g_bDumpNodeContents) DumpList(nodes);
		msg("-> Update uses and definitions\n");
		UpdateUsesAndDefinitions(nodes);
        //if (g_bDumpNodeContents) DumpList(nodes);
		msg("-> Live register analysis\n");
		Node::LiveRegisterAnalysis(nodes);
        //if (g_bDumpNodeContents) DumpList(nodes);
		msg("-> Finding DU chains\n");
		Node::FindDefintionUseChains(nodes);
        if (g_bDumpNodeContents) DumpList(nodes);
		
		msg("-> Data flow analysis\n");
		{
			DataFlowAnalysis analysis(nodes);
			analysis.AnalyzeNodeList();
			// want destructor to run here :-)
		}
        if (g_bDumpNodeContents) DumpList(nodes);

		msg("Basic block list:\n");
		GenerateCode(nodes, style);

	}
}

//--------------------------------------------------------------------------
char comment[] = "The Desquirr decompiler plugin";

char help[] = "The Desquirr decompiler plugin";


//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

char wanted_name[] = "Decompile function";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

char wanted_hotkey[] = "Ctrl-F10";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------

extern "C" plugin_t PLUGIN;

plugin_t PLUGIN = {
  IDP_INTERFACE_VERSION,
#if 0
  0,                    // plugin flags
#else
	PLUGIN_UNL, // for debugging
#endif
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};

// .... dump helpers
struct DumpInsnHelper {
    DumpInsnHelper(std::ostream& os)
        : os(os) 
    {}
    void operator() (Instruction_ptr item)
    {
        os << *item.get();
    }
    std::ostream& os;
};

std::ostream& printlist(std::ostream& os, Instruction_list& list)
{
    for_each(list.begin(), list.end(), DumpInsnHelper(os));

    return os;
}

void DumpList(Instruction_list& list)
{
    std::ostringstream strstr;
    printlist(strstr, list);
    message(strstr.str());
}

struct DumpNodeHelper {
    DumpNodeHelper(std::ostream& os)
        : os(os) 
    {}
    void operator() (Node_ptr item)
    {
        os << *item.get();
    }
    std::ostream& os;
};

std::ostream& printlist(std::ostream& os, Node_list& list)
{
    for_each(list.begin(), list.end(), DumpNodeHelper(os));

    return os;
}

void DumpList(Node_list& list)
{
    std::ostringstream strstr;
    printlist(strstr, list);
    message(strstr.str());
}

struct DumpExprHelper {
    DumpExprHelper(std::ostream& os)
        : os(os), first(true)
    {}
    void operator() (Expression_ptr item)
    {
        if (!first)
            os << ", ";
        os << *item.get();
        first= false;
    }
    std::ostream& os;
    bool first;
};

std::ostream& printvector(std::ostream& os, Expression_vector& list)
{
    for_each(list.begin(), list.end(), DumpExprHelper(os));

    return os;
}

void DumpVector(Expression_vector& list)
{
    std::ostringstream strstr;
    printvector(strstr, list);
    message(strstr.str());
}


