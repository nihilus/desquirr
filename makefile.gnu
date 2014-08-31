# author: Willem Hengeveld <itsme@xs4all.nl>
# web: http://www.xs4all.nl/~itsme/projects/disassemblers/ida/idp-Makefile
#
# makefile for gnu/cygwin make, using msvc compiler, or the gnu c compiler
# needs environment setup with 'vcvars32.bat' ( from vstudio )
#
# also:
#     expects IDA to be installed in c:\local\ida500
#     expects the boost library to be installed in c:\local\boost\boost_1_33_0
#     and having the cygwin tools installed
#
# NOTE:
# about using gcc:  it does not work.
#
# on ida 4.8 has a problem in libgcc.w32/ida.a 
#    where the compiler wants a '_qsnprintf' in the .objs
#    but the datarescue supplied ida.a lib contains '_qsnprintf@0'
#
# with ida 4.9 everything compiles and builds just fine
#   .. but still has an unsolved stackcorruption bug.
#
# in order for the gcc compile to succeed, in 
# /usr/lib/gcc/i686-pc-mingw32/3.4.4/include/c++/bits/locale_classes.h
# you need to change line 579:
# 	      std::strcpy(_M_tmp_names[__i], "*");
# into:
#         _M_tmp_names[__i][0]= '*';
#         _M_tmp_names[__i][1]= 0;
#
# and /usr/lib/gcc/i686-pc-mingw32/3.4.4/include/c++/i686-pc-mingw32/bits/time_members.h
# in line 59:
#       std::strcpy(__tmp, __s);
# into:
#     for (int i=std::strlen(__s) ; i>=0 ; i--)
#         __tmp[i]= __s[i];

#  this avoids the use of strcpy which is redefined to dont_use_strcpy by the idasdk/include/pro.h file.
#
#  BUG: the gcc compile crashes somewhere with a stack corruption.
#
#
# the microsoft C compiler works fine.
#

USEMSC=1
ifdef USEMSC
objdir=buildmsc
else
objdir=buildgcc
endif

idasdk=c:\local\ida500\idasdk
boost=c:/local/boost/boost_1_33_0
.SUFFIXES:
.SUFFIXES: .cpp .obj .plw

#   microsoft's headers are loaded with warnings:
#C4514: 'uint128::uint128' : unreferenced inline function has been removed
#C4710: function 'int __stdcall getreg(unsigned long,int)' not inlined
#C4244: '+=' : conversion from 'int' to 'unsigned short', possible loss of data
#C4242: '=' : conversion from 'int' to 'ushort', possible loss of data
#C4127: conditional expression is constant
#C4146: unary minus operator applied to unsigned type, result still unsigned
#C4820: '__stat64' : '4' bytes padding added after member '__stat64::st_rdev'
#C4217: member template functions cannot be used for copy-assignment or copy-construction
#C4668: '_MT' is not defined as a preprocessor macro, replacing with '0' for '#if/#elif'
#C4619: #pragma warning : there is no warning number '4284'

# disabling them all, to get a more readable compiler output.
NOWARN=-wd4619 -wd4514 -wd4710 -wd4244 -wd4242 -wd4127 -wd4668 -wd4146 -wd4820 -wd4217

CDEFS=-DWIN32 -D_USRDLL -D__NT__ -D__IDP__ -DMAXSTR=1024
CINCS=-I $(idasdk)\include -I $(boost) -I $(idasdk)\module
COPTS=-GX -GR -Gz -nologo  -Zi 

LDLIBS=/libpath:$(idasdk)\LIBVC.W32  $(idasdk)\LIBVC.W32\ida.lib
LDFLAGS=/nologo /dll /export:PLUGIN  /debug

# msvc 12.00 does not support -Wall yet -> use -W4.
# msvc 13.10 does support it.
#
$(objdir)/%.obj: %.cpp
ifdef USEMSC
	@CL -c -W3 $(NOWARN) $(COPTS) $(CINCS) $(CDEFS) -Fo$@ $<
else
	@g++ -c -Wall $(CINCS) $(CDEFS) -mrtd -mno-cygwin -o $@ $<
endif

all: $(objdir) $(objdir)/desquirr.plw

$(objdir):
	mkdir -p $(objdir)

$(objdir)/desquirr.plw: $(objdir)/desquirr.obj $(objdir)/instruction.obj $(objdir)/dataflow.obj $(objdir)/node.obj $(objdir)/expression.obj $(objdir)/idapro.obj $(objdir)/codegen.obj $(objdir)/usedefine.obj $(objdir)/function.obj $(objdir)/frontend.obj $(objdir)/ida-arm.obj $(objdir)/ida-x86.obj
ifdef USEMSC
	@LINK $(LDFLAGS) $(LDLIBS) $^ /out:$@ /map:desquirr.map
else
	echo "EXPORTS"        >$(objdir)/desquirr.def
	echo "  _PLUGIN @1"  >>$(objdir)/desquirr.def
	@g++ -Wl,--dll -shared -mno-cygwin $^ $(idasdk)/libgcc.w32/ida.a -o $@  --def $(objdir)/desquirr.def
endif

clean:
	-rm -rf buildgcc buildmsc Debug Release

install: $(objdir)/desquirr.plw
	cp $(objdir)/desquirr.plw $(idasdk)/../plugins

test: install
	$(idasdk)/../idag.exe testcode\example-block-structure.idb
