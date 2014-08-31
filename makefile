__CFLAGS=-Ic:\local\boost\boost_1_33_0
PROC=desquirr
SRC1=instruction
SRC2=dataflow
SRC3=node
SRC4=expression
SRC5=idapro
SRC6=codegen
SRC7=usedefine
SRC8=function
SRC9=frontend
SRC10=ida-arm
SRC11=ida-x86
OBJ1=$(F)$(SRC1)$(O)
OBJ2=$(F)$(SRC2)$(O)
OBJ3=$(F)$(SRC3)$(O)
OBJ4=$(F)$(SRC4)$(O)
OBJ5=$(F)$(SRC5)$(O)
OBJ6=$(F)$(SRC6)$(O)
OBJ7=$(F)$(SRC7)$(O)
OBJ8=$(F)$(SRC8)$(O)
OBJ9=$(F)$(SRC9)$(O)
OBJ10=$(F)$(SRC10)$(O)
OBJ11=$(F)$(SRC11)$(O)
!include ..\plugin.mak

HEADERS=$(I)area.hpp $(I)bytes.hpp $(I)funcs.hpp $(I)help.h         \
	        $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp       \
	        $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp $(I)netnode.hpp   \
	        $(I)pro.h $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp           \
					$(PROC).hpp $(SRC1).hpp $(SRC2).hpp $(SRC3).hpp $(SRC4).hpp \
					$(SRC6).hpp $(SRC7).hpp $(SRC8).hpp $(SRC9).hpp $(SRC10).hpp \
					 $(SRC11).hpp x86.hpp

# MAKEDEP dependency list ------------------
$(F)$(PROC)$(O): $(HEADERS) $(PROC).cpp

$(OBJ1): $(HEADERS) $(SRC1).hpp $(SRC1).cpp

$(OBJ2): $(HEADERS) $(SRC2).hpp $(SRC2).cpp

$(OBJ3): $(HEADERS) $(SRC3).hpp $(SRC3).cpp

$(OBJ4): $(HEADERS) $(SRC4).hpp $(SRC4).cpp

$(OBJ5): $(HEADERS) $(SRC5).hpp $(SRC5).cpp

$(OBJ6): $(HEADERS) $(SRC6).hpp $(SRC6).cpp

$(OBJ7): $(HEADERS) $(SRC7).hpp $(SRC7).cpp

$(OBJ8): $(HEADERS) $(SRC8).hpp $(SRC8).cpp

$(OBJ9): $(HEADERS) $(SRC9).hpp $(SRC9).cpp

$(OBJ10): $(HEADERS) $(SRC10).hpp $(SRC10).cpp

$(OBJ11): $(HEADERS) $(SRC11).hpp $(SRC11).cpp

install: $(BINARY)
	-copy $(BINARY) c:\ida\idapro\plugins\

