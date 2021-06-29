ifdef __NT__
  CFLAGS += /wd4062 /wd4265
endif
PROC=strikeout

include ../plugin.mak

# MAKEDEP dependency list ------------------
$(F)hidestmt$(O): $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp      \
                  $(I)fpro.h $(I)funcs.hpp $(I)gdl.hpp $(I)hexrays.hpp      \
                  $(I)ida.hpp $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp        \
                  $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
                  $(I)name.hpp $(I)netnode.hpp $(I)pro.h $(I)range.hpp      \
                  $(I)segment.hpp $(I)typeinf.hpp $(I)ua.hpp $(I)xref.hpp   \
                  plugin.cpp utils.hpp
