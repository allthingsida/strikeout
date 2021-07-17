#pragma once

#pragma warning(push)
#pragma warning(disable: 4267 4083 4244)
#include <auto.hpp>
#include <hexrays.hpp>
#include <bytes.hpp>
#include <kernwin.hpp>
#pragma warning(pop)
#include <idax/xpro.hpp>
#include <idax/xkernwin.hpp>
#include <idax/xhexrays.hpp>

#define STORE_NODE_NAME                "$ hexrays strikeout-plugin"

#define ACTION_NAME_DELSTMT            "hexrays-strikeout-delstmt"
#define ACTION_NAME_PATCHSTMT          "hexrays-strikeout-patchstmt"
#define ACTION_NAME_PATCHSTMT_FLUSH    "hexrays-strikeout-patchstmt-flush"
#define ACTION_NAME_PATCHSTMT_CLEAR    "hexrays-strikeout-patchstmt-clear"
#define ACTION_NAME_DELSTMTS           "hexrays-strikeout-reset-delstmts"
#define ACTION_NAME_DEL2PATCH          "hexrays-strikeout-del2patch"
#define ACTION_NAME_PATCHCODE          "hexrays-strikeout-patchcode"
#define ACTION_NAME_DISASM_LINEUP      "hexrays-strikeout-disasm-lineup"
#define ACTION_NAME_DISASM_LINEDOWN    "hexrays-strikeout-disasm-linedown"