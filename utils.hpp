#pragma once

#include <memory>
#include <algorithm>

//----------------------------------------------------------------------------------
ea_t get_selection_range(TWidget* widget, ea_t* end_ea = nullptr, int widget_type = BWN_DISASM)
{
    ea_t ea1 = BADADDR, ea2 = BADADDR;
    do
    {
        if (widget == nullptr || (widget_type != -1 && get_widget_type(widget) != widget_type))
            break;

        if (!read_range_selection(widget, &ea1, &ea2))
        {
            ea1 = get_screen_ea();

            if (ea1 == BADADDR)
                break;
            insn_t inst;
            ea2 = (decode_insn(&inst, ea1) == 0) ? ea1 + 1 : ea1 + inst.size;
        }
    } while (false);
    if (end_ea != nullptr)
        *end_ea = ea2;

    return ea1;
}

//----------------------------------------------------------------------------------
inline cinsn_t* hexrays_get_stmt_insn(cfunc_t* cfunc, citem_t* ui_item)
{
    auto func_body = &cfunc->body;

    citem_t* item = ui_item;
    citem_t* stmt_item;

    // Get the top level statement from this item
    for (stmt_item = item; item != nullptr && item->is_expr(); item = func_body->find_parent_of(item))
        stmt_item = item;

    // ...then the actual instruction item
    if (stmt_item->is_expr())
        stmt_item = func_body->find_parent_of(stmt_item);

    return (cinsn_t*)stmt_item;
}

//----------------------------------------------------------------------------------
inline bool hexrays_get_stmt_block_pos(
    cfunc_t* cfunc,
    citem_t* stmt_item,
    cblock_t** p_cblock,
    cblock_t::iterator* p_pos)
{
    auto func_body = &cfunc->body;
    cinsn_t* cblock_insn = (cinsn_t*)func_body->find_parent_of(stmt_item);
    if (cblock_insn == nullptr || cblock_insn->op != cit_block)
        return false;

    cblock_t* cblock = cblock_insn->cblock;

    for (auto p = cblock->begin(); p != cblock->end(); ++p)
    {
        if (*p == *((cinsn_t*)stmt_item))
        {
            *p_pos = p;
            *p_cblock = cblock;
            return true;
        }
    }
    return false;
}
