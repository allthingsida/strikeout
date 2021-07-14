#pragma once

#include <memory>
#include <algorithm>

//----------------------------------------------------------------------------------
class hexrays_ctreeparent_visitor_t : public ctree_parentee_t
{
private:
    std::map<const citem_t*, const citem_t*> parent;

public:
    int idaapi visit_expr(cexpr_t* e) override
    {
        parent[e] = parent_expr();
        return 0;
    }

    int idaapi visit_insn(cinsn_t* ins) override
    {
        parent[ins] = parent_insn();
        return 0;
    }

    const citem_t* parent_of(const citem_t* item)
    {
        return parent[item];
    }

    bool is_acenstor_of(const citem_t* parent, const citem_t* item)
    {
        while (item != nullptr)
        {
            item = parent_of(item);
            if (item == parent)
                return true;
        }
        return false;
    }
};

//----------------------------------------------------------------------------------
ea_t get_selection_range(
    TWidget* widget, 
    ea_t* end_ea = nullptr, 
    int widget_type = BWN_DISASM)
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

            ea2 = next_head(ea1, BADADDR);
            if (ea2 == BADADDR)
                ea2 = ea1 + 1;
        }
    } while (false);
    if (end_ea != nullptr)
        *end_ea = ea2;

    return ea1;
}

//----------------------------------------------------------------------------------
inline const cinsn_t* hexrays_get_stmt_insn(
    cfunc_t* cfunc, 
    const citem_t* ui_item, 
    hexrays_ctreeparent_visitor_t **ohelper = nullptr)
{
    auto func_body = &cfunc->body;

    const citem_t* item = ui_item;
    const citem_t* stmt_item;

    hexrays_ctreeparent_visitor_t* helper = nullptr;

    if (ohelper != nullptr)
    {
        if (*ohelper == nullptr)
        {
            helper = new hexrays_ctreeparent_visitor_t();
            helper->apply_to(func_body, nullptr);
        }
        else
        {
            helper = *ohelper;
        }
    }

    auto get_parent = [func_body, &helper](const citem_t* item)
    {
        return helper == nullptr ? func_body->find_parent_of(item)
                                 : helper->parent_of(item);
    };

    // Get the top level statement from this item
    for (stmt_item = item; 
         item != nullptr && item->is_expr(); 
         item = get_parent(item))
    {
        stmt_item = item;
    }

    // ...then the actual instruction item
    if (stmt_item->is_expr())
        stmt_item = get_parent(stmt_item);

    if (ohelper != nullptr)
    {
        if (*ohelper == nullptr)
            *ohelper = helper;
    }

    return (const cinsn_t*)stmt_item;
}

//----------------------------------------------------------------------------------
inline bool hexrays_get_stmt_block_pos(
    cfunc_t* cfunc,
    const citem_t* stmt_item,
    cblock_t** p_cblock,
    cblock_t::iterator* p_pos,
    hexrays_ctreeparent_visitor_t* helper = nullptr)
{
    auto func_body = &cfunc->body;
    auto cblock_insn = (cinsn_t*)(
        helper == nullptr ? func_body->find_parent_of(stmt_item)
                          : helper->parent_of(stmt_item));

    if (cblock_insn == nullptr || cblock_insn->op != cit_block)
        return false;

    cblock_t* cblock = cblock_insn->cblock;

    for (auto p = cblock->begin(); p != cblock->end(); ++p)
    {
        if (&*p == stmt_item)
        {
            *p_pos = p;
            *p_cblock = cblock;
            return true;
        }
    }
    return false;
}

//----------------------------------------------------------------------------------
bool hexrays_are_acenstor_of(
    hexrays_ctreeparent_visitor_t* h, 
    cinsnptrvec_t& inst, 
    citem_t* item)
{
    for (auto parent : inst)
    {
        if (h->is_acenstor_of(parent, item))
            return true;
    }
    return false;
};

//----------------------------------------------------------------------------------
void hexrays_keep_lca_cinsns(
    cfunc_t* cfunc,
    hexrays_ctreeparent_visitor_t* helper,
    cinsnptrvec_t& bulk_list)
{
    cinsnptrvec_t new_list;
    while (!bulk_list.empty())
    {
        auto item = bulk_list.back();
        bulk_list.pop_back();

        if (!hexrays_are_acenstor_of(helper, bulk_list, item) && !hexrays_are_acenstor_of(helper, new_list, item))
            new_list.push_back(item);
    }
    new_list.swap(bulk_list);
}

//----------------------------------------------------------------------------------
struct hexrays_collect_cinsn_from_ea : public hexrays_ctreeparent_visitor_t
{
    cinsnptrvec_t* marked_insn = nullptr;
    eanodes_t* marked_ea = nullptr;

    hexrays_collect_cinsn_from_ea(cfunc_t* cfunc, eanodes_t* marked_ea, cinsnptrvec_t* marked_insn) :
        marked_ea(marked_ea), marked_insn(marked_insn)
    {
        apply_to(&cfunc->body, nullptr);
    }

    int idaapi visit_insn(cinsn_t* ins) override
    {
        hexrays_ctreeparent_visitor_t::visit_insn(ins);
        if (ins->op != cit_block && marked_ea->contains(ins->ea))
            marked_insn->push_back(ins);

        return 0;
    }
};
