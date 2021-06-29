/*
StrikeOut: a plugin that allows you to delete Ctree statements and patch the disassembly code.

When StrikeOut is active, you will see context menu items in the decompiler window.

(c) Elias Bachaalany <elias.bachaalany@gmail.com>
*/

#include "plugin.h"
#include "storage.hpp"
#include "utils.hpp"

DECL_ACTION(delstmt);
DECL_ACTION(patchstmt);
DECL_ACTION(reset_delstmts);
DECL_ACTION(patchcode);

static ssize_t idaapi hr_callback(
    void* ud, 
    hexrays_event_t event, 
    va_list va);

//-------------------------------------------------------------------------
struct strikeout_plg_t : public plugmod_t, event_listener_t
{
    delstmt_ah_t        delstmt_ah;
    reset_delstmts_ah_t reset_delstmts_ah;
    patchstmt_ah_t      patchstmt_ah;
    patchcode_ah_t      patchcode_ah;

    eanodes_t marked;

    strikeout_plg_t() :
        patchstmt_ah(this), delstmt_ah(this), reset_delstmts_ah(this), patchcode_ah(this),
        marked(STORE_NODE_NAME)
    {
        install_hexrays_callback(hr_callback, this);

        setup_actions();
    }

    ssize_t idaapi on_event(ssize_t code, va_list va) override
    {
        if (code == ui_finish_populating_widget_popup)
        {
            TWidget* widget = va_arg(va, TWidget*);
            TPopupMenu* popup_handle = va_arg(va, TPopupMenu*);
            if (patchcode_ah_t::get_state(widget) <= AST_ENABLE)
                attach_action_to_popup(widget, popup_handle, ACTION_NAME_PATCHCODE);
        }
        return 0;
    }

    void setup_actions()
    {
        struct action_item_t
        {
            base_ah_t* act;
            const char* name;
            const char* hotkey;
            const char* desc;
        } actions[] = {
            {&delstmt_ah,        ACTION_NAME_DELSTMT,   "Del",            "StrikeOut: Delete statement"},
            {&patchstmt_ah,      ACTION_NAME_PATCHSTMT, "Ctrl-Shift-Del", "StrikeOut: Patch statement"},
            {&reset_delstmts_ah, ACTION_NAME_DELSTMTS,  "",               "StrikeOut: Reset all deleted statements"},
            {&patchcode_ah,      ACTION_NAME_PATCHCODE, "Ctrl-Shift-Del", "StrikeOut: Patch disassembly code"},
            { }
        };

        for (auto& act : actions)
        {
            register_action(ACTION_DESC_LITERAL_PLUGMOD(
                act.name,
                act.desc,
                act.act,
                this,
                act.hotkey,
                NULL,
                -1));
        }

        hook_event_listener(HT_UI, this);
    }

    virtual ~strikeout_plg_t()
    {
        remove_hexrays_callback(hr_callback, this);
    }

    bool idaapi run(size_t) override 
    { 
        return false; 
    }

    void transform_ctree(cfunc_t* cfunc)
    {
        marked.load();

        cinsnptrvec_t marked_insn;

        // Walk the tree just to get citem_t* from actual saved EAs
        struct ctreeinfo_t : public ctree_visitor_t
        {
            strikeout_plg_t* self = nullptr;
            cinsnptrvec_t* marked_insn = nullptr;

            ctreeinfo_t(strikeout_plg_t* self, cinsnptrvec_t* marked_insn) :
                self(self), marked_insn(marked_insn), ctree_visitor_t(CV_FAST) { }

            int idaapi visit_insn(cinsn_t* ins) override
            {
                if (self->marked.contains(ins->ea))
                    marked_insn->push_back(ins);
                return 0;
            }
        } ti(this, &marked_insn);

        ti.apply_to(&cfunc->body, nullptr);

        for (auto stmt_item : marked_insn)
        {
            if (stmt_item->op == cit_block)
                continue;

            cblock_t* cblock;
            cblock_t::iterator pos;
            if (hexrays_get_stmt_block_pos(cfunc, stmt_item, &cblock, &pos))
                cblock->erase(pos);
        }
        cfunc->remove_unused_labels();
    }

    ea_t do_del_stmt(vdui_t& vu)
    {
        auto cfunc = vu.cfunc;
        auto item = vu.item.i;

        citem_t* stmt_item = hexrays_get_stmt_insn(cfunc, item);

        if (stmt_item == nullptr)
            return BADADDR;

        ea_t stmt_ea = stmt_item->ea;

        cblock_t* cblock;
        cblock_t::iterator pos;

        if (hexrays_get_stmt_block_pos(cfunc, stmt_item, &cblock, &pos))
        {
            cblock->erase(pos);
            cfunc->remove_unused_labels();
        }

        return stmt_ea;
    }

    ea_t do_patch_stmt(vdui_t& vu)
    {
        auto cfunc = vu.cfunc;
        auto item = vu.item.i;

        citem_t* stmt_item = hexrays_get_stmt_insn(cfunc, item);

        if (stmt_item == nullptr)
            return BADADDR;

        static char noops[32] = { 0 };
        if (!noops[0])
            memset(noops, 0x90, sizeof(noops));

        // Walk the tree just to get citem_t* from actual saved EAs
        using ea_size_t = std::map<ea_t, int>;
        struct collect_eas_t : public ctree_visitor_t
        {
            ea_size_t eas;

            collect_eas_t() : ctree_visitor_t(CV_PARENTS) { }

            void remember(ea_t ea)
            {
                if (ea == BADADDR)
                    return;
                auto p = eas.find(ea);
                if (p != eas.end())
                    return;

                insn_t ins;
                decode_insn(&ins, ea);
                eas[ea] = int(ins.size);
            }

            int idaapi visit_insn(cinsn_t* ins) override
            {
                remember(ins->ea);
                return 0;
            }

            int idaapi visit_expr(cexpr_t* expr)
            {
                remember(expr->ea);
                return 0;
            }
        } ti;

        ti.apply_to(stmt_item, nullptr);
        for (auto& kv : ti.eas)//=eas.begin(); p != eas.end(); ++p)
        {
            if (kv.second == 0)
                continue;

            patch_bytes(kv.first, noops, kv.second);
            msg("Patching %a with %d byte(s)...\n", kv.first, kv.second);
        }

        return BADADDR;
    }

    void do_reset_stmts(vdui_t& vu)
    {
        marked.reset();
    }
};

//--------------------------------------------------------------------------
// This decompiler callback handles various hexrays events.
static ssize_t idaapi hr_callback(void* ud, hexrays_event_t event, va_list va)
{
    strikeout_plg_t* plugmod = (strikeout_plg_t*)ud;
    switch (event)
    {
        case hxe_populating_popup:
        {
            TWidget* widget = va_arg(va, TWidget*);
            TPopupMenu* popup = va_arg(va, TPopupMenu*);
            vdui_t* vu = va_arg(va, vdui_t*);
            if (delstmt_ah_t::get_state(widget) <= AST_ENABLE)
                attach_action_to_popup(widget, popup, ACTION_NAME_DELSTMT);
            if (patchstmt_ah_t::get_state(widget) <= AST_ENABLE)
                attach_action_to_popup(widget, popup, ACTION_NAME_PATCHSTMT);
            if (reset_delstmts_ah_t::get_state(widget) <= AST_ENABLE)
                attach_action_to_popup(widget, popup, ACTION_NAME_DELSTMTS);

            break;
        }

        case hxe_maturity:
        {
            auto cfunc = va_arg(va, cfunc_t*);

            ctree_maturity_t new_maturity = va_argi(va, ctree_maturity_t);
            if (new_maturity == CMAT_FINAL)
                plugmod->transform_ctree(cfunc);

            break;
        }
    }
    return 0;
}

//-------------------------------------------------------------------------
//                            Action handlers
//-------------------------------------------------------------------------
action_state_t delstmt_ah_t::get_state(TWidget *widget)
{
    auto vu = get_widget_vdui(widget);
    return (vu == nullptr) ? AST_DISABLE_FOR_WIDGET
                           : vu->item.citype != VDI_EXPR ? AST_DISABLE : AST_ENABLE;
}

action_state_t patchstmt_ah_t::get_state(TWidget* widget)
{
    return delstmt_ah_t::get_state(widget);
}

action_state_t reset_delstmts_ah_t::get_state(TWidget* widget)
{
    auto vu = get_widget_vdui(widget);
    return vu == nullptr ? AST_DISABLE_FOR_WIDGET : AST_ENABLE;
}

action_state_t patchcode_ah_t::get_state(TWidget *widget)
{
    return get_widget_type(widget) == BWN_DISASM ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
}

// Delete a Ctree statement
int idaapi delstmt_ah_t::activate(action_activation_ctx_t* ctx)
{
    vdui_t& vu = *get_widget_vdui(ctx->widget);

    ea_t stmt_ea = plugmod->do_del_stmt(vu);
    if (stmt_ea != BADADDR)
        plugmod->marked.add(stmt_ea);

    vu.refresh_ctext();
    return 1;
}

// Reset all deleted statements
int idaapi reset_delstmts_ah_t::activate(action_activation_ctx_t* ctx)
{
    vdui_t& vu = *get_widget_vdui(ctx->widget);
    plugmod->do_reset_stmts(vu);
    vu.refresh_ctext();

    return 1;
}

// Patch code
int idaapi patchcode_ah_t::activate(action_activation_ctx_t* ctx)
{
    ea_t ea2;
    ea_t ea1 = get_selection_range(ctx->widget, &ea2, BWN_DISASM);
    if (ea1 == BADADDR)
        return 0;

    for (; ea1 < ea2; ++ea1)
    {
        msg("selection: %a .. %a\n", ea1, ea2);
        patch_byte(ea1, 0x90);
    }

    return 1;
}

// Patch selected statement and its children
int idaapi patchstmt_ah_t::activate(action_activation_ctx_t* ctx)
{
    vdui_t& vu = *get_widget_vdui(ctx->widget);
    ea_t stmt_ea = plugmod->do_patch_stmt(vu);
    return 1;
}

//--------------------------------------------------------------------------
// Initialize the plugin.
static plugmod_t* idaapi init()
{
    return init_hexrays_plugin() ? new strikeout_plg_t() : nullptr;
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_HIDE | PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
    "StrikeOut: Hex-Rays statements editor",
    "",
    "hxstrikeout",
    ""
};
