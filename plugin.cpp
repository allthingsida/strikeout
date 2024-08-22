/*
StrikeOut: a plugin that allows you to delete ctree statements and patch the disassembly code.

When StrikeOut is active, you will see context menu items in the decompiler window.

(c) Elias Bachaalany <elias.bachaalany@gmail.com>
*/

#include "plugin.h"
#include "storage.hpp"
#include "utils.hpp"
#include <memory>

//-------------------------------------------------------------------------
struct strikeout_plg_t : public plugmod_t, event_listener_t
{
    action_manager_t    am;
    eanodes_t           marked;
    eavec_t             patchstmt_queue;

    strikeout_plg_t() : am(this), marked(STORE_NODE_NAME)
    {
        install_hexrays_callback(hr_callback, this);

        setup_ui();
    }

    static ssize_t idaapi hr_callback(void* ud, hexrays_event_t event, va_list va)
    {
        strikeout_plg_t* plugmod = (strikeout_plg_t*)ud;
        switch (event)
        {
            case hxe_populating_popup:
                plugmod->am.on_hxe_populating_popup(va);
                break;

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

    ssize_t idaapi on_event(ssize_t code, va_list va) override
    {
        if (code == ui_finish_populating_widget_popup)
            am.on_ui_finish_populating_widget_popup(va);

        return 0;
    }

    void setup_ui()
    {
        am.set_popup_path("StrikeOut/");

        // Delete statement
        am.add_action(
            AMAHF_HXE_POPUP,
            ACTION_NAME_DELSTMT,
            "Delete statement",
            "Del",     
            hexrays_default_enable_for_vd_expr,
            FO_ACTION_ACTIVATE([this]) {
                vdui_t &vu   = *get_widget_vdui(ctx->widget);
                ea_t stmt_ea = this->do_del_stmt(vu);
                if (stmt_ea != BADADDR)
                    this->marked.add(stmt_ea);

                vu.refresh_ctext();
                return 1;
            }
        );

        // Patch code
        am.add_action(
            AMAHF_HXE_POPUP | AMAHF_IDA_POPUP,
            ACTION_NAME_PATCHCODE,
            "Patch disassembly code",
            "Ctrl-Shift-Del",
            am.default_enable_for_vd_disasm,
            FO_ACTION_ACTIVATE([this]) {
                return this->do_patch_disasm_code(ctx->widget);
            }
        );

        // Move line: up
        am.add_action(
            AMAHF_IDA_POPUP,
            ACTION_NAME_DISASM_LINEUP,
            "Move line up",
            "Alt-Shift-Up",
            am.default_enable_for_disasm,
            FO_ACTION_ACTIVATE([this]) {
                return this->do_move_disasm_line(ctx->cur_ea, true);
            }
        );

        // Move line: down
        am.add_action(
            AMAHF_IDA_POPUP,
            ACTION_NAME_DISASM_LINEDOWN,
            "Move line down",
            "Alt-Shift-Down",
            am.default_enable_for_disasm,
            FO_ACTION_ACTIVATE([this]) {
                return this->do_move_disasm_line(ctx->cur_ea, false);
            }
        );

        // Flush the statement patcher
        am.add_action(
            AMAHF_HXE_POPUP,
            ACTION_NAME_PATCHSTMT_FLUSH,
            "Apply patch statements queue",
            "Alt-Shift-End",
            hexrays_default_enable_for_vd,
            FO_ACTION_ACTIVATE([this]) {
                vdui_t& vu = *get_widget_vdui(ctx->widget);
                this->do_flush_patch_stmt(vu);
                return 0;
            }
        );

        // ================================ Clear =============================
        am.set_popup_path("StrikeOut/Clear/");

        // Transfer hidden statements as a patch
        am.add_action(
            AMAHF_HXE_POPUP | AMAHF_IDA_POPUP,
            ACTION_NAME_DEL2PATCH,
            "Reset deleted statements for current function",
            "Alt-Shift-Ins",
            am.default_enable_for_vd_disasm,
            FO_ACTION_ACTIVATE([this]) {
                this->do_transfer_to_patch_queue(ctx);
                vdui_t *vu = get_widget_vdui(ctx->widget);
                if (vu != nullptr)
                    vu->refresh_ctext();
                return 1;
        });

        // Clear the queue patch statements
        am.add_action(
            AMAHF_HXE_POPUP | AMAHF_IDA_POPUP,
            ACTION_NAME_PATCHSTMT_CLEAR,
            "Clear patch statement queue",
            "Alt-Shift-Del",
            am.default_enable_for_vd_disasm, 
            FO_ACTION_ACTIVATE([this]) {
                this->patchstmt_queue.qclear();
                return 0;
            }
        );

        // Reset all deleted statements
        am.add_action(
            AMAHF_HXE_POPUP,
            ACTION_NAME_DELSTMTS,
            "Clear all deleted statements",
            "",
            hexrays_default_enable_for_vd,
            FO_ACTION_ACTIVATE([this]) {
                vdui_t &vu = *get_widget_vdui(ctx->widget);
                this->do_reset_stmts(vu);
                vu.refresh_ctext();
                return 1;
           }
        );
        am.set_popup_path();

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
        hexrays_collect_cinsn_from_ea helper(cfunc, &marked, &marked_insn);

        hexrays_keep_lca_cinsns(cfunc, &helper, marked_insn);

        for (auto stmt_item : marked_insn)
        {
            cblock_t* cblock;
            cblock_t::iterator pos;
            if (hexrays_get_stmt_block_pos(cfunc, stmt_item, &cblock, &pos, &helper))
                cblock->erase(pos);
        }
        cfunc->remove_unused_labels();
    }

    // Move disassembly lines
    int do_move_disasm_line(ea_t ea, bool up)
    {
        // Sort addresses
        codeitem_t items[2];

        items[0] = up ? ea : next_head(ea, BADADDR);
        items[1] = up ? prev_head(ea, 0) : ea;

        if (!items[0] || !items[1])
        {
            msg("Cannot swap at %a\n", ea);
            return 0;
        }

        if (items[0] == items[1])
            return 0;

        ea_t start_ea, end_ea;
        start_ea = items[1].ea;
        end_ea   = items[0].ea + ea_t(items[0].size());
        
        auto old_auto = enable_auto(false);

        msg("Swapping....%a and %a\n", start_ea, end_ea);

        del_items(start_ea, 0, end_ea - start_ea);

        // Paste elements
        end_ea = items[0].paste(start_ea);
        ea     = items[1].paste(end_ea);

        // Re-create instructions
        create_insn(start_ea);

        enable_auto(old_auto);
        auto_wait();

        ea_t navto = up ? start_ea : end_ea;
        jumpto(navto);

        return 1;
    }

    int do_patch_disasm_code(TWidget* widget)
    {
        ea_t ea2;
        ea_t ea1 = get_selection_range(widget, &ea2, BWN_DISASM);
        if (ea1 == BADADDR)
        {
            auto vu = get_widget_vdui(widget);
            if (vu == nullptr || vu->item.citype != VDI_EXPR)
                return 0;

            ea1 = vu->item.get_ea();
            if (ea1 == BADADDR || (ea2 = next_head(ea1, BADADDR) == BADADDR))
                return 0;
        }

        msg("patched selection: %a .. %a\n", ea1, ea2);
        for (; ea1 < ea2; ++ea1)
            patch_byte(ea1, 0x90);

        return 1;
    }

    ea_t do_del_stmt(vdui_t& vu, bool use_helper=true)
    {
        auto cfunc = vu.cfunc;
        auto item = vu.item.i;

        hexrays_ctreeparent_visitor_ptr_t helper;
        const citem_t* stmt_item = hexrays_get_stmt_insn(cfunc, item, use_helper ? &helper : nullptr);
        if (stmt_item == nullptr)
            return BADADDR;

        ea_t stmt_ea = stmt_item->ea;

        cblock_t* cblock;
        cblock_t::iterator pos;
        if (hexrays_get_stmt_block_pos(
                cfunc, 
                stmt_item, 
                &cblock, 
                &pos, 
                use_helper ? helper.get() : nullptr))
        {
            cblock->erase(pos);
            cfunc->remove_unused_labels();
#if _DEBUG
            cfunc->verify(ALLOW_UNUSED_LABELS, true);
#endif
        }

        return stmt_ea;
    }

    void do_flush_patch_stmt(vdui_t& vu)
    {
        // Walk the tree just to get citem_t* from actual saved EAs
        struct collect_eas_t : public hexrays_ctreeparent_visitor_t
        {
            std::map<ea_t, int> eas;
            bool do_remember = false;

            void clear() { eas.clear(); }

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
                if (do_remember)
                    remember(ins->ea);
                hexrays_ctreeparent_visitor_t::visit_insn(ins);
                return 0;
            }

            int idaapi visit_expr(cexpr_t* expr)
            {
                if (do_remember)
                    remember(expr->ea);
                hexrays_ctreeparent_visitor_t::visit_expr(expr);
                return 0;
            }
        } ti;

        auto cfunc = vu.cfunc;
        ti.do_remember = false;
        ti.apply_to(&cfunc->body, nullptr);

        static char noops[32] = { 0 };
        if (!noops[0])
            memset(noops, 0x90, sizeof(noops));

        // Collect all children
        ti.do_remember = true;
        for (auto ea : patchstmt_queue)
        {
            auto citem = ti.by_ea(ea);
            if (citem == nullptr)
                continue;

            ti.apply_to((citem_t*)citem, nullptr);
        }

        for (auto& kv : ti.eas)
        {
            if (kv.second == 0)
                continue;

            patch_bytes(kv.first, noops, kv.second);
            msg("Patching %a with %d byte(s)...\n", kv.first, kv.second);
        }
        
        msg("Total: %u\n", uint(ti.eas.size()));

        patchstmt_queue.clear();
    }

    void do_reset_stmts(vdui_t& vu)
    {
        marked.reset();
    }

    void do_transfer_to_patch_queue(action_activation_ctx_t *ctx)
    {
        if (!marked.load() || ctx->cur_func == nullptr)
        {
            msg("No hidden statements or not positioned in a function!\n");
            return;
        }

        auto f_ea = ctx->cur_func->start_ea;
        for (auto it = marked.nodes().begin(), end=marked.nodes().end(); it != end; )
        {
            ea_t ea = *it;
            auto f = get_func(ea);
            if (f != nullptr && f->start_ea == f_ea)
            {
                patchstmt_queue.push_back(ea);
                marked.nodes().erase(it++);
            }
            else
            {
                ++it;
            }
        }
        marked.save();
        msg("Removed %u hidden statement(s) and moved to patch queue. Refresh to pseudo-code to take effect.\n", (uint)patchstmt_queue.size());
    }
};

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_HIDE | PLUGIN_MULTI,
    []()->plugmod_t* { return init_hexrays_plugin() ? new strikeout_plg_t() : nullptr; }, // initialize
    nullptr,
    nullptr,
    "StrikeOut: Hex-Rays statements editor",
    "",
    "hxstrikeout",
    ""
};
