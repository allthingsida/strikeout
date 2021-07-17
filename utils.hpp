#pragma once

#include <pro.h>

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

//----------------------------------------------------------------------------------
struct codeitem_t
{
    ea_t ea = BADADDR;
    bytevec_t bytes;
    qstring cmt, rep_cmt;

    codeitem_t()                           { }
    codeitem_t(ea_t ea)                    { copy(ea, *this); }

    const size_t size() const              { return bytes.size(); }
    bool copy(ea_t ea)                     { return copy(ea, *this); }

    const bool operator !() const          { return ea == BADADDR; }
    // Since we filter out instructions that break basic blocks (contain addresses) then
    // we assume it is safe to compare instruction bytes.
    bool operator==(const codeitem_t& rhs) { return bytes == rhs.bytes; }

    codeitem_t& operator =(const ea_t src)
    {
        copy(src);
        return *this;
    }

    static bool copy(ea_t ea, codeitem_t& _this)
    {
        insn_t inst;
        if (!decode_insn(&inst, ea) || is_basic_block_end(inst, true))
            return false;

        auto sz = inst.size;

        get_cmt(&_this.cmt, ea, false);
        get_cmt(&_this.rep_cmt, ea, true);

        _this.bytes.resize(sz);
        get_bytes(_this.bytes.begin(), sz, ea);

        _this.ea = ea;

        return true;
    }

    ea_t paste(ea_t dst_ea) const
    {
        patch_bytes(dst_ea, bytes.begin(), bytes.size());
        set_cmt(dst_ea, cmt.c_str(), false);
        set_cmt(dst_ea, rep_cmt.c_str(), true);
        dst_ea += bytes.size();
        return dst_ea;
    }
};
