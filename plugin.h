#pragma once

#pragma warning(push)
#pragma warning(disable: 4267 4083 4244)
#include <hexrays.hpp>
#include <kernwin.hpp>
#pragma warning(pop)

#define STORE_NODE_NAME          "$ hexrays strikeout-plugin"

#define ACTION_NAME_DELSTMT      "hexrays-strikeout-delstmt"
#define ACTION_NAME_PATCHSTMT    "hexrays-strikeout-patchstmt"
#define ACTION_NAME_DELSTMTS     "hexrays-strikeout-reset-delstmts"
#define ACTION_NAME_PATCHCODE    "hexrays-strikeout-patchcode"

//-------------------------------------------------------------------------
struct strikeout_plg_t;
struct base_ah_t : public action_handler_t
{
    strikeout_plg_t* plugmod;
    base_ah_t(strikeout_plg_t* _plugmod = nullptr) : plugmod(_plugmod) {}
};

#define DECL_ACTION(name) \
    struct name ## _ah_t : public base_ah_t \
    { \
        using base_ah_t::base_ah_t; \
        virtual int idaapi activate(action_activation_ctx_t* ctx) override; \
        static action_state_t get_state(TWidget *); \
                                                      \
        action_state_t idaapi update(action_update_ctx_t* ctx) override \
        { \
            return get_state(ctx->widget); \
        } \
    }
