#pragma once

#include <pro.h>
#include <nalt.hpp>

//-------------------------------------------------------------------------
class eanodes_t
{
    easet_t eas; // Cached copy of inverted if-statement addresses
    netnode node;
    qstring nodename;
    bool use_relative;

public:
    eanodes_t(const char *nodename, bool use_relative=true): nodename(nodename), use_relative(use_relative) { load(); }
    const easet_t& nodes() { return eas; }

    bool load()
    {
        eas.clear();
        if (node.create(nodename.c_str())) // create failed -> exists already
            return false;

        size_t n;
        ea_t image_base = 0;
        if (use_relative)
        {
            image_base = get_imagebase();
            if (image_base == BADADDR)
                image_base = 0;
        }

        void* blob = node.getblob(NULL, &n, 0, 'I');
        if (blob != nullptr)
        {
            auto pea = (ea_t*)blob;
            for (size_t i = 0, count = n / sizeof(ea_t); i < count; ++i, ++pea)
                eas.insert(*pea + image_base);

            qfree(blob);
        }
        return true;
    }

    void save()
    {
        ea_t image_base = 0;
        if (use_relative)
        {
            image_base = get_imagebase();
            if (image_base == BADADDR)
                image_base = 0;
        }

        eavec_t copy;
        copy.resize(eas.size());
        size_t idx = 0;
        for (auto ea : eas)
            copy[idx++] = ea - image_base;

        node.setblob(copy.begin(), copy.size() * sizeof(ea_t), 0, 'I');
    }

    void add(ea_t ea, bool flush = true)
    {
        eas.insert(ea);
        if (flush)
            save();
    }

    void reset()
    {
        netnode node;
        node.create(nodename.c_str());
        node.delblob(0, 'I');
        node.kill();

        eas.clear();
        load();
    }

    bool contains(ea_t ea) const { return eas.find(ea) != eas.end(); }
    bool empty() const { return eas.empty(); }
};

