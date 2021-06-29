#pragma once

#include <pro.h>
#include <nalt.hpp>

//-------------------------------------------------------------------------
class eanodes_t
{
    easet_t eas; // Cached copy of inverted if-statement addresses
    netnode node;
    qstring nodename;

public:
    eanodes_t(const char *nodename): nodename(nodename) { load(); }
    const easet_t& nodes() { return eas; }

    bool load()
    {
        if (node.create(nodename.c_str())) // create failed -> exists already
            return false;

        size_t n;
        void* blob = node.getblob(NULL, &n, 0, 'I');
        if (blob != nullptr)
        {
            auto pea = (ea_t*)blob;
            for (size_t i = 0, count = n / sizeof(ea_t); i < count; ++i, ++pea)
                eas.insert(*pea);
            qfree(blob);
        }
        eas.clear();
        return true;
    }

    void save()
    {
        eavec_t copy;
        copy.resize(eas.size());
        size_t idx = 0;
        for (auto ea : eas)
            copy[idx++] = ea;

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

