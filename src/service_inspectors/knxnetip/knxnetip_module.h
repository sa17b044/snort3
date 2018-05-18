//
// Created by alija on 16.05.18.
//

#ifndef KNXNETIP_MODULE_H
#define KNXNETIP_MODULE_H

#include "framework/module.h"

#define GID_KNXNETIP 146

#define KNXNETIP_NAME "knxnetip"
#define KNXNETIP_HELP "knxnetip inspection"

extern THREAD_LOCAL snort::ProfileStats knxnetip_prof;

class KNXnetIPModule : public snort::Module
{
public:
    KNXnetIPModule();

    unsigned get_gid() const override
    { return GID_KNXNETIP; }

    const snort::RuleMap* get_rules() const override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    snort::ProfileStats* get_profile() const override
    { return &knxnetip_prof; }

    Usage get_usage() const override
    { return INSPECT; };
};


#endif // KNXNETIP_MODULE_H
