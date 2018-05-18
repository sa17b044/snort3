//
// Created by alija on 16.05.18.
//

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "knxnetip_module.h"
#include "profiler/profiler.h"
#include "knxnetip.h"

THREAD_LOCAL ProfileStats knxnetip_prof;


//-------------------------------------------------------------------------
// stats
//-------------------------------------------------------------------------
const PegInfo peg_names[] =
{
        { CountType::END, nullptr, nullptr }
};

const PegInfo* KNXnetIPModule::get_pegs() const
{ return peg_names; }

PegCount* KNXnetIPModule::get_counts() const
{ return (PegCount*)&knxnetip_stats; }

//-------------------------------------------------------------------------
// rules
//-------------------------------------------------------------------------
static const RuleMap knxnetip_rules[] =
{
        { 0, nullptr }
};

const RuleMap* KNXnetIPModule::get_rules() const
{ return knxnetip_rules; }

//-------------------------------------------------------------------------
// params
//-------------------------------------------------------------------------

KNXnetIPModule::KNXnetIPModule() : Module(KNXNETIP_NAME, KNXNETIP_HELP)
{ }