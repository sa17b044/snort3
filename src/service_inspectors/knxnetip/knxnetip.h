//
// Created by alija on 15.05.18.
//

#ifndef KNXNETIP_H
#define KNXNETIP_H

#include "flow/flow.h"
#include "framework/counts.h"

struct KNXnetIPStats
{
    PegCount sessions;
    PegCount frames;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
};

// (Per-session) data block containing current state
// of the KNXnetIP preprocessor.
struct KNXnetIPData
{
    uint32_t state;
};

class KNXnetIPFlowData : public FlowData
{
public:
    KNXnetIPFlowData();
    ~KNXnetIPFlowData() override;

    static void init()
    { inspector_id = FlowData::create_flow_data_id(); }

public:
    static unsigned inspector_id;
    KNXnetIPData session;
};

//int get_message_type(int version, const char* name);
//int get_info_type(int version, const char* name);
//
extern THREAD_LOCAL KNXnetIPStats knxnetip_stats;

#endif // KNXNETIP_H
