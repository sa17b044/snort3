//
// Created by alija on 15.05.18.
//

#ifndef KNXNETIP_H
#define KNXNETIP_H

#include <cstdint>
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

class KNXnetIPFlowData : public snort::FlowData
{
public:
    KNXnetIPFlowData();
    ~KNXnetIPFlowData() override;

    static void init();
//    { inspector_id = snort::FlowData::create_flow_data_id(); }

    void reset()
    {
    	session.state = 0;
    }

private:
    static unsigned inspector_id;
    KNXnetIPData session;

};

//int get_message_type(int version, const char* name);
//int get_info_type(int version, const char* name);
//
extern THREAD_LOCAL KNXnetIPStats knxnetip_stats;

#endif // KNXNETIP_H
