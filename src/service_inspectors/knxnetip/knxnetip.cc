//
// Created by alija on 15.05.18.
//

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "knxnetip.h"


#include "events/event_queue.h"
#include "detection/detection_engine.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "log/messages.h"

#include "knxnetip_module.h"

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class KNXnetIP : public Inspector
{
public:
    // default ctor / dtor
    void eval(Packet *p) override;

    int get_message_type(int version, const char* name);
    int get_info_type(int version, const char* name);
};

void KNXnetIP::eval(Packet *p)
{
    LogMessage("Hello Snort!\n");

    p->has_tcp_data();

    p->has_udp_data();
}

int KNXnetIP::get_message_type(int version, const char *name)
{

    return 0;
}

int KNXnetIP::get_info_type(int version, const char *name)
{


    return 0;
}

//-------------------------------------------------------------------------
// api/plugin stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new KNXnetIPModule; }

static void mod_dtor(Module *m)
{ delete m; }

static void knxnetip_init()
{
    KNXnetIPFlowData::init();
}

static Inspector* knxnetip_ctor(Module *)
{
    return new KNXnetIP;
}

static void knxnetip_dtor(Inspector* p)
{
    delete p;
}

//-------------------------------------------------------------------------

static const InspectApi knxnetip_api =
{
        {                                   // BaseApi 
            PT_INSPECTOR,
            sizeof(InspectApi),
            INSAPI_VERSION,
            0,
            API_RESERVED,
            API_OPTIONS,
            KNXNETIP_NAME,
            KNXNETIP_HELP,
            mod_ctor,
            mod_dtor
        },
        IT_SERVICE,                         // InspectorType
        (uint16_t)PktType::PDU,             // packet type
        nullptr,                            // exported buffers
        "knxnetip",                         // service
        knxnetip_init,                      // plugin init
        nullptr,                            // cleanup pinit()
        nullptr,                            // thread local init
        nullptr,                            // cleanup thread local init
        knxnetip_ctor,                      // instantiate inspector from `Module` data
        knxnetip_dtor,                      // release inspector instance
        nullptr,                            // get new session tracker
        nullptr                             // clear stats
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* sin_knxnetip[] =
#endif
{
    &knxnetip_api.base,
    nullptr
};