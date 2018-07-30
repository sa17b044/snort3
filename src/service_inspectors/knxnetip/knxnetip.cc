//--------------------------------------------------------------------------
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// knxnetip.cc author Alija Sabic <sabic@technikum-wien.at>

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
#include "knxnetip_decode.h"

using namespace snort;

THREAD_LOCAL KNXnetIPStats knxnetip_stats;

//-------------------------------------------------------------------------
// flow stuff
//-------------------------------------------------------------------------
unsigned KNXnetIPFlowData::inspector_id = 0;

void KNXnetIPFlowData::init()
{
	inspector_id = FlowData::create_flow_data_id();
}

void KNXnetIPFlowData::reset()
{
    session.state = 0;
}

KNXnetIPFlowData::KNXnetIPFlowData() : FlowData(inspector_id)
{
	reset();
//	knxnetip_stats.concurrent_sessions++;
//	if(knxnetip_stats.max_concurrent_sessions < knxnetip_stats.concurrent_sessions)
//		knxnetip_stats.max_concurrent_sessions = knxnetip_stats.concurrent_sessions;
}

KNXnetIPFlowData::~KNXnetIPFlowData()
{
//	assert(knxnetip_stats.concurrent_sessions > 0);
//	knxnetip_stats.concurrent_sessions--;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class KNXnetIP : public Inspector
{
public:
    KNXnetIP(const KNXnetIPParaList *params);
    ~KNXnetIP();

    bool configure(SnortConfig *) override;
    void show(SnortConfig *) override;
    void update(SnortConfig *, const char *) override;

    bool likes(Packet *p) override;

    void eval(Packet* p) override;
    void clear(Packet* p) override;

    void meta(int, const uint8_t *) override;
    int exec(int, void *) override;

    int get_message_type(int version, const char* name);
    int get_info_type(int version, const char* name);

private:
    const KNXnetIPParaList * const param;
};

KNXnetIP::KNXnetIP(const KNXnetIPParaList *params) : param(params)
{

}

KNXnetIP::~KNXnetIP()
{
    delete param;
}

bool KNXnetIP::configure(SnortConfig *sc)
{
    int i = 0;

    return true;
}

void KNXnetIP::show(SnortConfig *sc)
{

    int i = 0;
}

void KNXnetIP::update(SnortConfig *sc, const char *c)
{
    int i = 0;

}

bool KNXnetIP::likes(Packet *p)
{
    int i = 0;

    // check server config resp. policy

    // check if auto detect

    // check ip, port

    return true;
}


void KNXnetIP::eval(Packet *p)
{
//    LogMessage("Hello Snort!\n");
//    p->has_tcp_data();
//    p->has_udp_data();

//    if (p->is_full_pdu())
//    {
//        LogMessage("full pdu\n.");
//    }
//
    LogMessage("packet flags: \e[38;5;161m0x%x\e[39m\n\n", p->packet_flags);

    // get policy

    // peg counts

    // dissect

    // policy -> detect

    // alert

    // peg counts?


    Profile profile(KNXnetIPModule::get_profile_stats());

    KNXnetIPFlowData *knxfd
        {(KNXnetIPFlowData *)p->flow->get_flow_data(KNXnetIPFlowData::inspector_id)};

    // reset knxfd

    if (!knxfd)
    {
        knxfd = new KNXnetIPFlowData;
        p->flow->set_flow_data(knxfd);
        knxnetip_stats.total_frames++;
    }

    if (!KNXnetIPDecode(p))
        knxfd->reset();

}

void KNXnetIP::clear(Packet *p)
{
    int i = 0;
}

void KNXnetIP::meta(int i, const uint8_t *d)
{
    int ii = 0;
}

int KNXnetIP::exec(int i, void *v)
{
    int ii = 0;

    return 0;
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

static Inspector* knxnetip_ctor(Module *m)
{
    KNXnetIPModule * const mod = (KNXnetIPModule *)m;
    return new KNXnetIP(mod->get_params());
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
