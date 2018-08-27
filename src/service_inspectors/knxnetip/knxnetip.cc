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
#include "knxnetip_detect.h"
#include "knxnetip_module.h"
#include "knxnetip_packet.h"

#include "events/event_queue.h"
#include "detection/detection_engine.h"
#include "profiler/profiler.h"
#include "log/messages.h"
#include "log/text_log.h"

using namespace snort;

THREAD_LOCAL KNXnetIPStats knxnetip_stats;

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------
KNXnetIP::KNXnetIP(knxnetip::module::param* p) : params(p)
{ }

KNXnetIP::~KNXnetIP()
{ }

//bool KNXnetIP::configure(SnortConfig *sc)
//{
//    return true;
//}

//void KNXnetIP::show(SnortConfig *sc)
//{
//    return true;
//}

bool KNXnetIP::likes(Packet *p)
{
    if(!p->has_udp_data()) {
        return false;
    }

    if (params->global_policy > 0) {
        return true;
    }

    const knxnetip::module::server* s = knxnetip::module::get_server_src(params, p);
    if (s != nullptr) {
        return true;
    }

    s = knxnetip::module::get_server_dst(params, p);
    if (s != nullptr) {
        return true;
    }

    return true;
}


void KNXnetIP::eval(Packet *p)
{
    knxnetip::Packet knxp{};
    Profile profile(knxnetip_prof);

    knxnetip::module::server* server;
    const knxnetip::module::policy* policy;

    // get server config
    if (knxnetip::module::get_server_src(params, p) != nullptr)
    {
        server = knxnetip::module::get_server_src(params, p);
        policy = knxnetip::module::get_policy_src(params, p);
    }
    else
    {
        server = knxnetip::module::get_server_dst(params, p);
        policy = knxnetip::module::get_policy_dst(params, p);
    }

    knxnetip::module::open_log(*server);

    // dissect packet
    if (policy != nullptr and knxp.dissect(*p, *server, *policy))
    {
        // analyze packet
        knxnetip::detection::detect(*p, knxp, *server, *policy);
        knxnetip_stats.valid_frames++;
    }

    // peg counts
    knxnetip_stats.frames++;
    knxnetip::module::close_log(*server);
}

//void KNXnetIP::clear(Packet *p)
//{ }

//void KNXnetIP::meta(int i, const uint8_t *d)
//{ }

//int KNXnetIP::get_message_type(int version, const char *name)
//{
//    return 0;
//}
//
//int KNXnetIP::get_info_type(int version, const char *name)
//{
//    return 0;
//}

//-------------------------------------------------------------------------
// api/plugin stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new KNXnetIPModule; }

static void mod_dtor(Module *m)
{ delete m; }

static void knxnetip_init()
{ }

static Inspector* knxnetip_ctor(Module *m)
{
    KNXnetIPModule* const mod = static_cast<KNXnetIPModule*>(m);
    return new KNXnetIP(&mod->params);
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
    nullptr,                           // exported buffers
    "knxnetip",                         // service
    knxnetip_init,                      // plugin init
    nullptr,                           // cleanup pinit()
    nullptr,                           // thread local init
    nullptr,                           // cleanup thread local init
    knxnetip_ctor,                      // instantiate inspector from `Module` data
    knxnetip_dtor,                      // release inspector instance
    nullptr,                           // get new session tracker
    nullptr                            // clear stats
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
