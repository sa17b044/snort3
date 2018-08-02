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

using namespace snort;

THREAD_LOCAL KNXnetIPStats knxnetip_stats;

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------
KNXnetIP::KNXnetIP(const knxnetip::module::param* p) : params(p)
{ }

KNXnetIP::~KNXnetIP()
{ }

bool KNXnetIP::configure(SnortConfig *sc)
{
    int i = 0;

    return true;
}

void KNXnetIP::show(SnortConfig *sc)
{

    int i = 0;
}

bool KNXnetIP::likes(Packet *p)
{
    return true;

    if(!p->has_udp_data()) {
        return false;
    }

    if(knxnetip::module::get_policy(params, p) == nullptr) {
        return false;
    }

    // check if KNXnet/IP

    // check if auto detect

    return true;
}


void KNXnetIP::eval(Packet *p)
{

    Profile profile(knxnetip_prof);
//    LogMessage("packet flags: \e[38;5;161m0x%x\e[39m\n\n", p->packet_flags);

    // get policy
    const knxnetip::module::policy* policy = knxnetip::module::get_policy(params, p);

    // decode packet
    knxnetip::Packet knxp{knxnetip::packet::dissect(p)};

    // analyze packet
    knxnetip::packet::detect(knxp, policy);

    // peg counts
    knxnetip_stats.frames++;

}

void KNXnetIP::clear(Packet *p)
{
    int i = 0;
}

void KNXnetIP::meta(int i, const uint8_t *d)
{
    int ii = 0;
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
