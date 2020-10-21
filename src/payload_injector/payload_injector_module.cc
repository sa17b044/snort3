//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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

// payload_injector_module.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "payload_injector_module.h"

#include "detection/detection_engine.h"
#include "packet_io/active.h"
#include "protocols/packet.h"
#include "service_inspectors/http2_inspect/http2_flow_data.h"
#include "utils/util.h"

#define s_name "payload_injector"
#define s_help \
    "payload injection utility"

using namespace snort;

THREAD_LOCAL PayloadInjectorCounts payload_injector_stats;

const PegInfo payload_injector_pegs[] =
{
    { CountType::SUM, "http_injects", "total number of http injections" },
    { CountType::SUM, "http2_injects", "total number of http2 injections" },
    { CountType::SUM, "http2_translate_err", "total number of http2 page translation errors" },
    { CountType::SUM, "http2_mid_frame", "total number of attempts to inject mid-frame" },
    { CountType::END, nullptr, nullptr }
};

// Should have an entry for each error in InjectionReturnStatus
static const std::map <InjectionReturnStatus, const char*> InjectionErrorToString =
{
    { ERR_INJECTOR_NOT_CONFIGURED, "Payload injector is not configured" },
    { ERR_STREAM_NOT_ESTABLISHED, "TCP stream not established" },
    { ERR_UNIDENTIFIED_PROTOCOL, "Unidentified protocol" },
    { ERR_HTTP2_STREAM_ID_0, "HTTP/2 - injection to stream 0" },
    { ERR_PAGE_TRANSLATION, "Error in translating HTTP block page to HTTP/2. "
      "Unsupported or bad format." },
    { ERR_HTTP2_MID_FRAME, "HTTP/2 - attempt to inject mid frame. Currently not supported." },
    { ERR_TRANSLATED_HDRS_SIZE,
      "HTTP/2 translated header size is bigger than expected. Update max size." },
    { ERR_HTTP2_BODY_SIZE, "HTTP/2 body is > 16k. Currently not supported." },
    { ERR_HTTP2_EVEN_STREAM_ID, "HTTP/2 - injection to server initiated stream" }
};

bool PayloadInjectorModule::configured = false;

PayloadInjectorModule::PayloadInjectorModule() :
    Module(s_name, s_help)
{ }

const PegInfo* PayloadInjectorModule::get_pegs() const
{ return payload_injector_pegs; }

PegCount* PayloadInjectorModule::get_counts() const
{ return (PegCount*)&payload_injector_stats; }

bool PayloadInjectorModule::end(const char*, int, SnortConfig*)
{
    configured = true;
    return true;
}

InjectionReturnStatus PayloadInjectorModule::inject_http2_payload(Packet* p,
    const InjectionControl& control, EncodeFlags df)
{
    InjectionReturnStatus status;

    if (control.stream_id == 0)
        status = ERR_HTTP2_STREAM_ID_0;
    else if (control.stream_id % 2 == 0)
    {
        // Don't inject against server initiated streams
        status = ERR_HTTP2_EVEN_STREAM_ID;
    }
    else
    {
        // Check if mid frame
        Http2FlowData* const session_data =
            (Http2FlowData*)p->flow->get_flow_data(Http2FlowData::inspector_id);
        if (!session_data || session_data->is_mid_frame())
        {
            payload_injector_stats.http2_mid_frame++;
            // FIXIT-E mid-frame injection not supported
            status = ERR_HTTP2_MID_FRAME;
        }
        else
        {
            uint8_t* http2_payload;
            uint32_t payload_len;
            status = get_http2_payload(control, http2_payload, payload_len);
            if (status == INJECTION_SUCCESS)
            {
                p->active->send_data(p, df, http2_payload, payload_len);
                snort_free(http2_payload);
                payload_injector_stats.http2_injects++;
                return INJECTION_SUCCESS;
            }
            else
                payload_injector_stats.http2_translate_err++;
        }
    }

    // If we got here, shouldn't inject the page
    p->active->send_data(p, df, nullptr, 0);
    return status;
}

InjectionReturnStatus PayloadInjectorModule::inject_http_payload(Packet* p,
    const InjectionControl& control)
{
    InjectionReturnStatus status = INJECTION_SUCCESS;

    assert(p != nullptr);

    if (configured)
    {
        EncodeFlags df = (p->packet_flags & PKT_FROM_SERVER) ? ENC_FLAG_FWD : 0;
        df |= ENC_FLAG_RST_SRVR; // Send RST to server.

        if (p->packet_flags & PKT_STREAM_EST)
        {
            if (!p->flow)
                status = ERR_UNIDENTIFIED_PROTOCOL;
            else if (!p->flow->gadget || strcmp(p->flow->gadget->get_name(),"http_inspect") == 0)
            {
                payload_injector_stats.http_injects++;
                p->active->send_data(p, df, control.http_page, control.http_page_len);
            }
            else if (strcmp(p->flow->gadget->get_name(),"http2_inspect") == 0)
                status = inject_http2_payload(p, control, df);
            else
                status = ERR_UNIDENTIFIED_PROTOCOL;
        }
        else
            status = ERR_STREAM_NOT_ESTABLISHED;
    }
    else
        status = ERR_INJECTOR_NOT_CONFIGURED;

    p->active->block_session(p, true);

    DetectionEngine::disable_all(p);

    if ( p->flow )
        p->flow->set_state(Flow::FlowState::BLOCK);

    return status;
}

const char* PayloadInjectorModule::get_err_string(InjectionReturnStatus status)
{
    auto iter = InjectionErrorToString.find(status);
    assert (iter != InjectionErrorToString.end());
    return iter->second;
}

