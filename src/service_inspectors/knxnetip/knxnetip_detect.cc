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
// knxnetip_detect.cc author Alija Sabic <sabic@technikum-wien.at>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "knxnetip_detect.h"
#include "knxnetip_module.h"
#include "knxnetip_tables.h"
#include "knxnetip_dpt.h"

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "managers/event_manager.h"
#include "protocols/packet.h"

#include "log/messages.h"

void knxnetip::queue_event(const knxnetip::module::policy& policy, unsigned sid)
{
    if (policy.inspection) {
        snort::DetectionEngine::queue_event(GID_KNXNETIP, sid);
    }
}

void knxnetip::queue_event(unsigned sid)
{
    snort::DetectionEngine::queue_event(GID_KNXNETIP, sid);
}

void knxnetip::detection::detect(knxnetip::Packet& p, const knxnetip::module::policy& policy)
{

    /* Detect individual addressing */
    bool is_indiv_addr = is_individual_address(p);
    if (policy.individual_addressing)
    {

        if (is_indiv_addr)
        {
            knxnetip::queue_event(KNXNETIP_INDIV_ADDR);
        }
    }

    /* Detect valid group addresses (and dpt spec.) */
    bool is_invalid_grp_addr = is_invalid_group_address(p, policy);
    if (policy.group_addressing && !is_indiv_addr)
    {
        if (is_invalid_grp_addr)
        {
            knxnetip::queue_event(KNXNETIP_INVALID_GROUP_ADDR);
        }

        /* max/min */
        if (!is_invalid_grp_addr)
        {
            /* max */
            if (out_of_bound(p, policy, knxnetip::detection::Comp::higher))
            {
                knxnetip::queue_event(KNXNETIP_GRPADDR_MAX);
            }

            /* min */
            else if (out_of_bound(p, policy, knxnetip::detection::Comp::lower))
            {
                knxnetip::queue_event(KNXNETIP_GRPADDR_MIN);
            }
        }

        /* add to history */

        /* detect history */

    }

    /* Detect invalid services */

}


static
knxnetip::packet::CEMI* get_cemi_frame(knxnetip::Packet& p)
{
    using knxnetip::ServiceType;

    knxnetip::packet::CEMI* c = nullptr;

    switch(p.h->get_service_type())
    {
    case ServiceType::DEVICE_CONFIGURATION_REQ:
        c = &p.device_conf_request.cemi_frame;
        break;

    case ServiceType::TUNNELLING_REQ:
        c = &p.tunnelling_request.cemi_frame;
        break;

    case ServiceType::ROUTING_INDICATION:
        c = &p.routing_indication.cemi_frame;
        break;

    default:
        break;
    }

    return c;
}

bool knxnetip::detection::is_individual_address(knxnetip::Packet& p)
{
    using knxnetip::packet::cemi::MessageCode;

    knxnetip::packet::CEMI* c = get_cemi_frame(p);
    if (c == nullptr) return false;


    bool result = false;
    switch(c->get_message_code())
    {
        case MessageCode::L_DATA_REQ:
        case MessageCode::L_DATA_CON:
        case MessageCode::L_DATA_IND:
            result = c->data_link.data.is_individual_address();
            break;

        case MessageCode::L_POLL_DATA_REQ:
        case MessageCode::L_POLL_DATA_CON:
            result = c->data_link.poll_data.is_individual_address();
            break;

        default:
            break;
    }

    return result;
}

bool knxnetip::detection::is_invalid_group_address(knxnetip::Packet& p, const knxnetip::module::policy& policy)
{
    using knxnetip::packet::cemi::MessageCode;

    knxnetip::packet::CEMI* c = get_cemi_frame(p);
    if (c == nullptr) return false;


    bool result = false;
    uint16_t group_address = 0;
    switch(c->get_message_code())
    {
        case MessageCode::L_DATA_REQ:
        case MessageCode::L_DATA_CON:
        case MessageCode::L_DATA_IND:
            group_address = c->data_link.data.get_destination_addr();
            break;

        case MessageCode::L_POLL_DATA_REQ:
        case MessageCode::L_POLL_DATA_CON:
            group_address = c->data_link.poll_data.get_destination_addr();
            break;

        default:
            break;
    }

    if (group_address == 0) return false;

    /* Check if destination address is not a listed group address */
    if (policy.group_addresses.count(group_address) == 0)
    {
        result = true;
    }

    return result;
}


bool knxnetip::detection::out_of_bound(knxnetip::Packet& p, const knxnetip::module::policy& policy, knxnetip::detection::Comp comp)
{
    using knxnetip::packet::cemi::MessageCode;
    using knxnetip::packet::cemi::APDU;
    using knxnetip::packet::cemi::apdu::Type;

    knxnetip::packet::CEMI* c = get_cemi_frame(p);
    if (c == nullptr) return false;

    bool result = false;
    APDU* a = nullptr;
    uint16_t group_address = 0;

    switch(c->get_message_code())
    {
        case MessageCode::L_DATA_REQ:
        case MessageCode::L_DATA_CON:
        case MessageCode::L_DATA_IND:
            a = &c->data_link.data.npdu.apdu;
            group_address = c->data_link.data.get_destination_addr();
            break;

        default:
            break;
    }

    double maxima, minima;
    knxnetip::module::Spec spec;
    switch(a->get_apci())
    {
        case Type::A_GroupValue_Write:
        case Type::A_GroupValue_Read:
        case Type::A_GroupValue_Response:
            spec = policy.group_addresses.find(group_address)->second;
            if (comp == Comp::higher)
            {
                maxima = spec.max;
                if (knxnetip::dpt::is_dpt_higher(a->group_value, spec.dpt, maxima))
                {
                    result = true;
                }
            }
            else if (comp == Comp::lower)
            {
                minima = spec.min;
                if (knxnetip::dpt::is_dpt_lower(a->group_value, spec.dpt, minima))
                {
                    result = true;
                }
            }
            break;

        default:
            break;
    }

    return result;
}
