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

#include <sys/stat.h>
#include <regex>
#include <string>
#include <sstream>
#include <algorithm>

#include "knxnetip_detect.h"
#include "knxnetip_module.h"
#include "knxnetip_tables.h"
#include "knxnetip_dpt.h"
#include "knxnetip.h"

#include "events/event_queue.h"
#include "detection/detection_engine.h"
#include "main/snort_config.h"
#include "managers/event_manager.h"
#include "protocols/packet.h"
#include "protocols/packet_manager.h"

#include "log/messages.h"
#include "log/log_text.h"
#include "log/text_log.h"

std::string knxnetip::detection::get_rule_string(std::string rule, bool file)
{
    using std::regex_constants::match_any;
    using std::regex_replace;

    std::string result {};
    std::regex start {R"(<em>)"};
    std::regex end {R"(</em>)"};

    if (file)
    {
        result = regex_replace(rule, start, "", match_any);
        result = regex_replace(result, end, "", match_any);
    }
    else
    {
        result = regex_replace(rule, start, KNXNETIP_ALERT_CON_EM, match_any);
        result = regex_replace(result, end, KNXNETIP_ALERT_CON_EM_RESET, match_any);
    }

    std::stringstream ss {};
    ss << KNXNETIP_ALERT_START << result << KNXNETIP_ALERT_END;

    return ss.str();
}

void knxnetip::queue_event(unsigned sid, const snort::Packet& p, const knxnetip::module::server& server, const knxnetip::module::policy& policy)
{
    if (policy.inspection) {
        snort::DetectionEngine::queue_event(GID_KNXNETIP, sid);

        if (server.log_knxnetip)
        {
            snort::TextLog_Print(server.log, "pkt:" STDu64 "\t", p.context->packet_number);
            snort::TextLog_Print(server.log, "    gid:%u    sid:%u    rev:%u\t", GID_KNXNETIP, sid, 0);
            TextLog_NewLine(server.log);

            snort::TextLog_Print(server.log, "timestamp:");
            snort::LogTimeStamp(server.log, (snort::Packet*) &p);
            TextLog_NewLine(server.log);

            if (snort::SnortConfig::output_datalink()){
                snort::PacketManager::log_protocols(server.log, &p);
                TextLog_NewLine(server.log);
            }

            if ( p.dsize and snort::SnortConfig::output_app_data() )
            {
                snort::LogPayload(server.log, (snort::Packet*) &p);
            }

            snort::TextLog_Print(server.log, "[**] [%u:%u:%u] \"(knxnetip) %s\" [**]\n", GID_KNXNETIP, sid, 0, knxnetip::module::get_rule_str(sid));
            TextLog_NewLine(server.log);

            snort::TextLog_Flush(server.log);
        }
    }
}

void knxnetip::queue_det_event(unsigned sid, const snort::Packet& p, const knxnetip::module::server& server, const knxnetip::module::policy& policy)
{
    if (policy.detection) {
        snort::DetectionEngine::queue_event(GID_KNXNETIP, sid);

        if (server.log_knxnetip)
        {
            snort::TextLog_Print(server.log, "pkt:" STDu64 "\t", p.context->packet_number);
            snort::TextLog_Print(server.log, "    gid:%u    sid:%u    rev:%u\t", GID_KNXNETIP, sid, 0);
            TextLog_NewLine(server.log);

            snort::TextLog_Print(server.log, "timestamp:");
            snort::LogTimeStamp(server.log, (snort::Packet*) &p);
            TextLog_NewLine(server.log);

            if (snort::SnortConfig::output_datalink()){
                snort::PacketManager::log_protocols(server.log, &p);
                TextLog_NewLine(server.log);
            }

            if ( p.dsize and snort::SnortConfig::output_app_data() )
            {
                snort::LogPayload(server.log, (snort::Packet*) &p);
            }
        }
    }
}

void knxnetip::detection::detect(const snort::Packet& p, knxnetip::Packet& knxp, knxnetip::module::server& server, const knxnetip::module::policy& policy)
{

    /* Detect illegal services */
    if (is_illegal_service(p, knxp, server, policy))
    {
        knxnetip_stats.illegal_services++;
    }
    /* Detect individual addressing */
    else if (is_individual_address(p, knxp, server, policy))
    {
        knxnetip_stats.individual_address++;
    }
    /* Detect group address */
    else if (is_illegal_group_address(p, knxp, server, policy))
    {
        knxnetip_stats.illegal_group_address++;
    }
    /* Detect illegal application layer services */
    else if (is_illegal_app_service(p, knxp, server, policy))
    {
        knxnetip_stats.illegal_app_services++;
    }
    /* Detect extremes */
    else if (is_extrema(p, knxp, server, policy))
    {
        knxnetip_stats.extremas++;
    }

    /* add to history */

    /* detect history */

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

bool knxnetip::detection::is_illegal_service(const snort::Packet& p, knxnetip::Packet& knxp, knxnetip::module::server& server, const knxnetip::module::policy& policy)
{
    using snort::TextLog_Flush;
    using snort::TextLog_Print;

    bool result = false;

    std::string service {knxnetip::service_identifier.find(knxp.h->get_service_type())->second};

    if (std::find(policy.services.begin(), policy.services.end(), service) != policy.services.end())
    {
        result = true;
        knxnetip::queue_det_event(KNXNETIP_SRVC, p, server, policy);
        if (server.log_knxnetip)
        {
            std::string rule = get_rule_string(KNXNETIP_SRVC_STR_PAR, server.log_to_file);
            TextLog_Print(server.log, rule.c_str(), GID_KNXNETIP,
                                      KNXNETIP_SRVC, 0,
                                      service.c_str());
            TextLog_NewLine(server.log);
            TextLog_Flush(server.log);
        }
    }

    return result;
}

bool knxnetip::detection::is_individual_address(const snort::Packet& p, knxnetip::Packet& knxp, knxnetip::module::server& server, const knxnetip::module::policy& policy)
{
    using knxnetip::packet::cemi::MessageCode;
    using snort::TextLog_Flush;
    using snort::TextLog_Print;

    knxnetip::packet::CEMI* c = get_cemi_frame(knxp);
    if (c == nullptr) return false;

    uint16_t individual_address;

    bool result = false;
    switch(c->get_message_code())
    {
        case MessageCode::L_DATA_REQ:
        case MessageCode::L_DATA_CON:
        case MessageCode::L_DATA_IND:
            result = c->data_link.data.is_individual_address();
            individual_address = c->data_link.data.get_destination_addr();
            break;

        case MessageCode::L_POLL_DATA_REQ:
        case MessageCode::L_POLL_DATA_CON:
            result = c->data_link.poll_data.is_individual_address();
            individual_address = c->data_link.poll_data.get_destination_addr();
            break;

        default:
            break;
    }

    if (result)
    {
        knxnetip::queue_det_event(KNXNETIP_INDIV_ADDR, p, server, policy);
        if (server.log_knxnetip)
        {
            std::string rule = get_rule_string(KNXNETIP_INDIV_ADDR_STR_PAR, server.log_to_file);
            uint8_t area = (individual_address & 0xf000) >> 12;
            uint8_t line = (individual_address & 0x0f00) >> 8;
            uint8_t device = individual_address & 0xff;

            TextLog_Print(server.log, rule.c_str(), GID_KNXNETIP,
                                      KNXNETIP_INDIV_ADDR, 0,
                                      area, line, device);
            TextLog_NewLine(server.log);
            TextLog_Flush(server.log);
        }
    }

    return result;
}

bool knxnetip::detection::is_illegal_group_address(const snort::Packet& p, knxnetip::Packet& knxp, knxnetip::module::server& server, const knxnetip::module::policy& policy)
{
    using knxnetip::packet::cemi::MessageCode;
    using snort::TextLog_Flush;
    using snort::TextLog_Print;

    knxnetip::packet::CEMI* c = get_cemi_frame(knxp);
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

    if (result)
    {
        knxnetip::queue_det_event(KNXNETIP_INVALID_GROUP_ADDR, p, server, policy);
        if (server.log_knxnetip)
        {
            std::string rule = get_rule_string(KNXNETIP_INVALID_GROUP_ADDR_STR_PAR, server.log_to_file);
            uint8_t main = (group_address & 0xf800) >> 11;
            uint8_t middle = (group_address & 0x0700) >> 8;
            uint8_t device = group_address & 0xff;
            uint8_t device2 = group_address & 0x7ff;

            TextLog_Print(server.log, rule.c_str(), GID_KNXNETIP,
                                      KNXNETIP_INVALID_GROUP_ADDR, 0,
                                      main, middle, device, main, device2);
            TextLog_NewLine(server.log);
            TextLog_Flush(server.log);

        }
    }

    return result;
}

bool knxnetip::detection::is_illegal_app_service(const snort::Packet& p, knxnetip::Packet& knxp, knxnetip::module::server& server, const knxnetip::module::policy& policy)
{
    using knxnetip::packet::cemi::MessageCode;
    using knxnetip::packet::cemi::APDU;
    using snort::TextLog_Flush;
    using snort::TextLog_Print;

    knxnetip::packet::CEMI* c = get_cemi_frame(knxp);
    if (c == nullptr) return false;

    bool result = false;
    APDU* a;

    switch(c->get_message_code())
    {
        case MessageCode::L_DATA_REQ:
        case MessageCode::L_DATA_CON:
        case MessageCode::L_DATA_IND:
            a = &c->data_link.data.npdu.apdu;
            break;

        case MessageCode::T_DATA_CONNEC_REQ:
        case MessageCode::T_DATA_CONNEC_IND:
        case MessageCode::T_DATA_INDV_REQ:
        case MessageCode::T_DATA_INDV_IND:
            a = &c->transport.tpdu.apdu;
            break;

        default:
            return false;
    }

    std::string app_service { knxnetip::packet::cemi::apdu::app_service_identifier.find(a->get_apci())->second};

    if (std::find(policy.app_services.begin(), policy.app_services.end(), app_service) != policy.app_services.end())
    {
        result = true;
        knxnetip::queue_det_event(KNXNETIP_APP_SRVC, p, server, policy);
        if (server.log_knxnetip)
        {
            std::string rule = get_rule_string(KNXNETIP_APP_SRVC_STR_PAR, server.log_to_file);
            TextLog_Print(server.log, rule.c_str(), GID_KNXNETIP,
                                      KNXNETIP_APP_SRVC, 0,
                                      app_service.c_str());
            TextLog_NewLine(server.log);
            TextLog_Flush(server.log);
        }
    }

    return result;
}

bool knxnetip::detection::is_extrema(const snort::Packet& p, knxnetip::Packet& knxp, knxnetip::module::server& server, const knxnetip::module::policy& policy)
{
    using knxnetip::packet::cemi::MessageCode;
    using knxnetip::packet::cemi::APDU;
    using knxnetip::packet::cemi::apdu::Type;
    using knxnetip::module::Spec;

    knxnetip::packet::CEMI* c = get_cemi_frame(knxp);
    if (c == nullptr) return false;

    bool result = false;
    APDU* a;
    uint16_t group_address = 0;

    switch(c->get_message_code())
    {
        case MessageCode::L_DATA_REQ:
        case MessageCode::L_DATA_CON:
        case MessageCode::L_DATA_IND:
            a = &c->data_link.data.npdu.apdu;
            group_address = c->data_link.data.get_destination_addr();
            break;

        /* FIXIT-L: T_DATA_* services have no group address information */

        default:
            return false;
    }

    knxnetip::module::Spec spec;
    switch(a->get_apci())
    {
        case Type::A_GroupValue_Write:
        case Type::A_GroupValue_Read:
        case Type::A_GroupValue_Response:
            spec = policy.group_addresses.find(group_address)->second;
            if (spec.get_state(Spec::State::MAX) or spec.get_state(Spec::State::MIN))
            {
                result = knxnetip::dpt::is_extrema(a->group_value, spec, p, server, policy);
            }
            break;

        default:
            break;
    }

    return result;
}
