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
// knxnetip_tables.cc author Alija Sabic <sabic@technikum-wien.at>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "knxnetip_tables.h"

using namespace snort;

const snort::Parameter knxnetip::module::server_params[] =
{
    {"from", Parameter::PT_STRING, nullptr, "0.0.0.0/32", "source ip address (CIDR notation)"},
    {"to", Parameter::PT_STRING, nullptr, "0.0.0.0/32", "destination ip address (CIDR notation)"},
    {"port", Parameter::PT_PORT, "1:", "3671", "server port number(s)"},
    {"policy", Parameter::PT_INT, "1:", "1", "server policy"},
    {"log_knxnetip", Parameter::PT_BOOL, nullptr, "false", "log inspection/detection events"},
    {"log_to_file", Parameter::PT_BOOL, nullptr, "false", "log to file or console"},
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

const Parameter knxnetip::module::policy_params[] =
{
    {"individual_addressing",Parameter::PT_BOOL, nullptr, "false", "individual addressing detection"},
    {"inspection", Parameter::PT_BOOL, nullptr, "true", "protocol inspection"},
    {"services", Parameter::PT_STRING, nullptr, nullptr, "service detection"},
    {"app_services", Parameter::PT_STRING, nullptr, nullptr, "application layer service detection"},
    {"header", Parameter::PT_BOOL, nullptr, "false", "print header with alert"},
    {"payload", Parameter::PT_BOOL, nullptr, "false", "print payload with alert"},
    {"detection", Parameter::PT_BOOL, nullptr, "false", "protocol detection"},
    {"group_address_level", Parameter::PT_INT, "2:3", "3",  "group address level (2/3)"},
    {"group_address_file", Parameter::PT_STRING, nullptr, nullptr, "group address file"},
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

const Parameter knxnetip::module::params[] =
{
    {"global_policy", Parameter::PT_INT, nullptr, 0, "global policy"},
    {"servers", Parameter::PT_LIST, server_params, nullptr, "server configuration"},
    {"policies", Parameter::PT_LIST, policy_params, nullptr, "detection policy"},
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

const snort::RuleMap knxnetip::module::events[] =
{
	{ 0, nullptr }
};

const PegInfo knxnetip::module::peg_names[] =
{
    { CountType::SUM, "total_frames", "total frames" },
    { CountType::SUM, "valid_frames", "valid frames" },
    { CountType::SUM, "illegal_services", "illegal knxnetip services" },
    { CountType::SUM, "individual_address", "individual addressing" },
    { CountType::SUM, "illegal_app_services", "illegal knxnetip application layer services" },
    { CountType::SUM, "illegal_group_address", "illegal knx group addresses" },
    { CountType::SUM, "illegal_ia", "illegal knx individual addresses" },
    { CountType::SUM, "extremas", "max/min exceeded" },
	{ CountType::END, nullptr, nullptr }
};

const RuleMap knxnetip::module::rules[] = {
    /* Protocol Header */
    { KNXNETIP_HEAD_SIZE, KNXNETIP_HEAD_SIZE_STR },
    { KNXNETIP_PROT_VERS, KNXNETIP_PROT_VERS_STR },
    { KNXNETIP_TOTAL_LEN, KNXNETIP_TOTAL_LEN_STR },
    { KNXNETIP_SRVC_TYPE, KNXNETIP_SRVC_TYPE_STR },
    { KNXNETIP_PACKET_PROCESS, KNXNETIP_PKT_PROCESS_STR },
    /* Protocol Services */
    { KNXNETIP_INDIV_ADDR, KNXNETIP_INDIV_ADDR_STR },
    { KNXNETIP_INVALID_INDIV_ADDR, KNXNETIP_INVALID_INDIV_ADDR_STR },
    { KNXNETIP_INVALID_GROUP_ADDR, KNXNETIP_INVALID_GROUP_ADDR_STR },
    { KNXNETIP_SRVC, KNXNETIP_SRVC_STR },
    { KNXNETIP_APP_SRVC, KNXNETIP_APP_SRVC_STR },
    { KNXNETIP_APP_SRVC_UNSUPPORTED, KNXNETIP_APP_SRVC_UNSUPPORTED_STR },
    { KNXNETIP_RESERVED_FIELD_W_DATA, KNXNETIP_RESERVED_FIELD_W_DATA_STR },
    { KNXNETIP_CEMI_SRVC_UNSUPPORTED, KNXNETIP_CEMI_SRVC_UNSUPPORTED_STR },
    { KNXNETIP_CEMI_PROCESSING_ERROR, KNXNETIP_CEMI_PROCESSING_ERROR_STR },
    /* Group Address */
    { KNXNETIP_GRPADDR_MAX, KNXNETIP_GRPADDR_MAX_STR },
    { KNXNETIP_GRPADDR_MIN, KNXNETIP_GRPADDR_MIN_STR },
    /* Misc */
    { KNXNETIP_EXPECTED_LEN, KNXNETIP_EXPECTED_LEN_STR },
    { KNXNETIP_DIB_UNSUPPORTED, KNXNETIP_DIB_UNSUPPORTED_STR },
    { KNXNETIP_CONN_TYPE_UNSUPPORTED, KNXNETIP_CONN_TYPE_UNSUPPORTED_STR },
    { KNXNETIP_SELECTOR_UNSUPPORTED, KNXNETIP_SELECTOR_UNSUPPORTED_STR },
//    { KNXNETIP_HEAD
//    { KNXNETIP_DUMMY, KNXNETIP_DUMMY_STR },
    { 0, nullptr }
};

const char* knxnetip::module::get_rule_str(int sid)
{
    int j;

    for (j = 0; knxnetip::module::rules[j].msg != nullptr; j++)
    {
        if (sid == knxnetip::module::rules[j].sid)
        {
            break;
        }
    }
    return knxnetip::module::rules[j].msg;
}
