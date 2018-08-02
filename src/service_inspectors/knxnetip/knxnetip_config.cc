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
// knxnetip_config.cc author Alija Sabic <sabic@technikum-wien.at>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <fstream>
#include <regex>

#include "log/messages.h"
#include "knxnetip_config.h"
#include "knxnetip_enum.h"
#include "knxnetip_regex.h"

// FIXIT-M: Move to knxnetip related processing
static uint16_t get_group_address(std::string m, std::string s)
{
    return (((uint16_t)std::stoi(m))  << 11) |
            ((uint16_t)std::stoi(s));
}
// FIXIT-M: Move to knxnetip related processing
static uint16_t get_group_address(std::string m, std::string mid, std::string s)
{
    return (((uint16_t)std::stoi(m))  << 11) |
           (((uint16_t)std::stoi(mid)) << 8) |
            ((uint16_t)std::stoi(s));
}

bool knxnetip::module::validate(param& params) {

    // validate server config
    for (int i = 0; i < params.servers.size(); i++)
    {
        server& s{params.servers[i]};

        // policy number
        if (s.policy < 0 or s.policy > (params.policies.size()-1))
        {
            LogMessage("ERROR: invalid policy '%d' at server[%d]\n", s.policy+1, i+1);
            return false;
        }

    }

    // validate policy config
    for (int i = 0; i < params.policies.size(); i++)
    {
        policy& p{params.policies[i]};

        // group address file
        std::ifstream ifile(p.group_address_file.c_str());
        if (!ifile)
        {
            LogMessage("ERROR: invalid group address file '%s'\n", p.group_address_file.c_str());
            p.group_address_file.clear();
        }

        // services
        for (int j = 0; j < p.services.size(); j++)
        {
            std::string s {p.services.at(j)};
            bool found = false;

            for (int k = 0; knxnetip::service_identifier[k].text != nullptr; k++)
            {
                if (!strcmp(s.c_str(), knxnetip::service_identifier[k].text))
                {
                    found = true;
                    break;
                }
            }

            if (!found)
            {
                LogMessage("ERROR: invalid service '%s'\n", s.c_str());
                s.clear();
            }
        }

    }

    return true;
}

bool knxnetip::module::load(param& params) {

    // server
//    for (int i = 0; i < params.servers.size(); i++)
//    {
//
//    }

    // policy
    for (int i = 0; i < params.policies.size(); i++)
    {
        policy& p{params.policies[i]};

        if (!p.group_address_file.empty())
        {
            std::string regexp;
            if (p.group_address_level == 2)
                regexp.assign(KNXNETIP_GRP_ADDR_2_REGEX);
            else
                regexp.assign(KNXNETIP_GRP_ADDR_3_REGEX);

            std::regex grpaddr {regexp.c_str()};
            std::smatch matches;

            std::ifstream in(p.group_address_file.c_str());
            std::string line;
            while (std::getline(in, line))
            {
                if(std::regex_search(line, matches, grpaddr))
                {
                    if(p.group_address_level == 2)
                    {
                        p.group_addresses.push_back(
                            get_group_address(
                                matches[3].str(),
                                matches[4].str()));
                    }
                    else
                    {
                        p.group_addresses.push_back(
                            get_group_address(
                                matches[3].str(),
                                matches[4].str(),
                                matches[5].str()));
                    }
                }
            }
        }
    }

    return true;
}

const knxnetip::module::policy* knxnetip::module::get_policy(const param* param, const Packet* p)
{
    for (auto s : param->servers) {
        if (s.cidr.contains(p->ptrs.ip_api.get_src()) == SfIpRet::SFIP_CONTAINS) {
            return &param->policies.at(s.policy);
        }
        if (s.cidr.contains(p->ptrs.ip_api.get_dst()) == SfIpRet::SFIP_CONTAINS) {
            return &param->policies.at(s.policy);
        }
    }

    if (param->global_policy > 0) {
        return &param->policies.at(param->global_policy-1);
    }

    return static_cast<policy*>(nullptr);
}
