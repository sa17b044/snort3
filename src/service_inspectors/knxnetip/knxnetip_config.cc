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

bool knxnetip::module::policy::load_group_addr(void)
{
    bool result = false;
    std::smatch m;

    LogMessage("file: %s\n", group_address_file.c_str());

    /* extract file extension */
    std::string ext;
    std::regex r_ext{knxnetip::regex::file_ext};
    if(std::regex_search(group_address_file, m, r_ext))
    {
        ext = m[1].str();
        result = true;
    }
    else
    {
        LogMessage("ERROR: failed to load group address. Cannot determine file extension (e.g. xml, csv) of '%s'\n", group_address_file.c_str());
        return false;
    }


    /* read each line */
    std::ifstream in(group_address_file);
    std::string line;

    while(std::getline(in, line))
    {
        bool valid = false;
        std::string group_address;
        std::string data_point_type;

        if (ext == "xml")
        {
            // validate line
            std::regex rl{knxnetip::regex::xml::valid_line};
            if (!std::regex_search(line, m, rl))
                continue;

            std::string vl{m[0].str()};

            // validate group address
            std::regex rg{knxnetip::regex::xml::valid_address};
            if (!std::regex_search(vl, m, rg))
                continue;

            group_address.assign(m[1].str());

            // validate data point type
            std::regex rdpt{knxnetip::regex::xml::valid_dpt};
            if (!std::regex_search(vl, m, rdpt))
                continue;

            data_point_type.assign(m[1].str());

            valid = true;
        }
        else if (ext == "csv")
        {
            // validate group address
            std::regex rg{knxnetip::regex::csv::valid_address};
            if (!std::regex_search(line, m, rg))
                continue;

            group_address.assign(m[1].str());

            // validate data point type
            std::regex rdpt{knxnetip::regex::csv::valid_dpt};
            if (!std::regex_search(line, m, rdpt))
                continue;

            data_point_type.assign(m[1].str());

            valid = true;
        }

        /* Add Group Address data */
        if (valid)
        {
            uint16_t g{0};
            uint32_t dpt{0};

            /* validate and convert group address */
            if (group_address_level == 2)
            {
                std::regex rg{knxnetip::regex::group_address_2l};
                if (std::regex_search(group_address, m, rg))
                {
                    unsigned long main {std::stoul(m[1].str())};
                    unsigned long device {std::stoul(m[2].str())};

                    if (main > 31 or device > 2047)
                    {
                        LogMessage("ERROR: invalid group address: %s\n", group_address.c_str());
                    }
                    else
                    {
                        g = (main << 11) | device;
                    }
                }
            }
            else if (group_address_level == 3)
            {
                std::regex rg{knxnetip::regex::group_address_3l};
                if (std::regex_search(group_address, m, rg))
                {
                    unsigned long main {std::stoul(m[1].str())};
                    unsigned long middle {std::stoul(m[2].str())};
                    unsigned long device {std::stoul(m[3].str())};

                    if (main > 31 or middle > 7 or device > 255)
                    {
                        LogMessage("ERROR: invalid group address: %s\n", group_address.c_str());
                    }
                    else
                    {
                        g = (main << 11) | (middle << 8) | device;
                    }
                }
            }

            /* validate and convert data point type */
            std::regex rdpt{knxnetip::regex::data_point_type};
            if (std::regex_search(data_point_type, m, rdpt))
            {
                unsigned long range {std::stoul(m[1].str())};
                unsigned long unit {1};

                if (m[2].matched)
                {
                    unit = std::stoul(m[2].str());
                }

                if (range > 65535 or unit > 65535)
                {
                    LogMessage("ERROR: invalid data point type: %s\n", data_point_type.c_str());
                }
                else
                {
                    dpt = (range << 16) | unit;
                }
            }

            /* Add converted values */
            if (g == 0)
            {
                LogMessage("ERROR: invalid group address: %s\n", m[1].str().c_str());
            }

            if (dpt == 0)
            {
                LogMessage("ERROR: invalid data point type: %s\n", m[1].str().c_str());
            }

            if (g != 0 and dpt != 0)
            {
                Spec d{};
                d.dpt = dpt;
                d.max = 0;
                d.min = 0;
                d.frequency = 0;
                d.duration = 0;

                group_addresses.insert(std::pair<uint16_t,Spec>(g, d));
            }
        }
    }

    return result;
}

bool knxnetip::module::validate(param& params) {

    // validate server configuration
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

    // validate policy configuration
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

            for (auto srv : knxnetip::service_identifier)
            {
                if(s == srv.second) {
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

    /* FIXME-H:
     * check if at least one policy is available,
     * if not, create default one.
     */

    /*FIXME: configuration */
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
            p.load_group_addr();

            /*
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
            */
        }
    }

    return true;
}

const knxnetip::module::policy& knxnetip::module::get_policy(const param* param, const snort::Packet* p)
{
    for (auto s : param->servers) {
        if (s.cidr.contains(p->ptrs.ip_api.get_src()) == SfIpRet::SFIP_CONTAINS) {
            return param->policies.at(s.policy);
        }
        if (s.cidr.contains(p->ptrs.ip_api.get_dst()) == SfIpRet::SFIP_CONTAINS) {
            return param->policies.at(s.policy);
        }
    }

    if (param->global_policy > 0) {
        return param->policies.at(param->global_policy-1);
    }

    return param->policies.at(0);
}

bool knxnetip::module::has_policy(const param* param, const snort::Packet *p)
{
    bool r = false;

    for (auto s : param->servers) {
        if (s.cidr.contains(p->ptrs.ip_api.get_src()) == SfIpRet::SFIP_CONTAINS) {
            r = true;
            break;
        }
        if (s.cidr.contains(p->ptrs.ip_api.get_dst()) == SfIpRet::SFIP_CONTAINS) {
            r = true;
            break;
        }
    }

    if (param->global_policy > 0) {
        r = true;
    }

    return r;
}
