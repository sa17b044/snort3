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
#include "knxnetip_apdu.h"

using namespace snort;

bool knxnetip::module::policy::load_group_addr(void)
{
    bool result = false;
    std::smatch m;

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
            Spec d{};

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
                    d.set_state(Spec::State::DPT);
                    d.dpt = (range << 16) | unit;
                }
            }

            /* validate and convert maxima and minima */
            std::regex rdptmax{knxnetip::regex::valid_dpt_max};
            if (std::regex_search(line, m, rdptmax))
            {
                d.set_state(Spec::State::MAX);
                d.max = std::stod(m[1].str());
            }

            std::regex rdptmin{knxnetip::regex::valid_dpt_min};
            if (std::regex_search(line, m, rdptmin))
            {
                d.set_state(Spec::State::MIN);
                d.min = std::stod(m[1].str());
            }

            /* Add converted values */
            if (g == 0)
            {
                LogMessage("ERROR: invalid group address: %s\n", m[1].str().c_str());
            }

            if (d.dpt == 0)
            {
                LogMessage("ERROR: invalid data point type: %s\n", m[1].str().c_str());
            }

            if (g != 0)
            {
                group_addresses.insert(std::pair<uint16_t,Spec>(g, d));
            }
        }
    }

    return result;
}

bool knxnetip::module::validate(param& params)
{
    // check if at least one server configuration is available, if not, create default one.
    if (params.policies.size() == 0)
    {
        knxnetip::module::policy p {};
        params.policies.push_back(p);
    }

    // validate server configuration
    for (int i = 0; i < params.servers.size(); i++)
    {
        server& s{params.servers[i]};

        // policy number
        if (s.policy < 0 or s.policy > params.policies.size())
        {
            LogMessage("ERROR: invalid policy '%d' at server[%d]\n", s.policy+1, i+1);
            return false;
        }

    }

    // check if at least one policy is available, if not, create default one.
    if (params.policies.size() == 0)
    {
        knxnetip::module::policy p {};
        params.policies.push_back(p);
    }

    // validate policy configuration
    for (auto& p : params.policies)
    {
        // group address file
        if (p.group_address_file.empty()) continue;

        std::ifstream ifile(p.group_address_file.c_str());
        if (!ifile)
        {
            LogMessage("ERROR: invalid group address file '%s'\n", p.group_address_file.c_str());
            p.group_address_file.clear();
        }

    }

    return true;
}

bool knxnetip::module::load(param& params)
{
    // server

    // policy
    for (auto& p : params.policies)
    {
        // services
        for (auto s : p.services)
        {
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

        // application layer services
        for (auto a : p.app_services)
        {
            bool found = false;

            for (auto app : knxnetip::packet::cemi::apdu::app_service_identifier)
            {
                if(a == app.second) {
                    found = true;
                    break;
                }
            }

            if (!found)
            {
                LogMessage("ERROR: invalid application layer service '%s'\n", a.c_str());
                a.clear();
            }
        }

        // group address and spec
        if (!p.group_address_file.empty())
        {
            p.load_group_addr();
        }
    }

    return true;
}

void knxnetip::module::open_log(knxnetip::module::server& s)
{
    std::string f = s.log_to_file ? F_NAME : "stdout";
    s.log = TextLog_Init(f.c_str());
}

void knxnetip::module::close_log(knxnetip::module::server& s)
{
    TextLog_Term(s.log);
}

knxnetip::module::server* knxnetip::module::get_server_src(param* param, const snort::Packet* p)
{
    for (int i = 0; i < param->servers.size(); i++)
    {
        knxnetip::module::server* s = &param->servers.at(i);
        if (s->from.contains(p->ptrs.ip_api.get_src()) == SfIpRet::SFIP_CONTAINS)
        {
            return s;
        }
    }

    return nullptr;
}

knxnetip::module::server* knxnetip::module::get_server_dst(param* param, const snort::Packet* p)
{
    for (int i = 0; i < param->servers.size(); i++)
    {
        knxnetip::module::server* s = &param->servers.at(i);
        if (s->to.contains(p->ptrs.ip_api.get_dst()) == SfIpRet::SFIP_CONTAINS)
        {
            return s;
        }
    }

    return nullptr;
}

const knxnetip::module::policy* knxnetip::module::get_policy_src(const param* param, const snort::Packet* p)
{
    for (auto s : param->servers) {
        if (s.from.contains(p->ptrs.ip_api.get_src()) == SfIpRet::SFIP_CONTAINS) {
            return &param->policies.at(s.policy-1);
        }
    }

    if (param->global_policy > 0 and param->global_policy <= param->policies.size()) {
        return &param->policies.at(param->global_policy-1);
    }

    return nullptr;
}

const knxnetip::module::policy* knxnetip::module::get_policy_dst(const param* param, const snort::Packet* p)
{
    for (auto s : param->servers) {
        if (s.to.contains(p->ptrs.ip_api.get_dst()) == SfIpRet::SFIP_CONTAINS) {
            return &param->policies.at(s.policy-1);
        }
    }

    if (param->global_policy > 0 and param->global_policy <= param->policies.size()) {
        return &param->policies.at(param->global_policy-1);
    }

    return nullptr;
}
