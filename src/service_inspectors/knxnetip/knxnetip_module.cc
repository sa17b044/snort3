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
// knxnetip_module.cc author Alija Sabic <sabic@technikum-wien.at>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "knxnetip_module.h"
#include "knxnetip_module_enum.h"
#include "knxnetip.h"
#include "knxnetip_enum.h"
#include "knxnetip_regex.h"

#include "profiler/profiler.h"
#include "log/messages.h"

#include <fstream>
#include <regex>

using namespace snort;
using namespace KNXnetIPModuleEnums;

//-------------------------------------------------------------------------
// params
//-------------------------------------------------------------------------
KNXnetIPPolicyParaList *policy_worker = nullptr;
KNXnetIPServerParaList *server_worker = nullptr;

KNXnetIPModule::KNXnetIPModule() : Module(KNXNETIP_NAME, KNXNETIP_HELP, knxnetip_params)
{ }

KNXnetIPModule::~KNXnetIPModule()
{
	if (server_worker)
		delete server_worker;

	if (policy_worker)
	    delete policy_worker;

	if (params)
	    delete params;
}

bool KNXnetIPModule::begin(const char *fqn, int idx, SnortConfig *)
{
	if (!idx && !strcmp(fqn, "knxnetip"))
	{
		// setup global config
		delete params;
		params = new KNXnetIPParaList;
	}
	else if (idx && !strcmp(fqn, "knxnetip.servers"))
	{
		// setup new server config
		if (server_worker)
			delete server_worker;
		server_worker = new KNXnetIPServerParaList;
	}
	else if (idx && !strcmp(fqn, "knxnetip.policies"))
	{
		// setup new policy config
		if (policy_worker)
			delete policy_worker;
		policy_worker = new KNXnetIPPolicyParaList;
	}

	return true;
}

bool KNXnetIPModule::set(const char *fqn, Value& val, SnortConfig *sc)
{
	// global
	if (val.is("global_policy"))
	{
		params->global_policy = val.get_long();
	}

	// server
	else if (server_worker)
	{
		if (val.is("cidr"))
		{
			unsigned n;
			std::string s((char *)val.get_buffer(n));

			std::regex r {KNXNETIP_CIDR_REGEX};
			std::smatch m;

			if(std::regex_search(s, m, r))
			{
			    server_worker->cidr.set(s.c_str());
			}
			else
			{
                LogMessage("ERROR: invalid ip address '%s'\n", s.c_str());
                server_worker->cidr.set("0.0.0.0/32");
			}
		}
		else if (val.is("port"))
		{
			server_worker->ports.push_back(val.get_long());
		}
		else if (val.is("policy"))
		{
			server_worker->policy = val.get_long() - 1;
		}
	}

	// policy
	else if (policy_worker)
	{
		if (val.is("individual_addressing"))
		{
			policy_worker->individual_addressing = val.get_bool();
		}
		else if (val.is("payload"))
		{
			policy_worker->payload = val.get_bool();
		}
		else if (val.is("group_addressing"))
		{
			policy_worker->group_addressing = val.get_bool();
		}
		else if (val.is("group_address_level"))
		{
		    policy_worker->group_address_level = val.get_long();
		}
		else if (val.is("group_address_file"))
		{
			unsigned n;
			const uint8_t *b = val.get_buffer(n);
			policy_worker->group_address_file.assign((const char *)b, n);
		}
		else if (val.is("services"))
		{
			unsigned n;
			const uint8_t *b = val.get_buffer(n);
			std::string s;
			s.assign((const char *)b, n);
			policy_worker->services.push_back(s);
		}

	}
	return true;
}

bool KNXnetIPModule::end(const char *fqn, int idx, SnortConfig *)
{
	// (global) configuration
	if (!idx && !strcmp(fqn, "knxnetip"))
	{
		if (!validate(this->params))
		{
			// FIXIT-L: Replace with proper snort message handling.
			LogMessage("ERROR: knxnetip configuration failed\n");

			// Fatal configuration.
			return false;
		}

		// load group addresses, etc.
		load(this->params);
	}

	// server
	else if (idx && !strcmp(fqn, "knxnetip.servers"))
	{
		if (!server_worker)
		{
			ParseError("invalid %s[%d]", fqn, idx);
			return true;
		}

		params->servers.push_back(server_worker);
		server_worker = nullptr;
	}

	// policy
	else if (idx && !strcmp(fqn, "knxnetip.policies"))
	{
		if (!policy_worker)
		{
			ParseError("invalid %s[%d]", fqn, idx);
		}

		params->policies.push_back(policy_worker);
		policy_worker = nullptr;
	}

	return true;
}

bool KNXnetIPModule::validate(KNXnetIPParaList *param)
{

	// validate server config
	for (int i = 0; i < param->servers.size(); i++)
	{
	    KNXnetIPServerParaList *p {param->servers.at(i)};

		// policy number
		if (p->policy < 0 or p->policy > (param->policies.size()-1))
		{
		    LogMessage("ERROR: invalid policy '%d' at server[%d]\n", p->policy+1, i+1);
			return false;
		}

	}

	// validate policy config
	for (int i = 0; i < param->policies.size(); i++)
	{
	    KNXnetIPPolicyParaList *p {param->policies.at(i)};

		// group address file
		std::ifstream ifile(p->group_address_file.c_str());
		if (!ifile)
		{
			LogMessage("ERROR: invalid group address file '%s'\n", p->group_address_file.c_str());
			p->group_address_file.clear();
		}

		// services
		for (int j = 0; j < p->services.size(); j++)
		{
		    std::string s {p->services.at(j)};
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

bool KNXnetIPModule::load(KNXnetIPParaList *param)
{

    // server
//    for (int i = 0; i < param->servers.size(); i++)
//    {
//
//    }

    // policy
    for (int i = 0; i < param->policies.size(); i++)
    {
        KNXnetIPPolicyParaList *p {param->policies.at(i)};

        if (!p->group_address_file.empty())
        {
            std::string regexp;
            if (p->group_address_level == 2)
                regexp.assign(KNXNETIP_GRP_ADDR_2_REGEX);
            else
                regexp.assign(KNXNETIP_GRP_ADDR_3_REGEX);

            std::regex grpaddr {regexp.c_str()};
            std::smatch matches;

            std::ifstream in(p->group_address_file.c_str());
            std::string line;
            while (std::getline(in, line))
            {
                if(std::regex_search(line, matches, grpaddr))
                {
                    if(p->group_address_level == 2)
                    {
                        p->group_addresses.push_back(
                            get_group_address(
                                matches[3].str(),
                                matches[4].str()));
                    }
                    else
                    {
                        p->group_addresses.push_back(
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

//-------------------------------------------------------------------------
// commands
//-------------------------------------------------------------------------
const Command *KNXnetIPModule::get_commands() const
{


    return new Command;
}


//-------------------------------------------------------------------------
// stats
//-------------------------------------------------------------------------
unsigned KNXnetIPModule::get_gid() const
{
    return GID_KNXNETIP;
}

THREAD_LOCAL ProfileStats KNXnetIPModule::knxnetip_profile;
ProfileStats* KNXnetIPModule::get_profile() const
{
    return &knxnetip_profile;
}

Module::Usage KNXnetIPModule::get_usage() const
{
    return INSPECT;
}

//-------------------------------------------------------------------------
// pegs
//-------------------------------------------------------------------------
const PegInfo* KNXnetIPModule::get_pegs() const
{
    return peg_names;
}

THREAD_LOCAL PegCount KNXnetIPModule::peg_counts[PEG_COUNT_MAX] = { 0 };
PegCount* KNXnetIPModule::get_counts() const
{
    return peg_counts;
}

//-------------------------------------------------------------------------
// rules
//-------------------------------------------------------------------------
static const snort::RuleMap knxnetip_rules[] =
{
    { 0, nullptr }
};

const snort::RuleMap* KNXnetIPModule::get_rules() const
{ return knxnetip_rules; }

//-------------------------------------------------------------------------
// custom
//-------------------------------------------------------------------------
ProfileStats& KNXnetIPModule::get_profile_stats()
{
    return knxnetip_profile;
}

const KNXnetIPParaList *KNXnetIPModule::get_params()
{
    KNXnetIPParaList *r = params;
    params = nullptr;
    return r;
}
