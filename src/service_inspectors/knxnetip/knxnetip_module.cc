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

#include <regex>

#include "knxnetip_module.h"
#include "knxnetip_module_enum.h"
#include "knxnetip.h"
#include "knxnetip_config.h"
#include "knxnetip_regex.h"
#include "knxnetip_tables.h"

#include "profiler/profiler.h"
#include "log/messages.h"

using namespace snort;
THREAD_LOCAL ProfileStats knxnetip_prof;

//-------------------------------------------------------------------------
// stats
//-------------------------------------------------------------------------
const PegInfo* KNXnetIPModule::get_pegs() const
{ return knxnetip::module::peg_names; }

PegCount* KNXnetIPModule::get_counts() const
{ return (PegCount*)&knxnetip_stats; }

//-------------------------------------------------------------------------
// rules
//-------------------------------------------------------------------------
const RuleMap* KNXnetIPModule::get_rules() const
{ return knxnetip::module::rules; }

//-------------------------------------------------------------------------
// params
//-------------------------------------------------------------------------
static knxnetip::module::policy *pworker;
static knxnetip::module::server *sworker;

KNXnetIPModule::KNXnetIPModule() : Module(KNXNETIP_NAME, KNXNETIP_HELP, knxnetip::module::params)
{
    pworker = nullptr;
    sworker = nullptr;
}
KNXnetIPModule::~KNXnetIPModule()
{ }

//-------------------------------------------------------------------------
// params - load configuration
//-------------------------------------------------------------------------
bool KNXnetIPModule::begin(const char *fqn, int idx, SnortConfig *)
{
	if (!idx && !strcmp(fqn, "knxnetip"))
	{ }
	else if (idx && !strcmp(fqn, "knxnetip.servers"))
	{
		// setup new server config
	    params.servers.push_back(knxnetip::module::server{});
	    sworker = &params.servers.back();
	}
	else if (idx && !strcmp(fqn, "knxnetip.policies"))
	{
		// setup new policy config
	    params.policies.push_back(knxnetip::module::policy{});
	    pworker = &params.policies.back();
	}

	return true;
}
bool KNXnetIPModule::set(const char *fqn, Value& val, SnortConfig *sc)
{
	// global
	if (val.is("global_policy"))
	{
		params.global_policy = val.get_long();
	}

	// server
	else if (sworker)
	{
	    knxnetip::module::server *sworker = &params.servers.back();

		if (val.is("cidr"))
		{
			unsigned n;
			std::string s((char *)val.get_buffer(n));

			std::regex r {KNXNETIP_CIDR_REGEX};
			std::smatch m;

			if(std::regex_search(s, m, r))
			{
			    sworker->cidr.set(s.c_str());
			}
			else
			{
                LogMessage("ERROR: invalid ip address '%s'\n", s.c_str());
                sworker->cidr.set("0.0.0.0/32");
			}
		}
		else if (val.is("port"))
		{
			sworker->ports.push_back(val.get_long());
		}
		else if (val.is("policy"))
		{
			sworker->policy = val.get_long() - 1;
		}
	}

	// policy
	else if (pworker)
	{
	    knxnetip::module::policy *pworker = &params.policies.back();

		if (val.is("individual_addressing"))
		{
			pworker->individual_addressing = val.get_bool();
		}
		else if (val.is("payload"))
		{
			pworker->payload = val.get_bool();
		}
		else if (val.is("group_addressing"))
		{
			pworker->group_addressing = val.get_bool();
		}
		else if (val.is("group_address_level"))
		{
		    pworker->group_address_level = val.get_long();
		}
		else if (val.is("group_address_file"))
		{
			unsigned n;
			const uint8_t *b = val.get_buffer(n);
			pworker->group_address_file.assign((const char *)b, n);
		}
		else if (val.is("services"))
		{
			unsigned n;
			const uint8_t *b = val.get_buffer(n);
			std::string s;
			s.assign((const char *)b, n);
			pworker->services.push_back(s);
		}

	}
	return true;
}

bool KNXnetIPModule::end(const char *fqn, int idx, SnortConfig *)
{
	// (global) configuration
	if (!idx && !strcmp(fqn, "knxnetip"))
	{
		if (!knxnetip::module::validate(params))
		{
			// FIXIT-L: Replace with proper snort message handling.
			LogMessage("ERROR: knxnetip configuration failed\n");

			// Fatal configuration.
			return false;
		}

		// load group addresses, etc.
		knxnetip::module::load(params);
	}

	// server
	else if (idx && !strcmp(fqn, "knxnetip.servers"))
	{
	    sworker = nullptr;
	}

	// policy
	else if (idx && !strcmp(fqn, "knxnetip.policies"))
	{
	    pworker = nullptr;
	}

	return true;
}
