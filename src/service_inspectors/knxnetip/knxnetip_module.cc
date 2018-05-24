//
// Created by alija on 16.05.18.
//

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "knxnetip_module.h"
#include "knxnetip_enum.h"
#include "knxnetip.h"

#include "profiler/profiler.h"
#include "log/messages.h"

using namespace snort;
using namespace KNXnetIPEnums;


static const Parameter knxnetip_servers_params[] =
{
	{"ip", Parameter::PT_STRING, nullptr, nullptr, "server ip address"},
	// {"ip", Parameter::PT_ADDR, nullptr, "0.0.0.0/32", "server ip address"},
	// {"port", Parameter::PT_PORT, "1:", "3671", "server port number(s)"},
	{"port", Parameter::PT_PORT, "1:", nullptr, "server port number(s)"},
	{"policy", Parameter::PT_INT, nullptr, 0, "server policy"},
	{ nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter knxnetip_policies_params[] =
{
	{"individual_addressing", Parameter::PT_BOOL, nullptr, "false", "individual addressing detection"},
	{"services", Parameter::PT_STRING, nullptr, nullptr, "service detection"},
	{"payload", Parameter::PT_BOOL, nullptr, "false", "payload with alert"},
	{"group_addressing", Parameter::PT_BOOL, nullptr, "false", "group address detection"},
	{"group_address_file", Parameter::PT_STRING, nullptr, nullptr, "group address file"},
	{ nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

const Parameter KNXnetIPModule::knxnetip_params[] =
{
	{"global_policy", Parameter::PT_INT, nullptr, 0, "global policy"},
	{"servers", Parameter::PT_LIST, knxnetip_servers_params, nullptr, "server configuration"},
	{"policies", Parameter::PT_LIST, knxnetip_policies_params, nullptr, "detection policy"},
	{ nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

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
const PegInfo peg_names[] =
{
	{ CountType::END, nullptr, nullptr }
};

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
// params
//-------------------------------------------------------------------------
KNXnetIPPolicyParaList *policy_worker = nullptr;
KNXnetIPServerParaList *server_worker = nullptr;

KNXnetIPModule::KNXnetIPModule() : Module(KNXNETIP_NAME, KNXNETIP_HELP, knxnetip_params)
{ }

KNXnetIPModule::~KNXnetIPModule()
{
//	delete policies;
//	delete servers;
	if (server_worker)
		delete server_worker;
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
		if (val.is("ip"))
		{
			unsigned n;
			const uint8_t *b = val.get_buffer(n);
			server_worker->ip.assign((const char *)b, n);
		}
		else if (val.is("port"))
		{
			server_worker->ports.push_back(val.get_long());
		}
		else if (val.is("policy"))
		{
			server_worker->policy = val.get_long();
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
		// validate configuration

		  // policy number

		  // group address file

		  // services

		  // port, ip?

		// load group addresses, etc.
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
