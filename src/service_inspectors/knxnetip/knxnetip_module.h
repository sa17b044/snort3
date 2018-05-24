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
// knxnetip_module.h author Alija Sabic <sabic@technikum-wien.at>

#ifndef KNXNETIP_MODULE_H
#define KNXNETIP_MODULE_H

#include "framework/module.h"

#define GID_KNXNETIP 146

#define KNXNETIP_NAME "knxnetip"
#define KNXNETIP_HELP "knxnetip inspection"

struct KNXnetIPPolicyParaList
{
public:
	bool individual_addressing = false;
	bool payload = false;
	bool group_addressing = false;
	std::string group_address_file;
	std::vector<std::string> services;
};

struct KNXnetIPServerParaList
{
public:
	std::string ip;
	std::vector<int> ports;
	int policy;
};

struct KNXnetIPParaList
{
public:
	int global_policy;
	std::vector<KNXnetIPPolicyParaList *> policies;
	std::vector<KNXnetIPServerParaList *> servers;
};

class KNXnetIPModule : public snort::Module
{
public:
    KNXnetIPModule();
    ~KNXnetIPModule() override;

    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    unsigned get_gid() const override;
    const snort::RuleMap* get_rules() const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile() const override;
    Module::Usage get_usage() const override;

#ifdef REG_TEST
    static const PegInfo* get_peg_names() { return peg_names; }
    static const PegCount* get_peg_counts() { return peg_counts; }
    static void reset_peg_counts() { }
#endif

private:
    static const snort::Parameter knxnetip_params[];
    static const snort::RuleMap knxnetip_events[];
    KNXnetIPParaList *params = nullptr;
    static const PegInfo peg_names[];
    static THREAD_LOCAL snort::ProfileStats knxnetip_profile;
    static THREAD_LOCAL PegCount peg_counts[];
};


#endif // KNXNETIP_MODULE_H
