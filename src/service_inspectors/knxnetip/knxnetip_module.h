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
#include "sfip/sf_cidr.h"
#include "sfip/sf_ip.h"

#define GID_KNXNETIP 146

#define KNXNETIP_NAME "knxnetip"
#define KNXNETIP_HELP "knxnetip inspection"

using namespace snort;

//-------------------------------------------------------------------------
// knxnetip statistics
//-------------------------------------------------------------------------
struct KNXnetIPStats
{
    PegCount total_frames;
};

//extern THREAD_LOCAL KNXnetIPStats knxnetip_stats;

//-------------------------------------------------------------------------
// knxnetip module
//-------------------------------------------------------------------------

struct KNXnetIPPolicyParaList
{
public:
	bool individual_addressing = false;
	bool payload = false;
	bool group_addressing = false;
	int group_address_level = 3;
	std::string group_address_file;
	std::vector<std::string> services;

// deduced
	std::vector<uint16_t> group_addresses;
};

struct KNXnetIPServerParaList
{
public:
    SfCidr cidr;
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

class KNXnetIPModule : public Module
{
public:
    KNXnetIPModule();
    ~KNXnetIPModule() override;

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    unsigned get_gid() const override;

    const Command* get_commands() const override;
    const RuleMap* get_rules() const override;
    const PegInfo* get_pegs() const override;

//    bool counts_need_prep() const override;
//    void prep_counts() override;

    PegCount* get_counts() const override;
//    PegCount get_global_count(const char* name) const override;
//    int get_num_counts() const override;
    ProfileStats* get_profile() const override;
//    const char* get_defaults() const override;
//    bool global_stats() const override;

//    void sum_stats(bool accumulate_now_stats) override;
//    void show_interval_stats(IndexVec&, FILE*) override;
//    void show_stats() override;
//    void reset_stats() override;
//    void show_dynamic_stats() override;

    Module::Usage get_usage() const override;

    static ProfileStats& get_profile_stats();
    const KNXnetIPParaList *get_params();


#ifdef REG_TEST
    static const PegInfo* get_peg_names() { return peg_names; }
    static const PegCount* get_peg_counts() { return peg_counts; }
    static void reset_peg_counts() { }
#endif

private:
    static bool validate(KNXnetIPParaList *param);
    static bool load(KNXnetIPParaList *param);

    static const Parameter knxnetip_params[];
    static const RuleMap knxnetip_events[];
    KNXnetIPParaList *params = nullptr;
    static const PegInfo peg_names[];
    static THREAD_LOCAL ProfileStats knxnetip_profile;
    static THREAD_LOCAL PegCount peg_counts[];
};


#endif // KNXNETIP_MODULE_H
