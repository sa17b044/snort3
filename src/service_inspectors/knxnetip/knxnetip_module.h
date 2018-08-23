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
#include "knxnetip_config.h"

#define GID_KNXNETIP 147

#define KNXNETIP_NAME "knxnetip"
#define KNXNETIP_HELP "knxnetip inspection"

extern THREAD_LOCAL snort::ProfileStats knxnetip_prof;

class KNXnetIPModule : public snort::Module
{
public:
    KNXnetIPModule();
    ~KNXnetIPModule() override;

    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    unsigned get_gid() const override
    { return GID_KNXNETIP; }

    const snort::RuleMap* get_rules() const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    Module::Usage get_usage() const override
    { return INSPECT; }

    knxnetip::module::param params;
};

#endif // KNXNETIP_MODULE_H
