---------------------------------------------------------------------------
-- Snort++ configuration
---------------------------------------------------------------------------

---------------------------------------------------------------------------
-- 1. configure environment
---------------------------------------------------------------------------

-- this depends on LUA_PATH
-- used to load this conf into Snort
require('snort_config')

-- this depends on SNORT_LUA_PATH
-- where to find other config files
-- conf_dir = os.getenv('SNORT_LUA_PATH')
conf_dir = './etc/scripts'

if ( not conf_dir ) then
    conf_dir = '.'
end

---------------------------------------------------------------------------
-- 2. configure defaults
---------------------------------------------------------------------------

HOME_NET = '172.22.0.0/16'
EXTERNAL_NET = '! ' .. HOME_NET

KNX_NET = [[172.22.10.76/32 172.22.10.77/32]]
BAC_NET = [[172.22.11.76/32 172.22.11.77/32]]
ENO_NET = '172.22.13.76/32'



dofile(conf_dir .. '/snort_defaults.lua')
-- dofile(conf_dir .. '/file_magic.lua')

---------------------------------------------------------------------------
-- 3. configure inspection
---------------------------------------------------------------------------
stream = { }
stream_ip = { }
stream_udp = { }

knxnetip = 
{ 
    global_policy = 1,
    policies =
    {
        {
            individual_addressing = true,
            services = 
            {
                'SEARCH_REQUEST',
                'DESCRIPTION_REQUEST'
            },
            group_addressing = true,
            group_address_level = 3,
            group_address_file = '/home/alija/Documents/group_address1.esf'
        },
        {
            individual_addressing = false,
            services = 
            {
                'SEARCH_REQUEST',
                'CONNECT_REQUEST',
                'knx2_service3'
            },
            group_addressing = false,
            group_address_level = 2,
            group_address_file = '/home/alija/Documents/group_address2.esf'
        },
        {
            individual_addressing = false,
            services = 
            {
                'SEARCH_REQUEST',
                'CONNECT_REQUEST',
                'knx2_service3'
            },
            group_addressing = false,
            group_address_file = '/home/alija/Documents/group_address3.esf'
        }
    },
    servers = 
    {
        {
            cidr = '172.22.10.76/32',
            port = 
            {
                3671,
                3672
            },
            policy = 1
        },
        {
            cidr = '244.22.11.76/30',
            port = 3672,
            policy = 2
        }
    },
}

http_inspect =
{
    response_depth = 50,
    request_depth = 100
}

---------------------------------------------------------------------------
-- 4. configure bindings
---------------------------------------------------------------------------

binder =
{
    -- { when = { proto = 'udp', ports = '3671' }, use = { type = 'knxnetip' } },
    { when = { proto = 'any', ports = 'any' }, use = { type = 'knxnetip' } },
    { when = { service = 'knxnetip' },         use = { type = 'knxnetip' } }
}

---------------------------------------------------------------------------
-- 5. configure performance
---------------------------------------------------------------------------

--perf_monitor = 
--{
    -- modules = {},
--    flow = true,
--    flow_ip = true,
--    cpu = true
--}

---------------------------------------------------------------------------
-- 6. configure detection
---------------------------------------------------------------------------

---------------------------------------------------------------------------
-- 7. configure filters
---------------------------------------------------------------------------

---------------------------------------------------------------------------
-- 8. configure outputs
---------------------------------------------------------------------------


