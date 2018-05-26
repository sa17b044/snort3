set( FILE_LIST
    knxnetip.cc
    knxnetip.h
    knxnetip_enum.h
    knxnetip_module.cc
    knxnetip_module.h
    knxnetip_module_enum.h
    knxnetip_regex.h
    knxnetip_tables.cc
)

if (STATIC_INSPECTORS)
    add_library(knxnetip OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(knxnetip inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)

