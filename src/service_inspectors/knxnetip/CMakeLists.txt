set( FILE_LIST
    knxnetip.cc
    knxnetip.h
    knxnetip_module.cc
    knxnetip_module.h
)

if (STATIC_INSPECTORS)
    add_library(knxnetip STATIC ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(knxnetip inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)

