
file_list = \
knxnetip.cc \
knxnetip.h \
knxnetip_config.cc \
knxnetip_config.h \
knxnetip_detect.cc \
knxnetip_detect.h \
knxnetip_enum.h \
knxnetip_module.cc \
knxnetip_module.h \
knxnetip_module_enum.h \
knxnetip_packet.cc \
knxnetip_packet.h \
knxnetip_regex.h \
knxnetip_tables.cc \
knxnetip_tables.h

if STATIC_INSPECTORS
noinst_LIBRARIES = libknxnetip.a
libmodbus_a_SOURCES = $(file_list)
else
shlibdir = $(pkglibdir)/inspectors
shlib_LTLIBRARIES = knxnetip.la
knxnetip_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
knxnetip_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
knxnetip_la_SOURCES = $(file_list)
endif

#EXTRA_DIST = dev_notes.txt
