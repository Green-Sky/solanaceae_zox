cmake_minimum_required(VERSION 3.14...3.24 FATAL_ERROR)

add_library(plugin_zox_ngc SHARED
	./plugin_zox_ngc.cpp
)
set_property(TARGET plugin_zox_ngc PROPERTY C_VISIBILITY_PRESET hidden)

target_link_libraries(plugin_zox_ngc PUBLIC
	solanaceae_plugin
	solanaceae_zox
)

########################################

add_library(plugin_zox_ngc_hs SHARED
	./plugin_zox_ngc_hs.cpp
)
set_property(TARGET plugin_zox_ngc_hs PROPERTY C_VISIBILITY_PRESET hidden)

target_link_libraries(plugin_zox_ngc_hs PUBLIC
	solanaceae_plugin
	solanaceae_zox
)
