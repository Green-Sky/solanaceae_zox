cmake_minimum_required(VERSION 3.14...3.24 FATAL_ERROR)

add_library(plugin_zox_ngc SHARED
	./plugin_zox_ngc.cpp
)
set_target_properties(plugin_zox_ngc PROPERTIES
	C_VISIBILITY_PRESET hidden
	POSITION_INDEPENDENT_CODE ON
)

target_link_libraries(plugin_zox_ngc PUBLIC
	solanaceae_plugin
	solanaceae_zox
)

########################################

add_library(plugin_zox_ngc_hs SHARED
	./plugin_zox_ngc_hs.cpp
)

set_target_properties(plugin_zox_ngc_hs PROPERTIES
	C_VISIBILITY_PRESET hidden
	POSITION_INDEPENDENT_CODE ON
)
target_compile_definitions(plugin_zox_ngc_hs PUBLIC ENTT_API_IMPORT)

target_link_libraries(plugin_zox_ngc_hs PUBLIC
	solanaceae_plugin
	solanaceae_zox
)
