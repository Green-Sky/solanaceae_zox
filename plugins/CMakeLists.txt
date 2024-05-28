cmake_minimum_required(VERSION 3.14...3.24 FATAL_ERROR)

add_library(plugin_zox_ngc MODULE
	./plugin_zox_ngc.cpp
)
set_target_properties(plugin_zox_ngc PROPERTIES
	C_VISIBILITY_PRESET hidden
)

target_link_libraries(plugin_zox_ngc PUBLIC
	solanaceae_plugin
	solanaceae_zox
)

########################################

add_library(plugin_zox_ngc_hs MODULE
	./plugin_zox_ngc_hs.cpp
)

set_target_properties(plugin_zox_ngc_hs PROPERTIES
	C_VISIBILITY_PRESET hidden
)
target_compile_definitions(plugin_zox_ngc_hs PUBLIC ENTT_API_IMPORT)

target_link_libraries(plugin_zox_ngc_hs PUBLIC
	solanaceae_plugin
	solanaceae_zox
)
