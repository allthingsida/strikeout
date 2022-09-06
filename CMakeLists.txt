cmake_minimum_required(VERSION 3.2 FATAL_ERROR)

project(strikeout)

set(PLUGIN_NAME              strikeout)
set(PLUGIN_SOURCES           plugin.cpp plugin.h utils.hpp storage.hpp)
set(PLUGIN_RUN_ARGS          "-t -z10000") # Debug messages for the debugger
include($ENV{IDASDK}/ida-cmake/addons.cmake)
