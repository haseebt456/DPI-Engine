cmake_minimum_required(VERSION 3.15)
project(network_analyzer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

set(CORE_SOURCES
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)

# --- Offline single-threaded engine ---
add_executable(dpi_engine src/main.cpp ${CORE_SOURCES})

# --- Offline multi-threaded engine ---
add_executable(dpi_engine_mt src/main_mt.cpp ${CORE_SOURCES})
find_package(Threads REQUIRED)
target_link_libraries(dpi_engine_mt PRIVATE Threads::Threads)

# --- Live Windows agent (WinDivert), Windows-only ---
if (WIN32)
    add_subdirectory(windivert_agent)
endif()
