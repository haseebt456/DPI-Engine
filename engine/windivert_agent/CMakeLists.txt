# Requires the WinDivert SDK. Point WINDIVERT_ROOT at the folder you
# extracted WinDivert-x.x.x-A.zip into -- the one that directly contains
# an "include" folder and an "x64" folder.
#
# Example (from an MSYS2 MinGW64 terminal, in the build/ directory):
#   cmake -G "MinGW Makefiles" -DWINDIVERT_ROOT="C:/WinDivert" ..

set(WINDIVERT_ROOT "" CACHE PATH "Path to extracted WinDivert package")

if (NOT WINDIVERT_ROOT)
    message(WARNING
        "WINDIVERT_ROOT not set -- skipping dpi_agent target.\n"
        "Reconfigure with: -DWINDIVERT_ROOT=C:/WinDivert")
    return()
endif()

add_executable(dpi_agent
    main_windivert.cpp
    sni_extractor.cpp
)

target_include_directories(dpi_agent PRIVATE ${WINDIVERT_ROOT}/include)
target_link_directories(dpi_agent PRIVATE ${WINDIVERT_ROOT}/x64)
target_link_libraries(dpi_agent PRIVATE WinDivert)

# Copy the two runtime files WinDivert needs right next to the built exe,
# so you can just run dpi_agent.exe directly without manual file copying.
add_custom_command(TARGET dpi_agent POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${WINDIVERT_ROOT}/x64/WinDivert.dll
        $<TARGET_FILE_DIR:dpi_agent>
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${WINDIVERT_ROOT}/x64/WinDivert64.sys
        $<TARGET_FILE_DIR:dpi_agent>
)
