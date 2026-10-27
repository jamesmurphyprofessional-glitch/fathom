cmake_minimum_required(VERSION 3.24)
project(fathom VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
endif()

find_package(fmt CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(Catch2 3 CONFIG REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(CAPSTONE REQUIRED IMPORTED_TARGET capstone)

set(LLVM_DIR "/opt/homebrew/opt/llvm@22/lib/cmake/llvm" CACHE PATH "LLVM cmake directory")
find_package(LLVM REQUIRED CONFIG)
message(STATUS "LLVM ${LLVM_PACKAGE_VERSION} from ${LLVM_DIR}")
separate_arguments(FATHOM_LLVM_DEFS NATIVE_COMMAND "${LLVM_DEFINITIONS}")

set(FATHOM_DEBUGSERVER
    "/Applications/Xcode.app/Contents/SharedFrameworks/LLDB.framework/Versions/A/Resources/debugserver"
    CACHE FILEPATH "Xcode debugserver")
set(FATHOM_CLANG22 "/opt/homebrew/opt/llvm@22/bin/clang" CACHE FILEPATH "Homebrew LLVM clang")

find_library(FATHOM_LLVM_DYLIB LLVM PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH REQUIRED)

add_library(fathom_core
    src/util.cpp
    src/load.cpp
    src/disasm.cpp
    src/passes.cpp
    src/report.cpp
    src/debug.cpp
    src/retsync.cpp
    src/workbench.cpp
)
target_include_directories(fathom_core
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS}
)
target_compile_definitions(fathom_core PRIVATE "FATHOM_DEBUGSERVER=\"${FATHOM_DEBUGSERVER}\"")
target_compile_options(fathom_core PRIVATE -Wall -Wextra -Wpedantic ${FATHOM_LLVM_DEFS})
target_link_libraries(fathom_core
    PUBLIC
        fmt::fmt
        nlohmann_json::nlohmann_json
        PkgConfig::CAPSTONE
        ${FATHOM_LLVM_DYLIB}
)

add_executable(fathom src/main.cpp)
target_link_libraries(fathom PRIVATE fathom_core)
target_compile_options(fathom PRIVATE -Wall -Wextra -Wpedantic)

add_executable(fathom_tests tests/engine_test.cpp tests/workbench_test.cpp)
target_link_libraries(fathom_tests PRIVATE fathom_core Catch2::Catch2WithMain)
target_compile_options(fathom_tests PRIVATE -Wall -Wextra -Wpedantic -Wno-c2y-extensions)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/fixtures)
target_compile_definitions(fathom_tests PRIVATE
    "FATHOM_SOURCE_DIR=\"${CMAKE_SOURCE_DIR}\""
    "FATHOM_FIXTURE_DIR=\"${CMAKE_BINARY_DIR}/fixtures\""
    "FATHOM_CLANG22=\"${FATHOM_CLANG22}\""
)

option(FATHOM_SANITIZE "Build with ASan and UBSan" OFF)
if(FATHOM_SANITIZE)
    foreach(tgt fathom_core fathom fathom_tests)
        target_compile_options(${tgt} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${tgt} PRIVATE -fsanitize=address,undefined)
    endforeach()
    target_compile_definitions(fathom_tests PRIVATE FATHOM_SANITIZED=1)
endif()

set(FATHOM_QT_ROOT "/opt/homebrew/opt/qtbase" CACHE PATH "Qt 6 prefix")
if(EXISTS "${FATHOM_QT_ROOT}/lib/cmake/Qt6/Qt6Config.cmake")
    list(PREPEND CMAKE_PREFIX_PATH "${FATHOM_QT_ROOT}")
endif()
find_package(Qt6 QUIET COMPONENTS Widgets Concurrent)
if(Qt6_FOUND)
    qt_standard_project_setup()
    qt_add_executable(fathom_app MACOSX_BUNDLE
        src/ui/main.cpp
        src/ui/main_window.cpp
        src/ui/main_window.hpp
        src/ui/disasm_model.cpp
        src/ui/disasm_model.hpp
        src/ui/hex_model.cpp
        src/ui/hex_model.hpp
        src/ui/graph_view.cpp
        src/ui/graph_view.hpp
        src/ui/theme.hpp
    )
    target_link_libraries(fathom_app PRIVATE fathom_core Qt6::Widgets Qt6::Concurrent)
    target_compile_options(fathom_app PRIVATE -Wall -Wextra -Wpedantic)
    set_target_properties(fathom_app PROPERTIES
        OUTPUT_NAME Fathom
        MACOSX_BUNDLE_BUNDLE_NAME "Fathom"
        MACOSX_BUNDLE_GUI_IDENTIFIER "local.fathom.workbench"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
        MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
    )
    install(TARGETS fathom_app BUNDLE DESTINATION Applications)
    if(FATHOM_SANITIZE)
        target_compile_options(fathom_app PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(fathom_app PRIVATE -fsanitize=address,undefined)
    endif()
else()
    message(STATUS "Qt6 not found; the Fathom.app workbench will not be built")
endif()

install(TARGETS fathom RUNTIME DESTINATION bin)
