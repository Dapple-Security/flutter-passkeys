cmake_minimum_required(VERSION 3.15)
set(PROJECT_NAME "passkeys_windows")
project(${PROJECT_NAME} LANGUAGES CXX)

# This value is used when generating builds using this plugin, so it must
# not be changed
set(PLUGIN_NAME "passkeys_windows_plugin")

# Fetch nlohmann/json for JSON parsing
include(FetchContent)
FetchContent_Declare(
  nlohmann_json
  URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
)
set(JSON_BuildTests OFF CACHE INTERNAL "")
set(JSON_Install OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(nlohmann_json)

add_library(${PLUGIN_NAME} SHARED
  "passkeys_windows.cpp"
  "passkeys_windows_plugin.cpp"
  "webauthn_helper.cpp"
  "messages.g.cpp"
)

apply_standard_settings(${PLUGIN_NAME})
set_target_properties(${PLUGIN_NAME} PROPERTIES
  CXX_VISIBILITY_PRESET hidden)
target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)
target_include_directories(${PLUGIN_NAME} INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(${PLUGIN_NAME} PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(${PLUGIN_NAME} PRIVATE
  flutter
  flutter_wrapper_plugin
  WebAuthN
  crypt32
  bcrypt
  nlohmann_json::nlohmann_json
)

# WebAuthn API is loaded dynamically from webauthn.dll at runtime
# No static library linking required

# List of absolute paths to libraries that should be bundled with the plugin
set(passkeys_windows_bundled_libraries
  ""
  PARENT_SCOPE
)
