option(BUILD_TESTING "" OFF)
option(FMT_OS "" OFF)
add_subdirectory(fmt)
add_subdirectory(json)

option(tinyxml2_BUILD_TESTING "" OFF)
add_subdirectory(tinyxml2)

add_subdirectory(quickjs)
