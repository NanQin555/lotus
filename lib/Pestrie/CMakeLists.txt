# Define the library name
set(PESTRIE_LIB_NAME "Pestrie")

# Collect all source files
file(GLOB PESTRIE_SOURCES "*.cc")

# Create the static library
add_library(${PESTRIE_LIB_NAME} STATIC ${PESTRIE_SOURCES})

# Set include directories
target_include_directories(${PESTRIE_LIB_NAME} 
    PUBLIC ${CMAKE_SOURCE_DIR}/include)

# Add preprocessor definitions
target_compile_definitions(${PESTRIE_LIB_NAME} PRIVATE INDEX_UTILITY)

# Link math library on Unix
if(UNIX)
    target_link_libraries(${PESTRIE_LIB_NAME} PRIVATE m)
endif()
