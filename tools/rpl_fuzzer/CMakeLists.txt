# Minimum required CMake version
cmake_minimum_required(VERSION 3.0)

project(mariadb_fuzzers C)

# 1. Enforce that the fuzzer is compiled using Clang and the correct flags
if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "Fuzzing requires the Clang compiler. Reconfigure with -DCMAKE_C_COMPILER=clang")
endif()

# 2. Define the fuzzing and sanitizer compilation flags
set(FUZZ_FLAGS "-fsanitize=fuzzer,address,undefined -g -fprofile-instr-generate -fcoverage-mapping")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FUZZ_FLAGS}")

# 3. Add the fuzzer executable target
add_executable(rpl_fuzzer rpl_fuzzer.c)

file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data"
     DESTINATION "${CMAKE_CURRENT_BINARY_DIR}"
)

# 4. Pull in includes from the core connector (adjust paths if your source layout differs)
target_include_directories(rpl_fuzzer PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/libmariadb
)

# 5. Link against the internal mariadb library target and zlib
# 'mariadb_obj' or 'libmariadb' ensures it links statically or directly to the object files
target_link_libraries(rpl_fuzzer PRIVATE
    libmariadb
    z
    pthread
    m
)
