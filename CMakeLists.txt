cmake_minimum_required(VERSION 3.10)

# 设置项目名称
project(algorithm)

set(CMAKE_DEBUG_POSTFIX d)

set(CXX_FLAGS
    -g
    # -DVALGRIND
    -DCHECK_PTHREAD_RETURN_VALUE
    -D_FILE_OFFSET_BITS=64
    -march=native
    # -MMD
    -rdynamic
    )
string(REPLACE ";" " " CMAKE_CXX_FLAGS "${CXX_FLAGS}")

# 设置生成文件输出路径
set(EXECUTABLE_OUTPUT_PATH, ./output/debug/bin)
add_executable(algorithm ./main/sha1_test.cc)

target_include_directories(algorithm PUBLIC ./inc/)
target_include_directories(algorithm PRIVATE ./extern_inc/)

target_link_directories(algorithm PRIVATE ./lib/debug/)

target_link_libraries(algorithm PRIVATE basicd)
include(src/CMakeLists.txt)

