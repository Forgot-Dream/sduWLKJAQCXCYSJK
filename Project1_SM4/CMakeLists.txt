cmake_minimum_required(VERSION 3.10)
project(SM4_Implementation)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 编译选项
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")

# 检测编译器和架构
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    set(X86_64_ARCH TRUE)
    message(STATUS "Detected x86_64 architecture")
else()
    set(X86_64_ARCH FALSE)
    message(STATUS "Not x86_64 architecture, some optimizations will be disabled")
endif()

# 设置编译器特定的选项
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    message(STATUS "Using GCC compiler")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
    if(X86_64_ARCH)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes -mavx -mavx2 -mavxvnni")
    endif()
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    message(STATUS "Using Clang compiler")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
    if(X86_64_ARCH)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes -mavx -mavx2 -mavxvnni")
    endif()
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    message(STATUS "Using MSVC compiler")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /arch:AVX2")
endif()

# 源文件列表
set(SM4_SOURCES
    sm4_basic.cpp
    sm4_ttable.cpp
    sm4_gcm.cpp
)

# 根据架构添加特定源文件
if(X86_64_ARCH)
    list(APPEND SM4_SOURCES
        sm4_aesni.cpp
        sm4_modern.cpp
    )
endif()

# 创建SM4库
add_library(sm4_lib STATIC ${SM4_SOURCES})

# 设置库的编译选项
target_include_directories(sm4_lib PUBLIC .)

# 创建测试可执行文件
add_executable(test_sm4 test_sm4.cpp)
target_link_libraries(test_sm4 sm4_lib)

# 如果需要线程库
find_package(Threads)
if(Threads_FOUND)
    target_link_libraries(test_sm4 Threads::Threads)
endif()

# 设置可执行文件属性
set_target_properties(test_sm4 PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# 复制头文件到构建目录
configure_file(sm4.h ${CMAKE_BINARY_DIR}/include/sm4.h COPYONLY)

# 安装目标
install(TARGETS sm4_lib test_sm4
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES sm4.h DESTINATION include)

# 提供构建信息
message(STATUS "SM4 Implementation Configuration:")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Compiler: ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "  Architecture: ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "  x86_64 optimizations: ${X86_64_ARCH}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")

# 添加自定义目标用于清理
add_custom_target(clean-all
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/CMakeCache.txt
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/CMakeFiles
)

# 添加性能测试目标
add_custom_target(benchmark
    COMMAND $<TARGET_FILE:test_sm4>
    DEPENDS test_sm4
    COMMENT "Running SM4 performance benchmarks"
)

# 添加验证测试目标
add_custom_target(verify
    COMMAND $<TARGET_FILE:test_sm4>
    DEPENDS test_sm4
    COMMENT "Running SM4 correctness tests"
)
