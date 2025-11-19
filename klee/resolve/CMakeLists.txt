# project(resolve)
# cmake_minimum_required(VERSION 3.22)

add_library(resolve INTERFACE)

# target_include_directories(resolve PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

target_include_directories(resolve INTERFACE .)

# target_compile_features(resolve PUBLIC cxx_std_23)

# find_package(LLVM REQUIRED CONFIG HINTS "${LLVM_DIR}")
# message(STATUS "LLVM directory ${LLVM_DIR}")
# set(LLVMCC "${LLVM_TOOLS_BINARY_DIR}/clang"
#   CACHE
#   PATH
#   "Path to C bitcode compiler"
#   )
# set(LLVMCXX "${LLVM_TOOLS_BINARY_DIR}/clang++"
#   CACHE
#   PATH
#   "Path to C++ bitcode compiler"
# )

# target_link_libraries(resolve PRIVATE llvm)

# include_directories(${LLVM_INCLUDE_DIRS})

# add_executable(test test.cpp)
# target_link_libraries(test PRIVATE resolve)
