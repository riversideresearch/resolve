cmake_minimum_required(VERSION 3.20)
project(EnhancedFacts)

find_package(LLVM CONFIG)

# Add LLVM headers to include search paths
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

# Debug by default
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

# Match C++ stdlib version with system llvm
if(LLVM_VERSION_MAJOR GREATER_EQUAL 18)
    set(CMAKE_CXX_STANDARD 17 STRING "")
else()
    set(CMAKE_CXX_STANDARD 14 STRING "")
endif()

# LLVM is normally built without RTTI. Be consistent with that.
if(NOT LLVM_ENABLE_RTTI)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
endif()


add_library(EnhancedFacts SHARED EnhancedFacts.cpp)
add_library(CVEAssert SHARED 
  CVEAssert/CVEAssert.cpp
  CVEAssert/bounds_check.cpp
  CVEAssert/null_ptr.cpp
  CVEAssert/arith_san.cpp
  CVEAssert/helpers.cpp
)
add_library(AnnotateFunctions SHARED AnnotateFunctions.cpp)
add_library(ObjHook SHARED ObjHook.cpp)
add_library(DlsymHook SHARED DlsymHook.cpp)



