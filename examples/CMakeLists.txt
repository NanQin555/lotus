# Examples CMakeLists.txt

# BDD Example
add_executable(BDDExample BDDExample.cpp)
target_include_directories(BDDExample PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(BDDExample PRIVATE BDD m)


# Model Checking Example
add_executable(ModelCheckingExample ModelCheckingExample.cpp)
target_include_directories(ModelCheckingExample PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(ModelCheckingExample PRIVATE BDD m)

# RapidJSON Example
add_executable(RapidJSONExample RapidJSONExample.cpp)
target_include_directories(RapidJSONExample PUBLIC ${CMAKE_SOURCE_DIR}/include)

# Andersen Example
add_executable(AndersenExample AndersenExample.cpp)
target_include_directories(AndersenExample PUBLIC ${CMAKE_SOURCE_DIR}/include)

# Get LLVM components needed for examples that don't get LLVM through dependencies
llvm_map_components_to_libnames(llvm_libs irreader analysis)

target_link_libraries(AndersenExample PRIVATE 
  AndersenStatic 
  ${llvm_libs}
) 


# PDG Example
add_executable(PDGExample PDGExample.cpp)
target_include_directories(PDGExample PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(PDGExample PRIVATE
  CanaryPDG
  ${llvm_libs}
)

# WPDS Examples 
# add_subdirectory(wpds) 


# BDD Points-to Set Benchmark
# add_executable(BDDPtsSetBenchmark BDDPtsSetBenchmark.cpp)
# target_include_directories(BDDPtsSetBenchmark PUBLIC ${CMAKE_SOURCE_DIR}/include)
# target_link_libraries(BDDPtsSetBenchmark PRIVATE
#  AndersenStatic
#  BDD
#  ${llvm_libs}
#  m
#) 

# Pointer Analysis Interface Example
# add_executable(PointerAnalysisExample PointerAnalysisExample.cpp)
# target_include_directories(PointerAnalysisExample PUBLIC ${CMAKE_SOURCE_DIR}/include)
# target_link_libraries(PointerAnalysisExample PRIVATE 
#  PointerAnalysisInterface
#  ${llvm_libs}
#) 