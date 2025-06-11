add_subdirectory(DyckAA)
add_subdirectory(CFLAA)
add_subdirectory(seadsa) 
add_subdirectory(Andersen)
add_subdirectory(AllocAA)
add_subdirectory(FPA)
add_subdirectory(Dynamic)


# FSCS needs further updates for LLVM 14 compatibility - see lib/Alias/FSCS/LLVM14_UPGRADE.md
# add_subdirectory(FSCS)

# Build PointerAnalysisInterface as a separate library (not a good idea?)
# add_library(PointerAnalysisInterface SHARED PointerAnalysisInterface.cpp)
# target_include_directories(PointerAnalysisInterface PUBLIC ${CMAKE_SOURCE_DIR}/include)
