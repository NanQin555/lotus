add_subdirectory(DyckAA)
add_subdirectory(CFLAA)
add_subdirectory(seadsa) 
add_subdirectory(Andersen)
add_subdirectory(AllocAA)
add_subdirectory(FPA)
add_subdirectory(Dynamic)
# FSCS needs further updates for LLVM 14 compatibility - see lib/Alias/FSCS/LLVM14_UPGRADE.md
# add_subdirectory(FSCS)

# Build PointerAnalysisInterface as a separate library
add_library(PointerAnalysisInterface SHARED PointerAnalysisInterface.cpp)
target_include_directories(PointerAnalysisInterface PUBLIC ${CMAKE_SOURCE_DIR}/include)

# Get LLVM components needed for PointerAnalysisInterface
llvm_map_components_to_libnames(pointer_analysis_llvm_libs support core analysis)

target_link_libraries(PointerAnalysisInterface
	PRIVATE
	${pointer_analysis_llvm_libs}
	Andersen
	CFLAA
)