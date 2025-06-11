set(AndersenSourceCodes
	Andersen.cpp
	AndersenAA.cpp
	ConstraintCollect.cpp
	ConstraintOptimize.cpp
	ConstraintSolving.cpp
	ExternalLibrary.cpp
	NodeFactory.cpp
)

# Get LLVM components for Andersen
llvm_map_components_to_libnames(andersen_llvm_libs analysis)

add_library(AndersenObj OBJECT ${AndersenSourceCodes})
add_library(Andersen SHARED $<TARGET_OBJECTS:AndersenObj>)
add_library(AndersenStatic STATIC $<TARGET_OBJECTS:AndersenObj>)
set_target_properties(AndersenStatic PROPERTIES OUTPUT_NAME "Andersen")

target_link_libraries(Andersen
	PRIVATE
	${andersen_llvm_libs}
)

target_link_libraries(AndersenStatic
	PRIVATE
	${andersen_llvm_libs}
)