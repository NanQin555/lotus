add_subdirectory(canary)
add_subdirectory(kint)
add_subdirectory(seadsa)
add_subdirectory(fpa)
add_subdirectory(dynaa)
add_subdirectory(esss)
add_subdirectory(z_solver)
add_subdirectory(taint)

# Optional targets - OFF by default
option(BUILD_OWL "Build Owl SMT solver" OFF)
option(BUILD_HORN_ICE "Build ICE learning for CHC and Boogie" OFF)
option(BUILD_CSR "Build indexing context-sensitive reachability" OFF)

if(BUILD_OWL)
    add_subdirectory(owl)
endif()

if(BUILD_HORN_ICE)
    add_subdirectory(horn-ice)
endif()

if(BUILD_CSR)
    add_subdirectory(csr)
endif() 