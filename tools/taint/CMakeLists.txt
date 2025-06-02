# Find out what libraries are needed by LLVM
llvm_map_components_to_libnames(LLVM_LINK_COMPONENTS
  #Core
  #Support
  IRReader
  #BitReader
  #Target
)

add_executable(taint-analyzer taint-analyzer.cpp)
if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    target_link_libraries(taint-analyzer PRIVATE
            CanaryTaint
            CanarySupport
            -Wl,--start-group
            ${LLVM_LINK_COMPONENTS}
            -Wl,--end-group
            z ncurses pthread dl
    )
else()
    target_link_libraries(taint-analyzer PRIVATE
            CanaryTaint
            CanarySupport
            ${LLVM_LINK_COMPONENTS}
            z ncurses pthread dl
    )
endif() 