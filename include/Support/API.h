#ifndef SUPPORT_API_H
#define SUPPORT_API_H

#include <llvm/IR/Instruction.h>
#include <set>

using namespace llvm;

class API {
public:
    static bool isMemoryAllocate(Instruction *);

    static bool isHeapAllocate(Instruction *);

    static bool isStackAllocate(Instruction *);

    static std::set<std::string> HeapAllocFunctions;
};

#endif //SUPPORT_API_H
