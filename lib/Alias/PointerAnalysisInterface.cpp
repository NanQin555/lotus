#include "Alias/PointerAnalysisInterface.h"
#include "Alias/Andersen/AndersenAA.h"
#include "Alias/CFLAA/CFLSteensAliasAnalysis.h"
#include "Alias/CFLAA/CFLAndersAliasAnalysis.h"

#include "llvm/Analysis/BasicAliasAnalysis.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Support/CommandLine.h"
// #include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

#include <string>
#include <memory>

using namespace llvm;
using namespace lotus;

// Register command line options
static cl::opt<std::string> DefaultAnalysisType(
    "default-ptr-analysis", cl::desc("Default pointer analysis to use"),
    cl::value_desc("analysis type"), cl::init("andersen"));

//===----------------------------------------------------------------------===//
// Andersen Pointer Analysis Implementation
//===----------------------------------------------------------------------===//

class AndersenPointerAnalysisResult::Implementation {
private:
  std::unique_ptr<AndersenAAResult> Result;

public:
  Implementation(const Module &M) {
    Result = std::make_unique<AndersenAAResult>(M);
  }

  AliasResult alias(const MemoryLocation &LocA, const MemoryLocation &LocB) {
    return Result->alias(LocA, LocB);
  }
};

AndersenPointerAnalysisResult::AndersenPointerAnalysisResult(const Module &M)
    : Impl(std::make_unique<Implementation>(M)) {}

AndersenPointerAnalysisResult::~AndersenPointerAnalysisResult() = default;

AliasResult AndersenPointerAnalysisResult::alias(const MemoryLocation &LocA,
                                             const MemoryLocation &LocB) {
  return Impl->alias(LocA, LocB);
}

//===----------------------------------------------------------------------===//
// CFLAnders Pointer Analysis Implementation
//===----------------------------------------------------------------------===//

class CFLAnderPointerAnalysisResult::Implementation {
private:
  std::unique_ptr<CFLAndersAAResult> Result;

public:
  Implementation(const Module &Mod) {
    // Create a function to get TargetLibraryInfo
    auto GetTLI = [](Function &) -> const TargetLibraryInfo & {
      static TargetLibraryInfoImpl TLII;
      static TargetLibraryInfo TLI(TLII);
      return TLI;
    };
    
    Result = std::make_unique<CFLAndersAAResult>(GetTLI);
    errs() << "CFLAnders initialized for module: " << Mod.getName() << "\n";
  }

  AliasResult alias(const MemoryLocation &LocA, const MemoryLocation &LocB) {
    AAQueryInfo AAQI(nullptr);
    return Result->alias(LocA, LocB, AAQI);
  }
};

CFLAnderPointerAnalysisResult::CFLAnderPointerAnalysisResult(const Module &M)
    : Impl(std::make_unique<Implementation>(M)) {}

CFLAnderPointerAnalysisResult::~CFLAnderPointerAnalysisResult() = default;

AliasResult CFLAnderPointerAnalysisResult::alias(const MemoryLocation &LocA,
                                          const MemoryLocation &LocB) {
  return Impl->alias(LocA, LocB);
}

//===----------------------------------------------------------------------===//
// CFLSteens Pointer Analysis Implementation
//===----------------------------------------------------------------------===//

class CFLSteensPointerAnalysisResult::Implementation {
private:
  std::unique_ptr<CFLSteensAAResult> Result;

public:
  Implementation(const Module &Mod) {
    // Create a function to get TargetLibraryInfo
    auto GetTLI = [](Function &) -> const TargetLibraryInfo & {
      static TargetLibraryInfoImpl TLII;
      static TargetLibraryInfo TLI(TLII);
      return TLI;
    };
    
    Result = std::make_unique<CFLSteensAAResult>(GetTLI);
    errs() << "CFLSteens initialized for module: " << Mod.getName() << "\n";
  }

  AliasResult alias(const MemoryLocation &LocA, const MemoryLocation &LocB) {
    AAQueryInfo AAQI(nullptr);
    return Result->alias(LocA, LocB, AAQI);
  }
};

CFLSteensPointerAnalysisResult::CFLSteensPointerAnalysisResult(const Module &M)
    : Impl(std::make_unique<Implementation>(M)) {}

CFLSteensPointerAnalysisResult::~CFLSteensPointerAnalysisResult() = default;

AliasResult CFLSteensPointerAnalysisResult::alias(const MemoryLocation &LocA,
                                          const MemoryLocation &LocB) {
  return Impl->alias(LocA, LocB);
}

//===----------------------------------------------------------------------===//
// BasicAA Pointer Analysis Implementation
//===----------------------------------------------------------------------===//

class BasicAAPointerAnalysisResult::Implementation {
public:
  Implementation(const Module &Mod) {
    errs() << "BasicAA initialized for module: " << Mod.getName() << "\n";
  }

  AliasResult alias(const MemoryLocation &LocA, const MemoryLocation &LocB) {
    // Conservative approach for BasicAA
    if (LocA.Ptr == LocB.Ptr) {
      return AliasResult::MustAlias;
    }
    
    // Conservative: assume everything may alias
    return AliasResult::MayAlias;
  }
};

BasicAAPointerAnalysisResult::BasicAAPointerAnalysisResult(const Module &M)
    : Impl(std::make_unique<Implementation>(M)) {}

BasicAAPointerAnalysisResult::~BasicAAPointerAnalysisResult() = default;

AliasResult BasicAAPointerAnalysisResult::alias(const MemoryLocation &LocA,
                                       const MemoryLocation &LocB) {
  return Impl->alias(LocA, LocB);
}

//===----------------------------------------------------------------------===//
// Factory Implementation
//===----------------------------------------------------------------------===//

std::unique_ptr<PointerAnalysisResult> PointerAnalysisFactory::create(
    const Module &M, const std::string &Type) {
  if (Type == "andersen") {
    return std::make_unique<AndersenPointerAnalysisResult>(M);
  } else if (Type == "cfl-anders") {
    return std::make_unique<CFLAnderPointerAnalysisResult>(M);
  } else if (Type == "cfl-steens") {
    return std::make_unique<CFLSteensPointerAnalysisResult>(M);
  } else if (Type == "basic") {
    return std::make_unique<BasicAAPointerAnalysisResult>(M);
  }
  
  // Default to Andersen if the requested type is not available
  errs() << "Warning: Pointer analysis type '" << Type 
         << "' not supported. Using Andersen instead.\n";
  return std::make_unique<AndersenPointerAnalysisResult>(M);
}

//===----------------------------------------------------------------------===//
// Pass Implementation
//===----------------------------------------------------------------------===//

char PointerAnalysisWrapperPass::ID = 0;

PointerAnalysisWrapperPass::PointerAnalysisWrapperPass(const std::string &Type)
    : ModulePass(ID), AnalysisType(Type) {}

PointerAnalysisWrapperPass::~PointerAnalysisWrapperPass() = default;

bool PointerAnalysisWrapperPass::runOnModule(Module &M) {
  Result = PointerAnalysisFactory::create(M, AnalysisType);
  return false;
}

void PointerAnalysisWrapperPass::getAnalysisUsage(AnalysisUsage &AU) const {
  // This pass does not modify the program
  AU.setPreservesAll();
}

// Register the pass
static RegisterPass<PointerAnalysisWrapperPass>
    X("ptr-analysis", "Unified Pointer Analysis", false, true); 