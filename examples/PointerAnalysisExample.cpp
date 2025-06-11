#include "Alias/PointerAnalysisInterface.h"

#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"

#include <memory>
#include <vector>

using namespace llvm;
using namespace lotus;

// Command line options
static cl::opt<std::string> InputFilename(cl::Positional,
                                         cl::desc("<input bitcode file>"),
                                         cl::Required);

static cl::opt<std::string> AnalysisType("analysis",
                                        cl::desc("Pointer analysis type"),
                                        cl::value_desc("type"),
                                        cl::init("andersen"));

int main(int argc, char **argv) {
  cl::ParseCommandLineOptions(argc, argv, "Pointer Analysis Example\n");

  LLVMContext Context;
  
  // Load the bitcode file
  auto BufferOrError = MemoryBuffer::getFile(InputFilename);
  if (std::error_code EC = BufferOrError.getError()) {
    errs() << "Error reading file: " << EC.message() << "\n";
    return 1;
  }

  auto ModuleOrError = parseBitcodeFile(BufferOrError.get()->getMemBufferRef(), Context);
  if (Error E = ModuleOrError.takeError()) {
    errs() << "Error parsing bitcode: ";
    logAllUnhandledErrors(std::move(E), errs(), "");
    return 1;
  }

  std::unique_ptr<Module> M = std::move(ModuleOrError.get());
  errs() << "Loaded module: " << M->getName() << "\n";

  // Create pointer analysis
  auto Analysis = PointerAnalysisFactory::create(*M, AnalysisType);
  if (!Analysis) {
    errs() << "Failed to create pointer analysis\n";
    return 1;
  }

  errs() << "Created " << AnalysisType << " pointer analysis\n";

  // Collect pointer values from the module
  std::vector<const Value*> Pointers;
  
  // Add global variables
  for (const GlobalVariable &GV : M->globals()) {
    if (GV.getType()->isPointerTy()) {
      Pointers.push_back(&GV);
    }
  }
  
  // Add function arguments and instructions
  for (const Function &F : *M) {
    // Add pointer arguments
    for (const Argument &Arg : F.args()) {
      if (Arg.getType()->isPointerTy()) {
        Pointers.push_back(&Arg);
      }
    }
    
    // Add pointer instructions
    for (const BasicBlock &BB : F) {
      for (const Instruction &I : BB) {
        if (I.getType()->isPointerTy()) {
          Pointers.push_back(&I);
        }
      }
    }
  }

  errs() << "Found " << Pointers.size() << " pointer values\n";

  // Demonstrate alias queries
  errs() << "\n=== Alias Analysis Results ===\n";
  unsigned AliasCount = 0;
  unsigned QueryCount = 0;
  
  // Test pairs of pointers for aliasing
  for (size_t i = 0; i < std::min(Pointers.size(), size_t(10)); ++i) {
    for (size_t j = i + 1; j < std::min(Pointers.size(), size_t(10)); ++j) {
      AliasResult Result = Analysis->alias(Pointers[i], Pointers[j]);
      QueryCount++;
      
      if (Result != AliasResult::NoAlias) {
        AliasCount++;
        errs() << "Alias (";
        switch (Result) {
          case AliasResult::MayAlias:
            errs() << "May";
            break;
          case AliasResult::MustAlias:
            errs() << "Must";
            break;
          case AliasResult::PartialAlias:
            errs() << "Partial";
            break;
          default:
            errs() << "Unknown";
            break;
        }
        errs() << "): ";
        Pointers[i]->print(errs());
        errs() << " <-> ";
        Pointers[j]->print(errs());
        errs() << "\n";
      }
    }
  }

  errs() << "\nSummary:\n";
  errs() << "- Total alias queries: " << QueryCount << "\n";
  errs() << "- Potential aliases found: " << AliasCount << "\n";

  return 0;
} 