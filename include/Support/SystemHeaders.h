
#ifndef SYSTEMHEADERS_H
#define SYSTEMHEADERS_H
#include <map>
#include <unordered_map>
#include <set>
#include <unordered_set>
#include <vector>
#include <stack>
#include <queue>
#include <list>
#include <deque>
#include <thread>
#include <sstream>
#include <math.h>
#include <optional>

/*
 * LLVM headers.
 */
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/InstrTypes.h"
#include <llvm/ADT/StringRef.h>
#include "llvm/ADT/iterator_range.h"
#include "llvm/ADT/SCCIterator.h"
#include "llvm/ADT/BitVector.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/DerivedUser.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/DataLayout.h"
#include <llvm/IR/InstVisitor.h>
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/LoopUtils.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionExpressions.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/IR/Mangler.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/CFG.h"
#include <llvm/IR/Verifier.h>

using namespace llvm;

#endif