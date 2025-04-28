#include "Alias/FSCS/FrontEnd/CFG/CFGBuilder.h"
#include "Alias/FSCS/FrontEnd/SemiSparseProgramBuilder.h"
#include "Alias/FSCS/FrontEnd/Type/TypeAnalysis.h"

#include <llvm/IR/Module.h>

using namespace llvm;

namespace tpa
{

void SemiSparseProgramBuilder::buildCFGForFunction(SemiSparseProgram& ssProg, const Function& f, const TypeMap& typeMap)
{
	auto& cfg = ssProg.getOrCreateCFGForFunction(f);
	CFGBuilder(cfg, typeMap).buildCFG(f);
}

SemiSparseProgram SemiSparseProgramBuilder::runOnModule(const Module& module)
{
	SemiSparseProgram ssProg(module);

	// Process types
	auto typeMap = TypeAnalysis().runOnModule(module);

	// Translate functions to CFG
	for (auto const& f: module)
	{
		if (f.isDeclaration())
			continue;

		buildCFGForFunction(ssProg, f, typeMap);
	}

	ssProg.setTypeMap(std::move(typeMap));
	return ssProg;
}

}