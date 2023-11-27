#include "SMT/SMTModel.h"
#include "SMT/SMTFactory.h"
#include <string>
#include <sstream>


SMTModel::SMTModel(SMTFactory *F, z3::model Z3Model) :
		SMTObject(F), Model(Z3Model) {
}

SMTModel::SMTModel(SMTModel const &M) :
		SMTObject(M), Model(M.Model) {
}

SMTModel::~SMTModel() {
}

SMTModel& SMTModel::operator=(const SMTModel &M) {
	SMTObject::operator =(M);
	if (this != &M) {
		this->Model = M.Model;
	}
	return *this;
}

unsigned SMTModel::size() {
	return Model.size();
}

std::pair<std::string, std::string> SMTModel::getModelDbgInfo(int Index) {
	auto Item = Model[Index];

	if (Item.name().kind() == Z3_STRING_SYMBOL) {
		z3::expr E = Model.get_const_interp(Item);
		std::ostringstream OstrExpr;
		OstrExpr << E;

		std::ostringstream OstrTy;
		OstrTy << E.get_sort();

		return std::pair<std::string, std::string>(OstrExpr.str(), OstrTy.str());
	} else {
		return std::pair<std::string, std::string>("", "");
	}
}

SMTExpr SMTModel::Eval(SMTExpr const &E, bool ModelCompletion) const {
	return SMTExpr(&E.getSMTFactory(), Model.eval(E.Expr, ModelCompletion));
}

std::pair<int, bool> SMTModel::getIntValue(const SMTExpr &E,
		bool ModelCompletion) const {
	std::pair<int, bool> Ret(0, false);
	try {
		Ret.first = Model.eval(E.Expr, ModelCompletion).get_numeral_int();
	} catch (z3::exception &Ex) {
		return Ret;
	}
	Ret.second = true;
	return Ret;
}

std::pair<bool, bool> SMTModel::getBoolValue(const SMTExpr &E,
		bool ModelCompletion) const {
	// E can be a variable of bool type or a predicate.
	std::pair<bool, bool> Ret(false, false);
	if (!E.Expr.is_bool())
		return Ret;
	try {
		Z3_lbool Tmp = Model.eval(E.Expr, ModelCompletion).bool_value();
		if (Tmp == Z3_L_FALSE) {
			Ret.first = true;
		} else if (Tmp == Z3_L_TRUE) {
			Ret.first = true;
			Ret.second = true;
		}
	} catch (z3::exception &Ex) {
		return Ret;
	}
	return Ret;
}

// Given a model, build a partial model contains only variables from Vars.
// this is not a good approach, but currently we cannot build a model explicitly with C/C++ APIs

/*
 * Here is an examples using getExprVars, setDifference and getPartialModel.
 *  	SMTFactory ft;
 SMTExpr x = ft.createBitVecConst("x", 32);
 SMTExpr y = ft.createBitVecConst("y", 32);

 SMTSolver sol = ft.createSMTSolver();
 SMTExpr gg = x == 0 && y == 1;
 sol.add(gg); sol.check();

 // we hope to mark them as "don't cares"
 SMTExprVec interface_vars = ft.createEmptySMTExprVec();
 interface_vars.push_back(y);

 // get all variables
 SMTExprVec all_vars = ft.createEmptySMTExprVec();
 gg.getExprVars(all_vars);

 // build the partial model containing only all_vars - interface_vars
 SMTModel par_mol = sol.getSMTModel().getPartialModel(all_vars.setDifference(interface_vars));

 SMTExpr ff = y * x == 0;
 std::cout << par_mol.getBoolValue(ff).second << std::endl;
 *
 */

SMTModel SMTModel::getPartialModel(const SMTExprVec &Vars) {
#if 0
	z3::solver Solver4Model(*&getSMTFactory().getZ3Ctx());
	for (unsigned I = 0; I < Vars.size(); I++) {
		Solver4Model.add(Vars[I].getZ3Expr() == Model.eval(Vars[I].getZ3Expr()));
	}
	Solver4Model.check();
	return SMTModel(&getSMTFactory(), Solver4Model.get_model());
#else
	SMTSolver Solver4Model = Vars.getSMTFactory().createSMTSolver();
	for (unsigned I = 0; I < Vars.size(); I++) {
		Solver4Model.add(Vars[I] == this->Eval(Vars[I]));
	}
	Solver4Model.check();
	return Solver4Model.getSMTModel();
#endif
}

