#include "z3++.h"
#include "SMT/SMTConfigure.h"

int SMTConfigure::Timeout;

static int SolverTimetout = 0;

void SMTConfigure::init(int T) {
	if (T != -1 && SolverTimetout == 0) {
		Timeout = T;
	}
}
