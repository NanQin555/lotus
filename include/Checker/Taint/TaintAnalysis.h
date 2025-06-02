#ifndef TAINT_ANALYSIS_H
#define TAINT_ANALYSIS_H

#include <llvm/IR/Function.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Value.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SmallPtrSet.h>

#include <map>
#include <set>
#include <vector>
#include <string>

namespace taint {

// Forward declarations
class TaintValue;
class TaintState;
class TaintAnalysisResult;

// Taint source types
enum class TaintSourceType {
    USER_INPUT,      // User input (stdin, argv, environment variables)
    NETWORK_INPUT,   // Network input (socket reads, HTTP requests)
    FILE_INPUT,      // File input (file reads)
    EXTERNAL_CALL,   // External function calls
    CUSTOM          // Custom defined sources
};

// Taint sink types
enum class TaintSinkType {
    SYSTEM_CALL,     // System calls (system, exec family)
    FILE_WRITE,      // File writes
    NETWORK_WRITE,   // Network writes
    SQL_QUERY,       // SQL queries
    MEMORY_WRITE,    // Memory writes (strcpy, memcpy)
    CUSTOM          // Custom defined sinks
};

// Sanitizer types
enum class SanitizerType {
    INPUT_VALIDATION,  // Input validation functions
    ENCODING,         // Encoding functions (HTML, URL encoding)
    ESCAPING,         // Escaping functions (SQL escaping)
    BOUNDS_CHECK,     // Bounds checking
    CUSTOM           // Custom sanitizers
};

// Represents a tainted value with its source information
class TaintValue {
public:
    llvm::Value* value;
    TaintSourceType sourceType;
    llvm::Instruction* sourceLocation;
    std::string sourceDescription;
    std::set<TaintValue*> derivedFrom;
    
    TaintValue(llvm::Value* v, TaintSourceType type, llvm::Instruction* loc, const std::string& desc)
        : value(v), sourceType(type), sourceLocation(loc), sourceDescription(desc) {}
    
    bool operator==(const TaintValue& other) const {
        return value == other.value && sourceLocation == other.sourceLocation;
    }
    
    bool operator<(const TaintValue& other) const {
        if (value != other.value) return value < other.value;
        return sourceLocation < other.sourceLocation;
    }
};

// Represents the taint state at a program point
class TaintState {
public:
    std::set<TaintValue*> taintedValues;
    std::map<llvm::Value*, std::set<TaintValue*>> valueTaints;
    
    void addTaint(llvm::Value* val, TaintValue* taint);
    void removeTaint(llvm::Value* val);
    bool isTainted(llvm::Value* val) const;
    std::set<TaintValue*> getTaints(llvm::Value* val) const;
    void merge(const TaintState& other);
    void clear();
    
    bool operator==(const TaintState& other) const;
    bool operator!=(const TaintState& other) const { return !(*this == other); }
};

// Configuration for taint analysis
struct TaintConfig {
    // Source functions (function name -> source type)
    std::map<std::string, TaintSourceType> sourceFunctions;
    
    // Sink functions (function name -> sink type)
    std::map<std::string, TaintSinkType> sinkFunctions;
    
    // Sanitizer functions (function name -> sanitizer type)
    std::map<std::string, SanitizerType> sanitizerFunctions;
    
    // Whether to track through memory operations
    bool trackThroughMemory = true;
    
    // Whether to track through function calls
    bool trackThroughCalls = true;
    
    // Maximum depth for interprocedural analysis
    int maxCallDepth = 5;
    
    TaintConfig();
    void loadDefaultConfig();
};

// Represents a taint flow from source to sink
struct TaintFlow {
    TaintValue* source;
    llvm::Instruction* sink;
    TaintSinkType sinkType;
    std::vector<llvm::Instruction*> path;
    bool sanitized;
    std::vector<llvm::Instruction*> sanitizers;
    
    TaintFlow(TaintValue* src, llvm::Instruction* snk, TaintSinkType type)
        : source(src), sink(snk), sinkType(type), sanitized(false) {}
};

// Main taint analysis result
class TaintAnalysisResult {
public:
    std::vector<TaintFlow> flows;
    std::map<llvm::Function*, std::map<llvm::Instruction*, TaintState>> functionStates;
    std::set<TaintValue*> allTaints;
    
    void addFlow(const TaintFlow& flow);
    void addTaint(TaintValue* taint);
    void setState(llvm::Function* func, llvm::Instruction* inst, const TaintState& state);
    TaintState getState(llvm::Function* func, llvm::Instruction* inst) const;
    
    void printResults(llvm::raw_ostream& OS) const;
    void printFlows(llvm::raw_ostream& OS) const;
    void printStatistics(llvm::raw_ostream& OS) const;
};

// Main taint analysis engine
class TaintAnalysis {
private:
    TaintConfig config;
    TaintAnalysisResult result;
    
    // Helper methods
    bool isSourceFunction(const llvm::Function* func) const;
    bool isSinkFunction(const llvm::Function* func) const;
    bool isSanitizerFunction(const llvm::Function* func) const;
    
    TaintSourceType getSourceType(const llvm::Function* func) const;
    TaintSinkType getSinkType(const llvm::Function* func) const;
    SanitizerType getSanitizerType(const llvm::Function* func) const;
    
    void analyzeFunction(llvm::Function* func);
    void analyzeInstruction(llvm::Instruction* inst, TaintState& state);
    void analyzeCallInstruction(llvm::CallInst* call, TaintState& state);
    
    void propagateTaint(llvm::Value* from, llvm::Value* to, TaintState& state);
    void checkForTaintFlow(llvm::Instruction* inst, const TaintState& state);
    
    TaintValue* createTaintValue(llvm::Value* val, TaintSourceType type, llvm::Instruction* loc, const std::string& desc);
    
public:
    TaintAnalysis(const TaintConfig& cfg = TaintConfig()) : config(cfg) {
        config.loadDefaultConfig();
    }
    
    // Analysis methods
    void analyzeModule(llvm::Module* M);
    
    const TaintAnalysisResult& getResult() const { return result; }
    TaintAnalysisResult& getResult() { return result; }
    
    void setConfig(const TaintConfig& cfg) { config = cfg; }
    const TaintConfig& getConfig() const { return config; }
};

} // namespace taint

#endif // TAINT_ANALYSIS_H 