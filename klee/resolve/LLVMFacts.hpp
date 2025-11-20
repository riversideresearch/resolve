
#ifndef RESOLVE_LLVM_LLVMFACTS_HPP
#define RESOLVE_LLVM_LLVMFACTS_HPP

#include "Facts.hpp"
#include "NodeID.hpp"

#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/Support/FileSystem.h"

#include <unordered_map>

class LLVMFacts {
    Facts &facts;
    NodeID prefix;
    
    std::unordered_map<const llvm::Module*, std::string> moduleIDs;
    std::unordered_map<const llvm::Function*, std::string> functionIDs;
    std::unordered_map<const llvm::BasicBlock*, std::string> basicBlockIDs;
    std::unordered_map<const llvm::Argument*, std::string> argumentIDs;
    std::unordered_map<const llvm::Instruction*, std::string> instructionIDs;
    std::unordered_map<const llvm::GlobalVariable*, std::string> globalVarIDs;

    using edge_rec_t = std::tuple<std::string, std::string, std::string>;
    struct edge_rec_hash : public std::function<std::size_t(edge_rec_t)>
    {
        std::hash<std::string> hasher;
        std::size_t operator()(const edge_rec_t& k) const
        {
            return hasher(std::get<0>(k)) ^ hasher(std::get<1>(k)) ^ hasher(std::get<2>(k));
        }

        edge_rec_hash() {}
    };
    std::unordered_map<edge_rec_t, std::size_t, edge_rec_hash> edgeIdx;

public:
    LLVMFacts(Facts& facts, NodeID prefix = NodeID()) : facts(facts), prefix(prefix), edgeIdx() {
        prefix += "llvm";
    }

    NodeID addNode(const llvm::Module &M) {
        if (moduleIDs.find(&M) == moduleIDs.end()) {
            llvm::SmallString<128> src_path = llvm::StringRef(M.getSourceFileName());
            llvm::sys::fs::make_absolute(src_path);
    
            std::string id = prefix + std::string(src_path.str());
            moduleIDs[&M] = id;
            facts.recordNode(id, "Module");
            return id;
        }
        return moduleIDs[&M];
    }

    template <typename T>
    NodeID getParentID(const T &item) {
        return addNode(*item.getParent());
    }

    template <typename T>
    static std::size_t getIndexInParent(const T &item) {
        const auto &parent = *item.getParent();
        return std::distance(parent.begin(), item.getIterator());
    }

    NodeID addNode(const llvm::GlobalVariable &GV) {
        if (globalVarIDs.find(&GV) == globalVarIDs.end()) {
            std::string id = getParentID(GV) + ("g" + GV.getName().str());
            globalVarIDs[&GV] = id;
            facts.recordNode(id, "GlobalVariable");
            return id;
        }
        return globalVarIDs[&GV];
    }

    NodeID addNode(const llvm::Function &F) {
        if (functionIDs.find(&F) == functionIDs.end()) {
            std::string id = getParentID(F) + ("f" + F.getName().str());
            functionIDs[&F] = id;
            facts.recordNode(id, "Function");
            return id;
        }
        return functionIDs[&F];
    }

    NodeID addNode(const llvm::Argument &A) {
        if (argumentIDs.find(&A) == argumentIDs.end()) {
            auto idx = A.getArgNo();
            std::string id = getParentID(A) + ("a" + std::to_string(idx));
            argumentIDs[&A] = id;
            facts.recordNode(id, "Argument");
            return id;
        }
        return argumentIDs[&A];
    }

    NodeID addNode(const llvm::BasicBlock &BB) {
        if (basicBlockIDs.find(&BB) == basicBlockIDs.end()) {
            auto idx = getIndexInParent(BB);
            std::string id = getParentID(BB) + ("bb" + std::to_string(idx));
            basicBlockIDs[&BB] = id;
            facts.recordNode(id, "BasicBlock");
            return id;
        }
        return basicBlockIDs[&BB];
    }

    NodeID addNode(const llvm::Instruction &I) {
        if (instructionIDs.find(&I) == instructionIDs.end()) {
            auto idx = getIndexInParent(I);
            std::string id = getParentID(I) + ("i" + std::to_string(idx));
            instructionIDs[&I] = id;
            facts.recordNode(id, "Instruction");
            return id;
        }
        return instructionIDs[&I];
    }

    template <typename S, typename D>
    std::string addEdge(std::string kind, S &src, D &dst) {
        return addEdge(kind, addNode(src), addNode(dst));
    }

    std::string addEdge(std::string kind, std::string src, std::string dst) {
        auto [it, created] = edgeIdx.try_emplace(std::make_tuple(kind, src, dst), 0);
        auto &idx = it->second;
        
        std::string id;
        if (created) {
            id = src + "-[" + kind + "]->" + dst;
        } else {
            idx += 1;
            id = src + "-[" + kind + "; " + std::to_string(idx) + "]->" + dst;
        }
        
        facts.recordEdge(id, kind, src, dst);

        return id;
    }

    template <typename N>
    void addNodeProp(const N &node, const std::string &key, const std::string &value) {
        facts.recordNodeProp(addNode(node), key, value);
    }

    void addEdgeProp(const std::string &edgeID, const std::string &key, const std::string &value) {
        facts.recordEdgeProp(edgeID, key, value);
    }

    const std::string &getNodes() const {
        return facts.nodes;
    }
    
    const std::string &getNodeProps() const {
        return facts.nodeProps;
    }

    const std::string &getEdges() const {
        return facts.edges;
    }
    
    const std::string &getEdgeProps() const {
        return facts.edgeProps;
    }


};

#endif // RESOLVE_LLVM_LLVMFACTS_HPP
