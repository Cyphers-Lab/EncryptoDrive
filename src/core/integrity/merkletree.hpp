#pragma once

#include "core/core_export.hpp"
#include "core/fileintegrity.hpp"
#include "core/securememory.hpp"
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <ctime>
#include <fstream>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace encrypto::core {

/**
 * @brief Merkle Tree implementation for directory integrity verification
 */
class ENCRYPTO_CORE_EXPORT MerkleTree {
public:
    /**
     * @brief Node metadata for encrypted storage
     */
    struct NodeMetadata {
        std::string path;
        std::time_t timestamp;
        size_t size;
        bool isDirectory;
    };

    /**
     * @brief Constructor
     * @param hasher FileIntegrity instance for hash calculations
     */
    explicit MerkleTree(std::shared_ptr<FileIntegrity> hasher);

    /**
     * @brief Add or update a file/directory in the tree
     */
    bool updateNode(const std::string& path, const std::vector<uint8_t>& data);

    bool verifyPath(const std::string& path, const std::vector<uint8_t>& data);
    std::vector<std::vector<uint8_t>> getProof(const std::string& path) const;
    bool verifyProof(const std::string& path,
                    const std::vector<uint8_t>& data,
                    const std::vector<std::vector<uint8_t>>& proof);

    bool save(const std::string& filename,
             const SecureMemory::SecureVector<uint8_t>& key) const;
    bool load(const std::string& filename,
             const SecureMemory::SecureVector<uint8_t>& key);

    std::vector<uint8_t> getRootHash() const;

    // Debug helpers
    void enableDebugOutput() { debugEnabled_ = true; }
    void disableDebugOutput() { debugEnabled_ = false; }
    std::string getDebugOutput() const { return debugStream_.str(); }
    void clearDebugOutput() { debugStream_.str(""); }

protected:
    struct Node {
        std::vector<uint8_t> hash;
        NodeMetadata metadata;
        std::unique_ptr<Node> left;
        std::unique_ptr<Node> right;
        bool isLeaf{true};

        Node() = default;
        explicit Node(const std::vector<uint8_t>& h) : hash(h) {}
    };

    // Helper methods
    std::unique_ptr<Node> createNode(const std::vector<uint8_t>& data,
                                   const NodeMetadata& metadata);
    void updateParentHashes(const std::string& path);
    std::vector<Node*> getPathToRoot(const std::string& path) const;
    Node* findNode(const std::string& path) const;
    std::vector<uint8_t> calculateNodeHash(const Node& node) const;
    std::vector<std::string> splitPath(const std::string& path) const;
    bool addToDirectory(Node* directory, 
                       const std::vector<std::string>& pathComponents,
                       std::unique_ptr<Node> node);
    void serializeNode(const Node& node, std::vector<uint8_t>& output) const;
    std::unique_ptr<Node> deserializeNode(const std::vector<uint8_t>& input, size_t& pos);
    void rebuildPathMap(Node* node, const std::string& parentPath);

    void debug(const std::string& message) const {
        if (debugEnabled_) {
            debugStream_ << message << std::endl;
        }
    }

    template<typename T>
    void debugHex(const std::string& prefix, const T& data) const {
        if (debugEnabled_) {
            debugStream_ << prefix;
            for (const auto& b : data) {
                debugStream_ << std::hex << std::setw(2) << std::setfill('0') 
                           << static_cast<int>(b);
            }
            debugStream_ << std::dec << std::endl;
        }
    }

private:
    std::unique_ptr<Node> root_;
    std::shared_ptr<FileIntegrity> hasher_;
    std::unordered_map<std::string, Node*> pathMap_;
    bool debugEnabled_{false};
    mutable std::stringstream debugStream_;
};

} // namespace encrypto::core
