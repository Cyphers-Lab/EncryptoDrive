#include "merkletree.hpp"
#include "../encryptionengine.hpp"
#include <algorithm>
#include <stack>
#include <sstream>
#include <cassert>
#include <iostream>
#include <iomanip>

namespace encrypto::core {

MerkleTree::MerkleTree(std::shared_ptr<FileIntegrity> hasher)
    : hasher_(std::move(hasher)) {
    assert(hasher_ != nullptr);
    debug("MerkleTree initialized");
}

std::unique_ptr<MerkleTree::Node> MerkleTree::createNode(
    const std::vector<uint8_t>& data,
    const NodeMetadata& metadata) {
    auto node = std::make_unique<Node>();
    node->hash = hasher_->calculateHash(data);
    node->metadata = metadata;
    debugHex("Created node with hash: ", node->hash);
    return node;
}

bool MerkleTree::updateNode(const std::string& path,
                          const std::vector<uint8_t>& data) {
    std::stringstream ss;
    ss << "\n=== updateNode: Adding path " << path << " ===\n"
       << "Data size: " << data.size() << " bytes";
    debug(ss.str());
    
    if (path.empty()) {
        debug("Empty path, returning false");
        return false;
    }

    NodeMetadata metadata;
    metadata.path = path;
    metadata.timestamp = std::time(nullptr);
    metadata.size = data.size();
    metadata.isDirectory = false;

    auto node = createNode(data, metadata);
    debugHex("Node hash: ", node->hash);
    
    if (!root_) {
        debug("No root exists yet - Creating first node as root");
        root_ = std::move(node);
        pathMap_[path] = root_.get();
        debugHex("Root hash set to: ", root_->hash);
        return true;
    }

    if (!pathMap_["/"] && root_) {
        debug("Converting root file to directory structure");
        auto oldRoot = std::move(root_);
        auto dirNode = std::make_unique<Node>();
        dirNode->metadata.path = "/";
        dirNode->metadata.timestamp = std::time(nullptr);
        dirNode->metadata.isDirectory = true;
        dirNode->isLeaf = false;
        dirNode->left = std::move(oldRoot);
        dirNode->right = std::move(node);
        
        debug("Updating path map for directory structure");
        pathMap_.clear();
        pathMap_["/"] = dirNode.get();
        pathMap_[dirNode->left->metadata.path] = dirNode->left.get();
        pathMap_[path] = dirNode->right.get();
        
        std::vector<uint8_t> combined;
        combined.insert(combined.end(), dirNode->left->hash.begin(), dirNode->left->hash.end());
        combined.insert(combined.end(), dirNode->right->hash.begin(), dirNode->right->hash.end());
        
        debugHex("Left child hash: ", dirNode->left->hash);
        debugHex("Right child hash: ", dirNode->right->hash);
        
        dirNode->hash = hasher_->calculateHash(combined);
        debugHex("New root hash: ", dirNode->hash);
        
        root_ = std::move(dirNode);
        return true;
    }

    auto* existing = findNode(path);
    if (existing) {
        debug("Updating existing node at path: " + path);
        existing->hash = node->hash;
        existing->metadata = node->metadata;
        debugHex("New node hash: ", node->hash);
        updateParentHashes(path);
        return true;
    }

    // Handle root-level files
    if (path.find('/') == path.length() - 1 || path.find('/') == std::string::npos) {
        debug("Adding root-level file");
        if (root_->left && !root_->right) {
            debug("Adding as right child of root");
            root_->right = std::move(node);
            pathMap_[path] = root_->right.get();
            
            std::vector<uint8_t> combined;
            combined.insert(combined.end(), root_->left->hash.begin(), root_->left->hash.end());
            combined.insert(combined.end(), root_->right->hash.begin(), root_->right->hash.end());
            debugHex("Combined child hashes: ", combined);
            
            root_->hash = hasher_->calculateHash(combined);
            debugHex("New root hash: ", root_->hash);
            return true;
        }
    }

    debug("Processing file in directory structure");
    std::vector<std::string> components = splitPath(path);
    Node* current = root_.get();
    std::string currentPath;

    for (size_t i = 0; i < components.size() - 1; ++i) {
        currentPath += "/" + components[i];
        auto* next = findNode(currentPath);
        
        if (!next) {
            debug("Creating new directory: " + currentPath);
            NodeMetadata dirMeta;
            dirMeta.path = currentPath;
            dirMeta.timestamp = std::time(nullptr);
            dirMeta.isDirectory = true;
            
            auto dirNode = createNode({}, dirMeta);
            if (!current->left) {
                debug("Adding directory as left child");
                current->left = std::move(dirNode);
                current->isLeaf = false;
                current = current->left.get();
            } else if (!current->right) {
                debug("Adding directory as right child");
                current->right = std::move(dirNode);
                current->isLeaf = false;
                current = current->right.get();
            } else {
                debug("No space for new directory node");
                return false;
            }
            pathMap_[currentPath] = current;
        } else {
            current = next;
        }
    }

    // Add file node
    debug("Adding file node to directory: " + path);
    bool success = false;
    if (!current->left) {
        debug("Adding as left child");
        current->left = std::move(node);
        current->isLeaf = false;
        pathMap_[node->metadata.path] = current->left.get();
        success = true;
    } else if (!current->right) {
        debug("Adding as right child");
        current->right = std::move(node);
        current->isLeaf = false;
        pathMap_[node->metadata.path] = current->right.get();
        success = true;
    }

    if (success) {
        debug("Successfully added file, updating parent hashes");
        updateParentHashes(path);
        return true;
    }

    debug("Failed to add file node");
    return false;
}

void MerkleTree::updateParentHashes(const std::string& path) {
    debug("\n=== Updating parent hashes for path: " + path + " ===");
    auto nodes = getPathToRoot(path);
    
    for (auto* node : nodes) {
        if (!node->isLeaf) {
            std::vector<uint8_t> combined;
            if (node->left) {
                debug("Adding left child hash to combined");
                combined.insert(combined.end(),
                              node->left->hash.begin(),
                              node->left->hash.end());
                debugHex("Left child hash: ", node->left->hash);
            }
            if (node->right) {
                debug("Adding right child hash to combined");
                combined.insert(combined.end(),
                              node->right->hash.begin(),
                              node->right->hash.end());
                debugHex("Right child hash: ", node->right->hash);
            }
            node->hash = hasher_->calculateHash(combined);
            debug("Calculated new hash for path: " + node->metadata.path);
            debugHex("New hash: ", node->hash);
        }
    }
}

std::vector<MerkleTree::Node*> MerkleTree::getPathToRoot(const std::string& path) const {
    std::vector<Node*> nodes;
    debug("Getting path to root from: " + path);
    
    auto* node = findNode(path);
    while (node) {
        nodes.push_back(node);
        debug("Added node: " + node->metadata.path);
        debugHex("Node hash: ", node->hash);
        
        if (node == root_.get()) {
            debug("Reached root node");
            break;
        }
        
        auto currentPath = node->metadata.path;
        auto pos = currentPath.find_last_of('/');
        if (pos == std::string::npos) {
            debug("No more parent nodes found");
            break;
        }
        
        auto parentPath = currentPath.substr(0, pos);
        if (parentPath.empty()) parentPath = "/";
        
        node = findNode(parentPath);
        if (!node) {
            debug("Parent not found");
            break;
        }
    }
    
    debug("Found " + std::to_string(nodes.size()) + " nodes in path to root");
    return nodes;
}

MerkleTree::Node* MerkleTree::findNode(const std::string& path) const {
    auto it = pathMap_.find(path);
    if (it != pathMap_.end()) {
        debug("Found node at path: " + path);
        return it->second;
    }
    debug("Node not found at path: " + path);
    return nullptr;
}

std::vector<std::string> MerkleTree::splitPath(const std::string& path) const {
    std::vector<std::string> components;
    std::string remaining = path;
    
    if (!remaining.empty() && remaining[0] == '/') {
        remaining = remaining.substr(1);
    }
    
    size_t pos = 0;
    while ((pos = remaining.find('/')) != std::string::npos) {
        if (pos > 0) {
            components.push_back(remaining.substr(0, pos));
        }
        remaining = remaining.substr(pos + 1);
    }
    if (!remaining.empty()) {
        components.push_back(remaining);
    }

    std::stringstream ss;
    ss << "Split path " << path << " into " << components.size() << " components";
    debug(ss.str());
    return components;
}

std::vector<std::vector<uint8_t>> MerkleTree::getProof(
        const std::string& path) const {
    debug("\n=== Getting proof for path: " + path + " ===");
    std::vector<std::vector<uint8_t>> proof;
    
    auto* node = findNode(path);
    if (!node || !root_) {
        debug("Node or root not found");
        return proof;
    }

    debug("Found node at path: " + node->metadata.path);
    debugHex("Node hash: ", node->hash);

    if (node == root_.get()) {
        debug("Node is root, no proof needed");
        return proof;
    }

    if (root_->left.get() == node && root_->right) {
        debug("Node is left child of root, using right sibling");
        proof.push_back(root_->right->hash);
        debugHex("Added right sibling hash: ", root_->right->hash);
        return proof;
    } else if (root_->right.get() == node && root_->left) {
        debug("Node is right child of root, using left sibling");
        proof.push_back(root_->left->hash);
        debugHex("Added left sibling hash: ", root_->left->hash);
        return proof;
    }

    Node* current = node;
    std::string currentPath = path;

    while (current != root_.get()) {
        auto pos = currentPath.find_last_of('/');
        if (pos == std::string::npos) break;
        
        auto parentPath = currentPath.substr(0, pos);
        if (parentPath.empty()) parentPath = "/";
        
        auto* parent = findNode(parentPath);
        if (!parent) {
            debug("Parent not found at: " + parentPath);
            break;
        }

        debug("Found parent: " + parent->metadata.path);

        if (parent->left.get() == current && parent->right) {
            debug("Adding right sibling to proof");
            proof.push_back(parent->right->hash);
            debugHex("Added right sibling hash: ", parent->right->hash);
        } else if (parent->right.get() == current && parent->left) {
            debug("Adding left sibling to proof");
            proof.push_back(parent->left->hash);
            debugHex("Added left sibling hash: ", parent->left->hash);
        }

        current = parent;
        currentPath = parentPath;
    }

    debug("Proof generated with " + std::to_string(proof.size()) + " elements");
    return proof;
}

bool MerkleTree::verifyProof(const std::string& path,
                           const std::vector<uint8_t>& data,
                           const std::vector<std::vector<uint8_t>>& proof) {
    debug("\n=== Verifying proof for path: " + path + " ===");
    
    auto currentHash = hasher_->calculateHash(data);
    debugHex("Initial data hash: ", currentHash);

    auto* node = findNode(path);
    if (!node) {
        debug("Node not found");
        return false;
    }

    debugHex("Stored node hash: ", node->hash);

    if (node == root_.get()) {
        debug("Node is root, comparing hashes directly");
        bool result = currentHash == root_->hash;
        debug("Verification result: " + std::to_string(result));
        return result;
    }

    if (root_->left.get() == node || root_->right.get() == node) {
        debug("Direct child of root");
        if (proof.size() != 1) {
            debug("Invalid proof size: " + std::to_string(proof.size()));
            return false;
        }
        
        std::vector<uint8_t> combined;
        if (root_->left.get() == node) {
            debug("Node is left child, combining with right sibling");
            combined.insert(combined.end(), currentHash.begin(), currentHash.end());
            combined.insert(combined.end(), proof[0].begin(), proof[0].end());
        } else {
            debug("Node is right child, combining with left sibling");
            combined.insert(combined.end(), proof[0].begin(), proof[0].end());
            combined.insert(combined.end(), currentHash.begin(), currentHash.end());
        }

        debugHex("Combined hash input: ", combined);
        auto finalHash = hasher_->calculateHash(combined);
        debugHex("Final computed hash: ", finalHash);
        debugHex("Root hash: ", root_->hash);
        
        bool result = finalHash == root_->hash;
        debug("Verification result: " + std::to_string(result));
        return result;
    }

    debug("Verifying nested file");
    Node* current = node;
    std::string currentPath = path;
    size_t proofIndex = 0;

    while (proofIndex < proof.size()) {
        auto pos = currentPath.find_last_of('/');
        if (pos == std::string::npos) break;
        
        currentPath = currentPath.substr(0, pos);
        if (currentPath.empty()) currentPath = "/";
        
        auto* parent = findNode(currentPath);
        if (!parent) {
            debug("Parent not found at: " + currentPath);
            break;
        }

        std::vector<uint8_t> combined;
        if (parent->left.get() == current) {
            debug("Combining as left child with right sibling");
            combined.insert(combined.end(), currentHash.begin(), currentHash.end());
            combined.insert(combined.end(), proof[proofIndex].begin(), proof[proofIndex].end());
        } else {
            debug("Combining as right child with left sibling");
            combined.insert(combined.end(), proof[proofIndex].begin(), proof[proofIndex].end());
            combined.insert(combined.end(), currentHash.begin(), currentHash.end());
        }
        
        debugHex("Combined hash input: ", combined);
        currentHash = hasher_->calculateHash(combined);
        debugHex("New intermediate hash: ", currentHash);
        
        current = parent;
        proofIndex++;
    }

    bool result = currentHash == getRootHash();
    debug("Final verification result: " + std::to_string(result));
    if (!result) {
        debugHex("Expected root hash: ", getRootHash());
        debugHex("Computed final hash: ", currentHash);
    }
    return result;
}

std::vector<uint8_t> MerkleTree::getRootHash() const {
    if (!root_) {
        debug("No root exists, returning empty hash");
        return std::vector<uint8_t>{};
    }
    debug("Getting root hash");
    debugHex("Root hash: ", root_->hash);
    return root_->hash;
}

} // namespace encrypto::core
