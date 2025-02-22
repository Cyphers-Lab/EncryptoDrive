#include "versionstore.hpp"
#include "../encryptionengine.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <stdexcept>

namespace fs = std::filesystem;

namespace encrypto::core {

VersionStore::VersionStore(
    const std::string& storageDir,
    const SecureMemory::SecureVector<uint8_t>& key)
    : storageDir_(storageDir),
      key_(key) {
    
    // Create storage directory if it doesn't exist
    fs::create_directories(storageDir_);

    // Load existing version info
    loadVersions();
}

bool VersionStore::isVersioned(const std::string& path) const {
    fs::path absPath = fs::absolute(path);
    return versions_.find(absPath.string()) != versions_.end();
}

bool VersionStore::addFile(const std::string& path,
                         const std::string& author,
                         const std::string& description) {
    // Convert to absolute path
    fs::path absPath = fs::absolute(path);
    
    // Check if file exists and not already versioned
    if (!fs::exists(absPath) || isVersioned(absPath.string())) {
        return false;
    }

    // Read file content
    auto content = readFile(path);
    if (content.empty()) {
        return false;
    }

    // Create new version
    auto version = std::make_unique<FileVersion>(content, author, description);
    if (!version) {
        return false;
    }

    // Save version file
    auto verPath = getVersionPath(path);
    if (!version->save(verPath.string(), key_)) {
        return false;
    }

    // Add to version map using normalized path
    versions_[absPath.string()] = std::move(version);
    return true;
}

std::optional<size_t> VersionStore::createVersion(
    const std::string& path,
    const std::string& author,
    const std::string& description) {
    
    fs::path absPath = fs::absolute(path);
    
    // Check if file exists and is versioned
    if (!fs::exists(path) || !isVersioned(absPath.string())) {
        return std::nullopt;
    }

    // Read current file content
    auto content = readFile(path);
    if (content.empty()) {
        return std::nullopt;
    }

    // Get version object
    auto it = versions_.find(absPath.string());
    if (it == versions_.end() || !it->second) {
        return std::nullopt;
    }

    // Create new version
    auto result = it->second->createVersion(content, author, description);
    if (!result) {
        return std::nullopt;
    }

    // Save updated version file
    if (!it->second->save(getVersionPath(absPath.string()).string(), key_)) {
        return std::nullopt;
    }

    return static_cast<size_t>(*result); // Convert uint32_t to size_t
}

std::optional<FileVersion::VersionInfo> VersionStore::getVersionInfo(
    const std::string& path,
    std::optional<size_t> version) const {
    
    fs::path absPath = fs::absolute(path);
    auto it = versions_.find(absPath.string());
    if (it == versions_.end()) {
        return std::nullopt;
    }

    size_t ver = version.value_or(it->second->currentVersion());
    return it->second->getVersionInfo(ver);
}

std::optional<std::vector<uint8_t>> VersionStore::getContent(
    const std::string& path,
    size_t version) const {
    
    fs::path absPath = fs::absolute(path);
    auto it = versions_.find(absPath.string());
    if (it == versions_.end()) {
        return std::nullopt;
    }

    return it->second->getContent(version);
}

bool VersionStore::rollback(
    const std::string& path,
    size_t version,
    const std::string& /* author */) {  // Unused parameter marked
    
    fs::path absPath = fs::absolute(path);
    auto it = versions_.find(absPath.string());
    if (it == versions_.end()) {
        return false;
    }

    // Get version content
    auto content = it->second->getContent(version);
    if (!content) {
        return false;
    }

    // Write to file
    if (!writeFile(absPath.string(), *content)) {
        return false;
    }

    // Truncate history to this version
    if (!it->second->rollback(static_cast<uint32_t>(version))) {
        return false;
    }

    // Save the updated version file
    if (!it->second->save(getVersionPath(absPath.string()).string(), key_)) {
        return false;
    }

    return true;
}

size_t VersionStore::pruneVersions(
    const std::string& path,
    const PruningPolicy& policy) {
    
    fs::path absPath = fs::absolute(path);
    auto it = versions_.find(absPath.string());
    if (it == versions_.end()) {
        return 0;
    }

    auto& version = it->second;
    size_t originalCount = version->currentVersion() + 1;
    
    // Always keep at least minVersions
    if (originalCount <= policy.minVersions) {
        return 0;
    }

    std::vector<size_t> versionsToKeep;
    auto now = std::chrono::system_clock::now();

    // Process each version
    for (size_t i = 0; i < originalCount; ++i) {
        auto info = version->getVersionInfo(i);
        if (!info) continue;

        bool keep = false;

        // Keep first version if policy requires
        if (policy.keepFirstVersion && i == 0) {
            keep = true;
        }
        
        // Keep versions within retention period
        auto timestamp = std::chrono::system_clock::from_time_t(info->timestamp);
        auto age = now - timestamp;
        if (age <= policy.retentionPeriod) {
            keep = true;
        }

        if (keep) {
            versionsToKeep.push_back(i);
        }
    }

    // Ensure minimum versions kept
    while (versionsToKeep.size() < policy.minVersions && 
           versionsToKeep.size() < originalCount) {
        for (size_t i = 0; i < originalCount; ++i) {
            if (std::find(versionsToKeep.begin(), versionsToKeep.end(), i) 
                == versionsToKeep.end()) {
                versionsToKeep.push_back(i);
                break;
            }
        }
    }

    // Trim to maxVersions if needed
    if (versionsToKeep.size() > policy.maxVersions) {
        // Keep newest versions
        std::sort(versionsToKeep.begin(), versionsToKeep.end(), std::greater<>());
        versionsToKeep.resize(policy.maxVersions);
    }

    // Create new version history with kept versions
    auto content = version->getContent(versionsToKeep[0]);
    auto info = version->getVersionInfo(versionsToKeep[0]);
    if (!content || !info) {
        return 0;
    }

    auto newVersion = std::make_unique<FileVersion>(*content, info->author, info->description);
    if (!newVersion) {
        return 0;
    }

    // Add remaining versions
    for (size_t i = 1; i < versionsToKeep.size(); ++i) {
        auto content = version->getContent(versionsToKeep[i]);
        auto info = version->getVersionInfo(versionsToKeep[i]);
        if (!content || !info) continue;

        newVersion->createVersion(*content, info->author, info->description);
    }

    // Save updated history
    if (!newVersion->save(getVersionPath(absPath.string()).string(), key_)) {
        return 0;
    }

    size_t pruned = originalCount - versionsToKeep.size();
    version = std::move(newVersion);
    return pruned;
}

std::vector<FileVersion::VersionInfo> VersionStore::getHistory(
    const std::string& path) const {
    
    std::vector<FileVersion::VersionInfo> history;
    fs::path absPath = fs::absolute(path);
    auto it = versions_.find(absPath.string());
    if (it == versions_.end()) {
        return history;
    }

    for (size_t i = 0; i <= it->second->currentVersion(); ++i) {
        auto info = it->second->getVersionInfo(i);
        if (info) {
            history.push_back(*info);
        }
    }

    return history;
}

bool VersionStore::save() const {
    try {
        for (const auto& [path, version] : versions_) {
            if (!version->save(getVersionPath(path).string(), key_)) {
                return false;
            }
        }
        return true;
    } catch (...) {
        return false;
    }
}

fs::path VersionStore::getVersionPath(const std::string& path) const {
    // Convert to absolute path and get relative to current directory
    fs::path absPath = fs::absolute(path);
    fs::path relPath = fs::relative(absPath, fs::current_path());
    
    // Create version file path in storage directory
    fs::path versionPath = fs::absolute(storageDir_) / relPath;
    versionPath += ".ver";
    
    // Create parent directories if needed
    fs::create_directories(versionPath.parent_path());
    
    return versionPath;
}

bool VersionStore::loadVersion(const std::string& path) {
    auto version = std::make_unique<FileVersion>();
    if (!version->load(path, key_)) {
        return false;
    }

    // Extract original file path from version file path
    fs::path versionPath = path;
    fs::path originalPath = versionPath.parent_path() / 
                           versionPath.stem().string();
    originalPath = fs::absolute(originalPath);
    
    versions_[originalPath.string()] = std::move(version);
    return true;
}

std::vector<uint8_t> VersionStore::readFile(const std::string& path) const {
    try {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file) return {};

        auto size = file.tellg();
        if (size <= 0) return {};

        std::vector<uint8_t> content(static_cast<size_t>(size));
        file.seekg(0);
        file.read(reinterpret_cast<char*>(content.data()), size);
        
        return content;
    } catch (...) {
        return {};
    }
}

bool VersionStore::writeFile(const std::string& path,
                           const std::vector<uint8_t>& data) const {
    try {
        std::ofstream file(path, std::ios::binary);
        if (!file) return false;

        file.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
        return true;
    } catch (...) {
        return false;
    }
}

void VersionStore::loadVersions() {
    try {
        fs::path basePath = fs::absolute(storageDir_);
        for (const auto& entry : fs::recursive_directory_iterator(basePath)) {
            if (entry.path().extension() == ".ver") {
                auto version = std::make_unique<FileVersion>();
                if (version->load(entry.path().string(), key_)) {
                    // Get the relative path from storage dir to the version file
                    fs::path relPath = fs::relative(entry.path(), basePath);
                    relPath.replace_extension("");  // Remove .ver extension
                    
                    // Reconstruct the original absolute path
                    fs::path originalPath = fs::absolute(fs::current_path() / relPath);
                    
                    // Store using absolute path
                    versions_[originalPath.string()] = std::move(version);
                }
            }
        }
    } catch (...) {
        // Handle filesystem errors gracefully
    }
}

} // namespace encrypto::core