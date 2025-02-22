#include "core/version/versionstore.hpp"
#include <gtest/gtest.h>
#include <filesystem>
#include <memory>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include "test_config.h"

using namespace encrypto::core;
namespace fs = std::filesystem;

class VersionStoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test key
        key_.resize(32);  // 256-bit test key
        std::fill_n(key_.data(), key_.size(), 0x42);

        testOutputPath = std::filesystem::path(TEST_OUTPUT_DIR) / "versionstore";
        std::filesystem::create_directories(testOutputPath);
        
        // Create version store with both path and key
        store_ = std::make_unique<VersionStore>(testOutputPath.string(), key_);
    }

    void TearDown() override {
        store_.reset();
        std::filesystem::remove_all(testOutputPath);
    }

    std::vector<uint8_t> stringToBytes(const std::string& str) {
        return std::vector<uint8_t>(str.begin(), str.end());
    }

    std::unique_ptr<VersionStore> store_;
    std::filesystem::path testOutputPath;
    SecureMemory::SecureVector<uint8_t> key_;
};

TEST_F(VersionStoreTest, AddFile) {
    std::string testFilePath = (testOutputPath / "test.txt").string();
    std::string content = "test content";
    
    // Create the test file first
    std::ofstream testFile(testFilePath);
    testFile << content;
    testFile.close();
    
    EXPECT_TRUE(store_->addFile(testFilePath, "author", "initial version"));
    EXPECT_TRUE(store_->isVersioned(testFilePath));
}

TEST_F(VersionStoreTest, CreateAndRetrieveVersions) {
    std::string path = (testOutputPath / "test.txt").string();
    
    // Create test file
    std::ofstream testFile(path);
    testFile << "Initial content";
    testFile.close();
    std::string content1 = "version 1";
    std::string content2 = "version 2";

    // Add initial version
    EXPECT_TRUE(store_->addFile(path, "author1", "initial"));
    
    // Create second version
    auto v2 = store_->createVersion(path, "author2", "update");
    ASSERT_TRUE(v2.has_value());
    
    // Get version info
    auto info1 = store_->getVersionInfo(path, 0);
    auto info2 = store_->getVersionInfo(path, *v2);
    
    ASSERT_TRUE(info1.has_value());
    ASSERT_TRUE(info2.has_value());
    
    EXPECT_EQ(info1->author, "author1");
    EXPECT_EQ(info2->author, "author2");
}

TEST_F(VersionStoreTest, GetHistory) {
    std::string path = (testOutputPath / "test.txt").string();
    
    // Create test file
    std::ofstream testFile(path);
    testFile << "Initial content";
    testFile.close();
    
    // Create multiple versions
    EXPECT_TRUE(store_->addFile(path, "author1", "v1"));
    store_->createVersion(path, "author2", "v2");
    store_->createVersion(path, "author3", "v3");
    
    auto history = store_->getHistory(path);
    EXPECT_EQ(history.size(), 3);
    
    EXPECT_EQ(history[0].author, "author1");
    EXPECT_EQ(history[1].author, "author2");
    EXPECT_EQ(history[2].author, "author3");
}

TEST_F(VersionStoreTest, Rollback) {
    std::string path = (testOutputPath / "test.txt").string();
    
    // Create test file
    std::ofstream testFile(path);
    testFile << "Initial content";
    testFile.close();
    
    EXPECT_TRUE(store_->addFile(path, "author1", "v1"));
    auto v2 = store_->createVersion(path, "author2", "v2");
    store_->createVersion(path, "author3", "v3");
    
    ASSERT_TRUE(v2.has_value());
    
    // Rollback to version 2
    EXPECT_TRUE(store_->rollback(path, *v2, "author4"));
    
    auto history = store_->getHistory(path);
    EXPECT_EQ(history.size(), 2);  // v3 should be gone
    
    auto latest = store_->getVersionInfo(path);
    ASSERT_TRUE(latest.has_value());
    EXPECT_EQ(latest->author, "author2");
}

TEST_F(VersionStoreTest, PruningPolicy) {
    std::string path = (testOutputPath / "test.txt").string();
    
    // Create test file
    std::ofstream testFile(path);
    testFile << "Initial content";
    testFile.close();
    
    // Create several versions
    EXPECT_TRUE(store_->addFile(path, "author", "v1"));
    for (int i = 2; i <= 10; ++i) {
        store_->createVersion(path, "author", 
            "v" + std::to_string(i));
    }
    
    // Configure pruning policy
    VersionStore::PruningPolicy policy;
    policy.maxVersions = 5;
    policy.minVersions = 3;
    policy.keepFirstVersion = true;
    
    // Apply pruning
    size_t pruned = store_->pruneVersions(path, policy);
    EXPECT_GT(pruned, 0);
    
    auto history = store_->getHistory(path);
    EXPECT_LE(history.size(), policy.maxVersions);
    EXPECT_GE(history.size(), policy.minVersions);
    
    // First version should still exist
    auto firstVersion = store_->getVersionInfo(path, 0);
    ASSERT_TRUE(firstVersion.has_value());
}

TEST_F(VersionStoreTest, TimeBasedPruning) {
    std::string path = (testOutputPath / "test.txt").string();
    
    // Create test file
    std::ofstream testFile(path);
    testFile << "Initial content";
    testFile.close();
    
    // Create several versions
    EXPECT_TRUE(store_->addFile(path, "author", "v1"));
    for (int i = 2; i <= 5; ++i) {
        store_->createVersion(path, "author", 
            "v" + std::to_string(i));
        
        // Simulate time passing (very short delay)
        std::this_thread::sleep_for(std::chrono::microseconds(1));
    }
    
    // Configure pruning policy with short retention period
    VersionStore::PruningPolicy policy;
    policy.retentionPeriod = std::chrono::hours(0);  // Keep only recent versions
    policy.minVersions = 2;  // But keep at least 2 versions
    
    // Apply pruning
    size_t pruned = store_->pruneVersions(path, policy);
    EXPECT_GT(pruned, 0);
    
    auto history = store_->getHistory(path);
    EXPECT_GE(history.size(), policy.minVersions);
}

TEST_F(VersionStoreTest, SaveAndRestore) {
    std::string path1 = (testOutputPath / "file1.txt").string();
    std::string path2 = (testOutputPath / "file2.txt").string();
    
    // Create test files
    std::ofstream file1(path1);
    file1 << "File 1 content";
    file1.close();
    
    std::ofstream file2(path2);
    file2 << "File 2 content";
    file2.close();
    
    // Create versions for multiple files
    EXPECT_TRUE(store_->addFile(path1, "author1", "f1v1"));
    EXPECT_TRUE(store_->addFile(path2, "author1", "f2v1"));
    
    store_->createVersion(path1, "author2", "f1v2");
    store_->createVersion(path2, "author2", "f2v2");
    
    // Save state
    EXPECT_TRUE(store_->save());
    
    // Create new store instance with the same key
    auto newStore = std::make_unique<VersionStore>(testOutputPath.string(), key_);
    
    // Verify versions were restored
    EXPECT_TRUE(newStore->isVersioned(path1));
    EXPECT_TRUE(newStore->isVersioned(path2));
    
    auto history1 = newStore->getHistory(path1);
    auto history2 = newStore->getHistory(path2);
    
    EXPECT_EQ(history1.size(), 2);
    EXPECT_EQ(history2.size(), 2);
}

TEST_F(VersionStoreTest, InvalidOperations) {
    std::string path = (testOutputPath / "test.txt").string();
    
    // Create test file
    std::ofstream testFile(path);
    testFile << "Initial content";
    testFile.close();
    
    // Try to create version for non-versioned file
    auto version = store_->createVersion(path, "author", "desc");
    EXPECT_FALSE(version.has_value());
    
    // Try to get info for non-existent version
    EXPECT_FALSE(store_->getVersionInfo(path, 0).has_value());
    
    // Try to rollback non-existent file
    EXPECT_FALSE(store_->rollback(path, 0, "author"));
    
    // Add file and try invalid version operations
    EXPECT_TRUE(store_->addFile(path, "author", "initial"));
    EXPECT_FALSE(store_->getVersionInfo(path, 999).has_value());  // Non-existent version
    EXPECT_FALSE(store_->rollback(path, 999, "author"));  // Invalid version

    // Create new store instance
    auto newStore = std::make_unique<VersionStore>(testOutputPath.string(), key_);
}
