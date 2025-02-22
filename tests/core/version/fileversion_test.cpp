#include "core/version/fileversion.hpp"
#include <gtest/gtest.h>
#include <vector>
#include <string>
#include "test_config.h"
#include <filesystem>

using namespace encrypto::core;

class FileVersionTest : public ::testing::Test {
protected:
    std::vector<uint8_t> stringToBytes(const std::string& str) {
        return std::vector<uint8_t>(str.begin(), str.end());
    }

    void SetUp() override {
        testKey_.resize(32);  // 256-bit test key
        std::fill_n(testKey_.data(), testKey_.size(), 0x42);
        testOutputPath = std::filesystem::path(TEST_OUTPUT_DIR) / "fileversion";
        std::filesystem::create_directories(testOutputPath);
    }

    void TearDown() override {
        std::filesystem::remove_all(testOutputPath);
    }

    SecureMemory::SecureVector<uint8_t> testKey_;
    std::filesystem::path testOutputPath;
};

TEST_F(FileVersionTest, CreateEmptyVersion) {
    FileVersion version;
    EXPECT_EQ(version.currentVersion(), 0);
}

TEST_F(FileVersionTest, CreateInitialVersion) {
    std::string content = "initial content";
    FileVersion version(stringToBytes(content), "author", "initial version");
    
    EXPECT_EQ(version.currentVersion(), 0);
    
    auto info = version.getVersionInfo(0);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->version, 0);
    EXPECT_EQ(info->author, "author");
    EXPECT_EQ(info->description, "initial version");
}

TEST_F(FileVersionTest, CreateMultipleVersions) {
    std::string content1 = "initial content";
    FileVersion version(stringToBytes(content1), "author1", "version 1");
    
    std::string content2 = "modified content";
    auto v2 = version.createVersion(stringToBytes(content2), "author2", "version 2");
    ASSERT_TRUE(v2.has_value());
    EXPECT_EQ(*v2, 1);
    
    auto info1 = version.getVersionInfo(0);
    auto info2 = version.getVersionInfo(1);
    
    ASSERT_TRUE(info1.has_value());
    ASSERT_TRUE(info2.has_value());
    
    EXPECT_EQ(info1->author, "author1");
    EXPECT_EQ(info2->author, "author2");
    
    // Verify content retrieval
    auto content1_ver = version.getContent(0);
    auto content2_ver = version.getContent(1);
    
    ASSERT_TRUE(content1_ver.has_value());
    ASSERT_TRUE(content2_ver.has_value());
    
    EXPECT_EQ(std::string(content1_ver->begin(), content1_ver->end()), content1);
    EXPECT_EQ(std::string(content2_ver->begin(), content2_ver->end()), content2);
}

TEST_F(FileVersionTest, RollbackVersion) {
    std::string content1 = "version 1";
    std::string content2 = "version 2";
    std::string content3 = "version 3";
    
    FileVersion version(stringToBytes(content1), "author", "v1");
    version.createVersion(stringToBytes(content2), "author", "v2");
    version.createVersion(stringToBytes(content3), "author", "v3");
    
    EXPECT_EQ(version.currentVersion(), 2);
    
    // Rollback to version 1
    EXPECT_TRUE(version.rollback(1));
    EXPECT_EQ(version.currentVersion(), 1);
    
    // Version 2 content should no longer be accessible
    auto content = version.getContent(2);
    EXPECT_FALSE(content.has_value());
    
    // Version 1 content should still be accessible
    content = version.getContent(1);
    ASSERT_TRUE(content.has_value());
    EXPECT_EQ(std::string(content->begin(), content->end()), content2);
}

TEST_F(FileVersionTest, DeltaCompression) {
    std::string baseContent = "This is a base document with some content.";
    std::string modifiedContent = "This is a base document with modified content.";
    
    FileVersion version(stringToBytes(baseContent), "author", "base");
    version.createVersion(stringToBytes(modifiedContent), "author", "modified");
    
    // Get delta between versions
    auto delta = version.getDelta(0, 1);
    ASSERT_TRUE(delta.has_value());
    
    // Delta should be smaller than full content
    EXPECT_LT(delta->size(), modifiedContent.size());
}

TEST_F(FileVersionTest, SaveAndLoad) {
    std::string content = "test content";
    FileVersion version(stringToBytes(content), "author", "initial");
    version.createVersion(stringToBytes(content + " modified"), "author", "update");
    
    // Save to file using the test output path
    auto testFile = testOutputPath / "test_version.dat";
    EXPECT_TRUE(version.save(testFile.string(), testKey_));
    
    // Load in new instance
    FileVersion loadedVersion;
    EXPECT_TRUE(loadedVersion.load(testFile.string(), testKey_));
    
    // Verify version info matches
    auto originalInfo = version.getVersionInfo(1);
    auto loadedInfo = loadedVersion.getVersionInfo(1);
    
    ASSERT_TRUE(originalInfo.has_value());
    ASSERT_TRUE(loadedInfo.has_value());
    EXPECT_EQ(originalInfo->author, loadedInfo->author);
    EXPECT_EQ(originalInfo->description, loadedInfo->description);
    
    // Verify content matches
    auto originalContent = version.getContent(1);
    auto loadedContent = loadedVersion.getContent(1);
    
    ASSERT_TRUE(originalContent.has_value());
    ASSERT_TRUE(loadedContent.has_value());
    EXPECT_EQ(*originalContent, *loadedContent);
}

TEST_F(FileVersionTest, InvalidOperations) {
    FileVersion version;
    
    // Try to get non-existent version
    EXPECT_FALSE(version.getVersionInfo(0).has_value());
    EXPECT_FALSE(version.getContent(0).has_value());
    
    // Try to get delta with invalid versions
    EXPECT_FALSE(version.getDelta(0, 1).has_value());
    
    // Try to rollback to non-existent version
    EXPECT_FALSE(version.rollback(1));
    
    // Try to load with wrong key
    SecureMemory::SecureVector<uint8_t> wrongKey(32);
    std::fill_n(wrongKey.data(), wrongKey.size(), 0xFF);
    
    auto invalidFile = testOutputPath / "test_invalid.dat";
    FileVersion testVersion(stringToBytes("test"), "author", "test");
    EXPECT_TRUE(testVersion.save(invalidFile.string(), testKey_));
    EXPECT_FALSE(testVersion.load(invalidFile.string(), wrongKey));
}

TEST_F(FileVersionTest, LargeFileVersioning) {
    // Create large content with repeated pattern
    std::string pattern = "This is a test pattern that will be repeated. ";
    std::string largeContent;
    for (int i = 0; i < 1000; ++i) {
        largeContent += pattern;
    }
    
    // Create initial version
    FileVersion version(stringToBytes(largeContent), "author", "large file");
    
    // Modify small portion in the middle
    std::string modifiedContent = largeContent;
    modifiedContent.replace(modifiedContent.length() / 2, 20, "MODIFIED SECTION");
    
    // Create new version
    auto v2 = version.createVersion(stringToBytes(modifiedContent), "author", "small change");
    ASSERT_TRUE(v2.has_value());
    
    // Delta should be much smaller than full content
    auto delta = version.getDelta(0, 1);
    ASSERT_TRUE(delta.has_value());
    EXPECT_LT(delta->size(), largeContent.length() / 10);  // Expect < 10% of original size
}
