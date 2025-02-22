#include "core/integrity/merkletree.hpp"
#include "core/fileintegrity.hpp"
#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <string>
#include <iomanip>
#include <fstream>

using namespace encrypto::core;

class MerkleTreeTest : public ::testing::Test {
protected:
    void SetUp() override {
        hasher_ = std::make_shared<FileIntegrity>();
        tree_ = std::make_unique<MerkleTree>(hasher_);
        tree_->enableDebugOutput();
        logFile_.open("merkle_test.log", std::ios::out | std::ios::trunc);
        logFile_ << "=== Test Started ===\n" << std::flush;
    }

    void TearDown() override {
        logFile_ << "\n=== Final Debug Output ===\n" << tree_->getDebugOutput() 
                << "\n=== Test Finished ===\n" << std::flush;
        logFile_.close();
        
        // Display the log file contents
        std::ifstream readLog("merkle_test.log");
        if (readLog) {
            std::cout << "\n=== Test Log ===\n" << readLog.rdbuf() << std::endl;
        }
    }

    void LogDebug(const std::string& label) {
        auto output = tree_->getDebugOutput();
        logFile_ << "\n=== " << label << " ===\n" << output << std::flush;
        std::cout << "\n=== " << label << " ===\n" << output << std::flush;
        tree_->clearDebugOutput();
    }

    std::shared_ptr<FileIntegrity> hasher_;
    std::unique_ptr<MerkleTree> tree_;
    std::ofstream logFile_;

    std::vector<uint8_t> stringToBytes(const std::string& str) {
        return std::vector<uint8_t>(str.begin(), str.end());
    }

    void dumpHash(const std::vector<uint8_t>& hash, const std::string& label = "Hash") {
        std::stringstream ss;
        ss << label << "(" << hash.size() << "): ";
        for (auto b : hash) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }
        ss << std::dec << std::endl;
        logFile_ << ss.str() << std::flush;
        std::cout << ss.str() << std::flush;
    }
};

TEST_F(MerkleTreeTest, ProofGenerationAndVerification) {
    logFile_ << "\n=== Starting ProofGenerationAndVerification test ===\n" << std::flush;
    
    // Test Root Level File
    {
        logFile_ << "\n-- Testing root level file --\n" << std::flush;
        std::string rootData = "root file data";
        auto rootBytes = stringToBytes(rootData);
        
        logFile_ << "Adding root file with data size: " << rootBytes.size() << std::endl << std::flush;
        ASSERT_TRUE(tree_->updateNode("/root.txt", rootBytes)) 
            << "Failed to add root file";
        LogDebug("After adding root file");
        
        auto rootHash = tree_->getRootHash();
        dumpHash(rootHash, "Root");
        
        auto rootProof = tree_->getProof("/root.txt");
        logFile_ << "Root proof elements: " << rootProof.size() << "\n" << std::flush;
        LogDebug("After getting root proof");
        
        ASSERT_TRUE(tree_->verifyProof("/root.txt", rootBytes, rootProof))
            << "Root file verification failed";
        LogDebug("After root verification");
    }

    // Test Second Level File
    {
        logFile_ << "\n-- Testing second level file --\n" << std::flush;
        std::string secondData = "second file data";
        auto secondBytes = stringToBytes(secondData);
        
        logFile_ << "Adding second file with data size: " << secondBytes.size() << std::endl << std::flush;
        ASSERT_TRUE(tree_->updateNode("/second.txt", secondBytes))
            << "Failed to add second file";
        LogDebug("After adding second file");
        
        auto secondProof = tree_->getProof("/second.txt");
        logFile_ << "Second file proof elements: " << secondProof.size() << "\n" << std::flush;
        
        if (!secondProof.empty()) {
            dumpHash(secondProof[0], "First proof element");
        }
        LogDebug("After getting second proof");
        
        ASSERT_TRUE(tree_->verifyProof("/second.txt", secondBytes, secondProof))
            << "Second file verification failed";
        LogDebug("After second verification");
        
        // Test with wrong data
        auto wrongBytes = stringToBytes("wrong");
        ASSERT_FALSE(tree_->verifyProof("/second.txt", wrongBytes, secondProof))
            << "Verification with wrong data should fail";
        LogDebug("After wrong data verification");
    }
}
