#include <gtest/gtest.h>
#include "core/keyrotation.hpp"
#include "core/encryptionengine.hpp"
#include <thread>
#include <chrono>

using namespace encrypto::core;
using namespace std::chrono_literals;

class KeyRotationTest : public ::testing::Test {
protected:
    void SetUp() override {
        rotation = std::make_unique<KeyRotation>(KeyRotation::Policy::Manual);
    }

    void TearDown() override {
        rotation.reset();
    }

    std::unique_ptr<KeyRotation> rotation;

    SecureMemory::SecureVector<uint8_t> generateTestKey() {
        SecureMemory::SecureVector<uint8_t> key(32);
        EncryptionEngine engine;
        EXPECT_TRUE(engine.generateRandomBytes({key.data(), key.size()}));
        return key;
    }
};

TEST_F(KeyRotationTest, InitialStateHasNoKey) {
    EXPECT_FALSE(rotation->getCurrentKey().has_value());
}

TEST_F(KeyRotationTest, AddKeyVersion) {
    auto key = generateTestKey();
    auto version = rotation->addKeyVersion(key);
    EXPECT_GT(version, 0);

    auto retrieved = rotation->getKeyVersion(version);
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->version, version);
    EXPECT_TRUE(retrieved->active);
}

TEST_F(KeyRotationTest, RotateKey) {
    // Add initial key
    auto key1 = generateTestKey();
    auto v1 = rotation->addKeyVersion(key1);
    ASSERT_GT(v1, 0);

    // Rotate to new key
    auto key2 = generateTestKey();
    auto v2 = rotation->rotateKey(key2);
    ASSERT_GT(v2, v1);

    // Check old key is inactive
    auto old_key = rotation->getKeyVersion(v1);
    ASSERT_TRUE(old_key.has_value());
    EXPECT_FALSE(old_key->active);

    // Check new key is active
    auto new_key = rotation->getKeyVersion(v2);
    ASSERT_TRUE(new_key.has_value());
    EXPECT_TRUE(new_key->active);

    auto current = rotation->getCurrentKey();
    ASSERT_TRUE(current.has_value());
    EXPECT_EQ(current->version, v2);
}

TEST_F(KeyRotationTest, AutomaticRotation) {
    // Set short interval for testing
    std::chrono::hours short_interval(1);
    rotation->setPolicy(KeyRotation::Policy::Scheduled, short_interval);
    
    // Add key that expires immediately
    auto key = generateTestKey();
    auto v1 = rotation->addKeyVersion(key);
    ASSERT_GT(v1, 0);

    // Should need rotation immediately
    EXPECT_TRUE(rotation->needsRotation());
}

TEST_F(KeyRotationTest, CompromisedKeyHandling) {
    auto key = generateTestKey();
    auto version = rotation->addKeyVersion(key);
    ASSERT_GT(version, 0);

    rotation->markCompromised(version);
    auto meta = rotation->getKeyMetadata(version);
    ASSERT_TRUE(meta.has_value());
    EXPECT_TRUE(meta->compromised);

    auto key_ver = rotation->getKeyVersion(version);
    ASSERT_TRUE(key_ver.has_value());
    EXPECT_FALSE(key_ver->active);

    // Compromised key should trigger rotation need
    rotation->setPolicy(KeyRotation::Policy::Scheduled, 24h);
    EXPECT_TRUE(rotation->needsRotation());
}

TEST_F(KeyRotationTest, UsageTracking) {
    auto key = generateTestKey();
    auto version = rotation->addKeyVersion(key);
    ASSERT_GT(version, 0);

    // Track multiple uses
    const int uses = 5;
    for (int i = 0; i < uses; i++) {
        rotation->updateUsage(version);
    }

    auto meta = rotation->getKeyMetadata(version);
    ASSERT_TRUE(meta.has_value());
    EXPECT_EQ(meta->usageCount, uses);
    EXPECT_GE(meta->lastUsed, std::chrono::system_clock::now() - 1s);
}

TEST_F(KeyRotationTest, AdaptiveRotation) {
    rotation->setPolicy(KeyRotation::Policy::Adaptive, 24h);
    auto key = generateTestKey();
    auto version = rotation->addKeyVersion(key);
    ASSERT_GT(version, 0);

    // Simulate heavy usage
    for (int i = 0; i < 1000001; i++) {
        rotation->updateUsage(version);
    }

    EXPECT_TRUE(rotation->needsRotation());
}

TEST_F(KeyRotationTest, ExpirationAndCleanup) {
    auto now = std::chrono::system_clock::now();
    auto key = generateTestKey();

    // Add key that expires in 1ms
    auto version = rotation->addKeyVersion(key, now + 1ms);
    ASSERT_GT(version, 0);

    // Key should still exist
    ASSERT_TRUE(rotation->getKeyVersion(version).has_value());

    // Wait for expiration
    std::this_thread::sleep_for(2ms);
    
    // First verify that expired key is detected
    EXPECT_TRUE(rotation->needsRotation());

    // Then cleanup expired keys
    rotation->cleanupExpiredKeys();

    // Key should no longer exist
    EXPECT_FALSE(rotation->getKeyVersion(version).has_value());
}

TEST_F(KeyRotationTest, ThreadSafety) {
    auto key = generateTestKey();
    auto version = rotation->addKeyVersion(key);
    ASSERT_GT(version, 0);

    constexpr int NUM_THREADS = 10;
    constexpr int OPS_PER_THREAD = 100;
    std::vector<std::thread> threads;

    for (int i = 0; i < NUM_THREADS; i++) {
        threads.emplace_back([&]() {
            for (int j = 0; j < OPS_PER_THREAD; j++) {
                rotation->updateUsage(version);
                rotation->getKeyVersion(version);
                rotation->needsRotation();
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    auto meta = rotation->getKeyMetadata(version);
    ASSERT_TRUE(meta.has_value());
    EXPECT_EQ(meta->usageCount, NUM_THREADS * OPS_PER_THREAD);
}
