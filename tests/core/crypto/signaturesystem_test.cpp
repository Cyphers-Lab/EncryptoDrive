#include "core/crypto/signaturesystem.hpp"
#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <memory>
#include <chrono>

using namespace encrypto::core;

class SignatureSystemTest : public ::testing::Test {
protected:
    void SetUp() override {
        system_ = std::make_unique<SignatureSystem>();
        rootKeyPair_ = system_->generateKeyPair();

        // Debug log key generation
        ASSERT_FALSE(rootKeyPair_.privateKey.empty()) << "Root private key is empty";
        ASSERT_FALSE(rootKeyPair_.publicKey.empty()) << "Root public key is empty";
        ASSERT_EQ(rootKeyPair_.privateKey.size(), 32) << "Incorrect root private key size";
        ASSERT_EQ(rootKeyPair_.publicKey.size(), 32) << "Incorrect root public key size";

        // Create root certificate template
        auto now = std::time(nullptr);
        SignatureSystem::Certificate rootInfo;
        rootInfo.publicKey = rootKeyPair_.publicKey;
        rootInfo.subject = "Root CA";
        rootInfo.issuer = "Root CA";
        rootInfo.notBefore = now;
        rootInfo.notAfter = now + 365 * 24 * 60 * 60;

        // Create initial root certificate
        auto cert = system_->createCertificate(
            rootKeyPair_.publicKey,
            rootInfo.subject,
            rootKeyPair_.privateKey,
            rootInfo);
            
        ASSERT_TRUE(cert.has_value()) << "Failed to create root certificate: "
            << "publicKey.size=" << rootKeyPair_.publicKey.size() 
            << ", privateKey.size=" << rootKeyPair_.privateKey.size();
        
        rootCert_ = *cert;
        
        // Verify root certificate is valid
        std::vector<SignatureSystem::Certificate> trustAnchors = {rootCert_};
        ASSERT_TRUE(system_->verifyCertificateChain(rootCert_, trustAnchors)) 
            << "Failed to verify root certificate";
    }

    std::vector<uint8_t> stringToBytes(const std::string& str) {
        return std::vector<uint8_t>(str.begin(), str.end());
    }

    std::unique_ptr<SignatureSystem> system_;
    SignatureSystem::KeyPair rootKeyPair_;
    SignatureSystem::Certificate rootCert_;
};

TEST_F(SignatureSystemTest, KeyPairGeneration) {
    auto keyPair = system_->generateKeyPair();
    
    EXPECT_FALSE(keyPair.privateKey.empty());
    EXPECT_FALSE(keyPair.publicKey.empty());
    EXPECT_EQ(keyPair.privateKey.size(), 32);  // Ed25519 private key size
    EXPECT_EQ(keyPair.publicKey.size(), 32);   // Ed25519 public key size
}

TEST_F(SignatureSystemTest, SignAndVerify) {
    auto keyPair = system_->generateKeyPair();
    std::string message = "Test message";
    auto data = stringToBytes(message);
    
    // Sign data
    auto signature = system_->sign(data, keyPair.privateKey);
    EXPECT_FALSE(signature.empty());
    
    // Verify signature with correct public key
    EXPECT_TRUE(system_->verify(data, signature, keyPair.publicKey));
    
    // Verify signature fails with wrong public key
    auto wrongKeyPair = system_->generateKeyPair();
    EXPECT_FALSE(system_->verify(data, signature, wrongKeyPair.publicKey));
    
    // Verify signature fails with modified data
    auto modifiedData = stringToBytes("Modified message");
    EXPECT_FALSE(system_->verify(modifiedData, signature, keyPair.publicKey));
}

TEST_F(SignatureSystemTest, CertificateCreation) {
    auto keyPair = system_->generateKeyPair();
    
    auto cert = system_->createCertificate(
        keyPair.publicKey,
        "Test Subject",
        rootKeyPair_.privateKey,
        rootCert_);
    
    ASSERT_TRUE(cert.has_value());
    EXPECT_EQ(cert->subject, "Test Subject");
    EXPECT_EQ(cert->issuer, rootCert_.subject);
}

TEST_F(SignatureSystemTest, CertificateChainVerification) {
    // Test chain verification
    std::cout << "=== Starting CertificateChainVerification test ===" << std::endl;
    
    // Create intermediate CA certificate
    auto intermediateKeyPair = system_->generateKeyPair();
    auto intermediateCert = system_->createCertificate(
        intermediateKeyPair.publicKey,
        "Intermediate CA",
        rootKeyPair_.privateKey,
        rootCert_,
        180);  // 180 days validity
    
    ASSERT_TRUE(intermediateCert.has_value()) << "Failed to create intermediate certificate";
    std::cout << "Created intermediate CA certificate" << std::endl;

    // Create end entity certificate
    auto entityKeyPair = system_->generateKeyPair();
    auto entityCert = system_->createCertificate(
        entityKeyPair.publicKey,
        "End Entity",
        intermediateKeyPair.privateKey,
        *intermediateCert,
        30);  // 30 days validity
    
    ASSERT_TRUE(entityCert.has_value()) << "Failed to create end entity certificate";
    std::cout << "Created end entity certificate" << std::endl;

    // Set up trust anchors
    std::vector<SignatureSystem::Certificate> trustAnchors = {rootCert_};
    std::vector<SignatureSystem::Certificate> intermediates = {*intermediateCert};
    
    // Verify intermediate certificate directly against root
    std::cout << "Verifying intermediate certificate..." << std::endl;
    EXPECT_TRUE(system_->verifyCertificateChain(
        *intermediateCert, trustAnchors))
        << "Failed to verify intermediate certificate";

    // Verify end entity certificate through intermediate chain
    std::cout << "Verifying end entity certificate..." << std::endl;
    EXPECT_TRUE(system_->verifyCertificateChain(
        *entityCert, trustAnchors, intermediates))
        << "Failed to verify end entity certificate with intermediate";
    
    std::cout << "Testing with wrong trust anchors..." << std::endl;
    auto wrongKeyPair = system_->generateKeyPair();
    SignatureSystem::Certificate wrongRootInfo;
    wrongRootInfo.publicKey = wrongKeyPair.publicKey;
    wrongRootInfo.subject = "Wrong CA";
    wrongRootInfo.issuer = "Wrong CA";
    wrongRootInfo.notBefore = std::time(nullptr);
    wrongRootInfo.notAfter = std::time(nullptr) + 3600;
    
    auto wrongCert = system_->createCertificate(
        wrongKeyPair.publicKey,
        "Wrong CA",
        wrongKeyPair.privateKey,
        wrongRootInfo);
    
    ASSERT_TRUE(wrongCert.has_value()) << "Failed to create wrong CA certificate";
    
    std::vector<SignatureSystem::Certificate> wrongTrustAnchors = {*wrongCert};
    EXPECT_FALSE(system_->verifyCertificateChain(*entityCert, wrongTrustAnchors))
        << "Chain validation should fail with wrong trust anchors";

    std::cout << "=== CertificateChainVerification test complete ===" << std::endl;
}

TEST_F(SignatureSystemTest, CertificateValidity) {
    auto keyPair = system_->generateKeyPair();
    
    // Create test root CA template with past validity period
    auto now = std::time(nullptr);
    SignatureSystem::Certificate expiredRoot;
    expiredRoot.publicKey = rootKeyPair_.publicKey;
    expiredRoot.subject = "Expired CA";
    expiredRoot.issuer = "Expired CA";
    expiredRoot.notBefore = now - 48 * 3600;  // 2 days ago
    expiredRoot.notAfter = now - 24 * 3600;   // 1 day ago

    // Enable testing mode to create expired certificates
    system_->setTestingMode(true);

    // Create self-signed expired root CA (with testing mode)
    auto expiredRootCert = system_->createCertificate(
        expiredRoot.publicKey,
        expiredRoot.subject,
        rootKeyPair_.privateKey,
        expiredRoot);
    
    ASSERT_TRUE(expiredRootCert.has_value()) << "Failed to create expired root CA";

    // Disable testing mode to verify expired certificates fail validation
    system_->setTestingMode(false);

    // Verify the expired certificate fails validation with normal checks
    std::vector<SignatureSystem::Certificate> trustAnchors = {*expiredRootCert};
    EXPECT_FALSE(system_->verifyCertificateChain(*expiredRootCert, trustAnchors))
        << "Expired root certificate should not verify";

    // Re-enable testing mode to create a certificate with expired issuer
    system_->setTestingMode(true);
    auto entityKeyPair = system_->generateKeyPair();
    auto entityCert = system_->createCertificate(
        entityKeyPair.publicKey,
        "Test Entity",
        rootKeyPair_.privateKey,
        *expiredRootCert);

    ASSERT_TRUE(entityCert.has_value()) << "Failed to create entity certificate";

    // Disable testing mode again to verify expired certificates are rejected
    system_->setTestingMode(false);
    EXPECT_FALSE(system_->verifyCertificateChain(*entityCert, trustAnchors))
        << "Certificate with expired issuer should not verify";
}

TEST_F(SignatureSystemTest, CertificatePEMExport) {
    auto keyPair = system_->generateKeyPair();
    auto cert = system_->createCertificate(
        keyPair.publicKey,
        "Test Subject",
        rootKeyPair_.privateKey,
        rootCert_).value();
    
    // Export to PEM
    auto pem = system_->exportCertificatePEM(cert);
    EXPECT_FALSE(pem.empty());
    EXPECT_TRUE(pem.find("-----BEGIN CERTIFICATE-----") != std::string::npos);
    EXPECT_TRUE(pem.find("-----END CERTIFICATE-----") != std::string::npos);
    
    // Import from PEM
    auto imported = system_->importCertificatePEM(pem);
    ASSERT_TRUE(imported.has_value());
    
    // Verify imported certificate matches original
    EXPECT_EQ(imported->subject, cert.subject);
    EXPECT_EQ(imported->issuer, cert.issuer);
    EXPECT_EQ(imported->publicKey, cert.publicKey);
    EXPECT_EQ(imported->signature, cert.signature);
}

TEST_F(SignatureSystemTest, PrivateKeyPEMExport) {
    auto keyPair = system_->generateKeyPair();
    std::string password = "test password";
    
    // Export to encrypted PEM
    auto pem = system_->exportPrivateKeyPEM(keyPair.privateKey, password);
    EXPECT_FALSE(pem.empty());
    
    // Import from PEM
    auto imported = system_->importPrivateKeyPEM(pem, password);
    ASSERT_TRUE(imported.has_value());
    
    // Verify imported key works for signing
    std::string message = "Test message";
    auto data = stringToBytes(message);
    
    auto signature = system_->sign(data, *imported);
    EXPECT_TRUE(system_->verify(data, signature, keyPair.publicKey));
}

TEST_F(SignatureSystemTest, InvalidOperations) {
    auto keyPair = system_->generateKeyPair();
    std::string message = "Test message";
    auto data = stringToBytes(message);
    
    // Try to sign with empty private key
    SecureMemory::SecureVector<uint8_t> emptyKey;
    auto signature = system_->sign(data, emptyKey);
    EXPECT_TRUE(signature.empty());
    
    // Try to verify with empty public key
    std::vector<uint8_t> emptyPublicKey;
    EXPECT_FALSE(system_->verify(data, signature, emptyPublicKey));
    
    // Try to create certificate with invalid issuer
    SignatureSystem::Certificate invalidIssuer;
    auto cert = system_->createCertificate(
        keyPair.publicKey,
        "Test Subject",
        keyPair.privateKey,
        invalidIssuer);
    EXPECT_FALSE(cert.has_value());
    
    // Try to import invalid PEM
    std::string invalidPEM = "invalid PEM data";
    EXPECT_FALSE(system_->importCertificatePEM(invalidPEM).has_value());
    EXPECT_FALSE(system_->importPrivateKeyPEM(invalidPEM, "password").has_value());
}
