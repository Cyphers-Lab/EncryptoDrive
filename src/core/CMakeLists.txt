target_sources(encrypto-core
    PRIVATE
        crypto/signaturesystem.cpp
        encryptionengine.cpp
        fileintegrity.cpp
        integrity/merkletree.cpp
        keysmanager.cpp
        securememory.cpp
        version/fileversion.cpp
        version/versionstore.cpp
)

target_include_directories(encrypto-core
    PRIVATE
        ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(encrypto-core
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
        SQLite::SQLite3
)
