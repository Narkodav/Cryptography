#include <iostream>
#include "Hashing/SHA2Base.h"

//int main() {
//    std::cout << "=== Streaming API Example ===\n";
//
//    // Method 1: Streaming/Chunked
//    {
//        Cryptography::SHA256 sha;
//        sha.update("Hello, ");
//        sha.update("world!");
//        std::cout << "Streaming:  " << sha.hexdigest() << "\n";
//    }
//
//    // Method 2: One-shot
//    std::cout << "One-shot:   " << Cryptography::SHA256::hash("Hello, world!") << "\n";
//
//    // Method 3: Large file simulation
//    {
//        Cryptography::SHA256 sha;
//        std::string large_data(10000, 'A'); // 10KB of 'A's
//        sha.update(large_data);
//        std::cout << "Large data: " << sha.hexdigest() << "\n";
//    }
//
//    // Verify with known test vectors
//    std::cout << "\n=== Test Vectors ===\n";
//    std::cout << "Empty:    " << Cryptography::SHA256::hash("") << "\n";
//    std::cout << "Expected: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n";
//
//    std::cout << "\n'abc':    " << Cryptography::SHA256::hash("abc") << "\n";
//    std::cout << "Expected: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n";
//
//    return 0;
//}

//int main() {
//    std::cout << "=== SHA-384 Implementation ===\n\n";
//
//    // Test vectors from NIST
//    std::cout << "Test vectors from NIST FIPS 180-4:\n\n";
//
//    // Empty string
//    std::string empty = "";
//    std::cout << "SHA-384('" << empty << "') = \n";
//    std::cout << Cryptography::SHA384::hash(empty) << "\n";
//    std::cout << "Expected: 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b\n\n";
//
//    // "abc"
//    std::string abc = "abc";
//    std::cout << "SHA-384('" << abc << "') = \n";
//    std::cout << Cryptography::SHA384::hash(abc) << "\n";
//    std::cout << "Expected: cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7\n\n";
//
//    // Longer message
//    std::string message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
//    std::cout << "SHA-384(1024 'a's) = \n";
//
//    Cryptography::SHA384 sha;
//    for (int i = 0; i < 16; i++) { // 16 * 64 = 1024 'a's
//        sha.update(std::string(64, 'a'));
//    }
//    std::cout << sha.hexdigest() << "\n";
//    std::cout << "Expected: a31bea5896ef0e418f18014ef9fde89f6f33a177dc97190bc39dedd94e5476342a0d277c92bc19ca0542fca227d12c4c\n\n";
//
//    // Streaming example
//    std::cout << "=== Streaming Example ===\n";
//    Cryptography::SHA384 sha2;
//    sha2.update("Hello, ");
//    sha2.update("world! ");
//    sha2.update("This is a ");
//    sha2.update("streaming test.");
//    std::cout << "Streaming hash: " << sha2.hexdigest() << "\n";
//
//    // Compare with one-shot
//    std::cout << "One-shot hash:  " << Cryptography::SHA384::hash("Hello, world! This is a streaming test.") << "\n";
//
//    return 0;
//}

//int main() {
//    std::cout << "=== SHA-384 Implementation ===\n\n";
//
//    // Test vectors from NIST
//    std::cout << "Test vectors from NIST FIPS 180-4:\n\n";
//
//    // Empty string
//    std::string empty = "";
//    std::cout << "SHA-384('" << empty << "') = \n";
//    std::cout << Cryptography::SHA512::hash(empty) << "\n";
//    std::cout << "Expected: 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b\n\n";
//
//    // "abc"
//    std::string abc = "abc";
//    std::cout << "SHA-384('" << abc << "') = \n";
//    std::cout << Cryptography::SHA512::hash(abc) << "\n";
//    std::cout << "Expected: cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7\n\n";
//
//    // Longer message
//    std::string message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
//    std::cout << "SHA-384(1024 'a's) = \n";
//
//    Cryptography::SHA512 sha;
//    for (int i = 0; i < 16; i++) { // 16 * 64 = 1024 'a's
//        sha.update(std::string(64, 'a'));
//    }
//    std::cout << sha.hexdigest() << "\n";
//    std::cout << "Expected: a31bea5896ef0e418f18014ef9fde89f6f33a177dc97190bc39dedd94e5476342a0d277c92bc19ca0542fca227d12c4c\n\n";
//
//    // Streaming example
//    std::cout << "=== Streaming Example ===\n";
//    Cryptography::SHA512 sha2;
//    sha2.update("Hello, ");
//    sha2.update("world! ");
//    sha2.update("This is a ");
//    sha2.update("streaming test.");
//    std::cout << "Streaming hash: " << sha2.hexdigest() << "\n";
//
//    // Compare with one-shot
//    std::cout << "One-shot hash:  " << Cryptography::SHA512::hash("Hello, world! This is a streaming test.") << "\n";
//
//    return 0;
//}