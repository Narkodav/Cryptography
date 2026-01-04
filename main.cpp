#include <iostream>

#include "include/Hashing/MD5.h"
#include "include/Hashing/SHA1.h"
#include "include/Hashing/SHA2.h"
#include "include/Hashing/SHA3.h"
#include "include/Hashing/StreamHash.h"

int main() {

    //std::cout << "=== MD5 Implementation ===\n\n";
    //std::cout << "\"\"\t\t" << Cryptography::Hash::MD5::hash("") << std::endl;
    //std::cout << "\"Hello World\"\t" << Cryptography::Hash::MD5::hash("Hello World") << std::endl;
    //std::cout << "\"abc\"\t\t" << Cryptography::Hash::MD5::hash("abc") << std::endl;
    //std::cout << "\"message digest\"\t" << Cryptography::Hash::MD5::hash("message digest") << std::endl;
    //std::cout << "\"abcdefghijklmnopqrstuvwxyz\"\t"
    //    << Cryptography::Hash::MD5::hash("abcdefghijklmnopqrstuvwxyz") << std::endl;
    //std::cout << "\n\n";

    //std::cout << "=== SHA1 Implementation ===\n\n";
    //std::cout << "\"\"\t\t" << Cryptography::Hash::SHA1::hash("") << std::endl;
    //std::cout << "\"Hello World\"\t" << Cryptography::Hash::SHA1::hash("Hello World") << std::endl;
    //std::cout << "\"abc\"\t\t" << Cryptography::Hash::SHA1::hash("abc") << std::endl;
    //std::cout << "\"message digest\"\t" << Cryptography::Hash::SHA1::hash("message digest") << std::endl;
    //std::cout << "\"abcdefghijklmnopqrstuvwxyz\"\t"
    //    << Cryptography::Hash::SHA1::hash("abcdefghijklmnopqrstuvwxyz") << std::endl;
    //std::cout << "\n\n";

    //std::cout << "=== SHA2_224 Implementation ===\n\n";
    //std::cout << "\"\"\t\t" << Cryptography::Hash::SHA2_224::hash("") << std::endl;
    //std::cout << "\"Hello World\"\t" << Cryptography::Hash::SHA2_224::hash("Hello World") << std::endl;
    //std::cout << "\"abc\"\t\t" << Cryptography::Hash::SHA2_224::hash("abc") << std::endl;
    //std::cout << "\"message digest\"\t" << Cryptography::Hash::SHA2_224::hash("message digest") << std::endl;
    //std::cout << "\"abcdefghijklmnopqrstuvwxyz\"\t"
    //    << Cryptography::Hash::SHA2_224::hash("abcdefghijklmnopqrstuvwxyz") << std::endl;
    //std::cout << "\n\n";

    //std::cout << "=== SHA2_256 Implementation ===\n\n";
    //std::cout << "\"\"\t\t" << Cryptography::Hash::SHA2_256::hash("") << std::endl;
    //std::cout << "\"Hello World\"\t" << Cryptography::Hash::SHA2_256::hash("Hello World") << std::endl;
    //std::cout << "\"abc\"\t\t" << Cryptography::Hash::SHA2_256::hash("abc") << std::endl;
    //std::cout << "\"message digest\"\t" << Cryptography::Hash::SHA2_256::hash("message digest") << std::endl;
    //std::cout << "\"abcdefghijklmnopqrstuvwxyz\"\t"
    //    << Cryptography::Hash::SHA2_256::hash("abcdefghijklmnopqrstuvwxyz") << std::endl;
    //std::cout << "\n\n";

    //std::cout << "=== SHA2_384 Implementation ===\n\n";
    //std::cout << "\"\"\t\t" << Cryptography::Hash::SHA2_384::hash("") << std::endl;
    //std::cout << "\"Hello World\"\t" << Cryptography::Hash::SHA2_384::hash("Hello World") << std::endl;
    //std::cout << "\"abc\"\t\t" << Cryptography::Hash::SHA2_384::hash("abc") << std::endl;
    //std::cout << "\"message digest\"\t" << Cryptography::Hash::SHA2_384::hash("message digest") << std::endl;
    //std::cout << "\"abcdefghijklmnopqrstuvwxyz\"\t"
    //    << Cryptography::Hash::SHA2_384::hash("abcdefghijklmnopqrstuvwxyz") << std::endl;
    //std::cout << "\n\n";

    //std::cout << "=== SHA2_512 Implementation ===\n\n";
    //std::cout << "\"\"\t\t" << Cryptography::Hash::SHA2_512::hash("") << std::endl;
    //std::cout << "\"Hello World\"\t" << Cryptography::Hash::SHA2_512::hash("Hello World") << std::endl;
    //std::cout << "\"abc\"\t\t" << Cryptography::Hash::SHA2_512::hash("abc") << std::endl;
    //std::cout << "\"message digest\"\t" << Cryptography::Hash::SHA2_512::hash("message digest") << std::endl;
    //std::cout << "\"abcdefghijklmnopqrstuvwxyz\"\t"
    //    << Cryptography::Hash::SHA2_512::hash("abcdefghijklmnopqrstuvwxyz") << std::endl;
    //std::cout << "\n\n";

    //std::cout << "=== SHA3_224 Implementation ===\n\n";
    //std::cout << "\"\"\t\t" << Cryptography::Hash::SHA3_224::hash("") << std::endl;
    //std::cout << "\"Hello World\"\t" << Cryptography::Hash::SHA3_224::hash("Hello World") << std::endl;
    //std::cout << "\"abc\"\t\t" << Cryptography::Hash::SHA3_224::hash("abc") << std::endl;
    //std::cout << "\"message digest\"\t" << Cryptography::Hash::SHA3_224::hash("message digest") << std::endl;
    //std::cout << "\"abcdefghijklmnopqrstuvwxyz\"\t"
    //    << Cryptography::Hash::SHA3_224::hash("abcdefghijklmnopqrstuvwxyz") << std::endl;
    //std::cout << "\n\n";

    //std::cout << "=== SHA3_256 Implementation ===\n\n";
    //std::cout << "\"\"\t\t" << Cryptography::Hash::SHA3_256::hash("") << std::endl;
    //std::cout << "\"Hello World\"\t" << Cryptography::Hash::SHA3_256::hash("Hello World") << std::endl;
    //std::cout << "\"abc\"\t\t" << Cryptography::Hash::SHA3_256::hash("abc") << std::endl;
    //std::cout << "\"message digest\"\t" << Cryptography::Hash::SHA3_256::hash("message digest") << std::endl;
    //std::cout << "\"abcdefghijklmnopqrstuvwxyz\"\t"
    //    << Cryptography::Hash::SHA3_256::hash("abcdefghijklmnopqrstuvwxyz") << std::endl;
    //std::cout << "\n\n";

    //std::cout << "=== SHA3_384 Implementation ===\n\n";
    //std::cout << "\"\"\t\t" << Cryptography::Hash::SHA3_384::hash("") << std::endl;
    //std::cout << "\"Hello World\"\t" << Cryptography::Hash::SHA3_384::hash("Hello World") << std::endl;
    //std::cout << "\"abc\"\t\t" << Cryptography::Hash::SHA3_384::hash("abc") << std::endl;
    //std::cout << "\"message digest\"\t" << Cryptography::Hash::SHA3_384::hash("message digest") << std::endl;
    //std::cout << "\"abcdefghijklmnopqrstuvwxyz\"\t"
    //    << Cryptography::Hash::SHA3_384::hash("abcdefghijklmnopqrstuvwxyz") << std::endl;
    //std::cout << "\n\n";

    //std::cout << "=== SHA3_512 Implementation ===\n\n";
    //std::cout << "\"\"\t\t" << Cryptography::Hash::SHA3_512::hash("") << std::endl;
    //std::cout << "\"Hello World\"\t" << Cryptography::Hash::SHA3_512::hash("Hello World") << std::endl;
    //std::cout << "\"abc\"\t\t" << Cryptography::Hash::SHA3_512::hash("abc") << std::endl;
    //std::cout << "\"message digest\"\t" << Cryptography::Hash::SHA3_512::hash("message digest") << std::endl;
    //std::cout << "\"abcdefghijklmnopqrstuvwxyz\"\t"
    //    << Cryptography::Hash::SHA3_512::hash("abcdefghijklmnopqrstuvwxyz") << std::endl;
    //std::cout << "\n\n";


    return 0;
}