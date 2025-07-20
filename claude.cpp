#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <cstring>
#include <cassert>
#include <ctime>
#include <cstdlib>
#include <gmp.h>

class RSA {
private:
    mpz_t n, e, d;
    size_t key_size;
    size_t block_size;
    size_t encrypted_block_size;
    gmp_randstate_t rng_state;
    
    // Generate a random prime of specified bit length
    void generate_prime(mpz_t result, size_t bits) {
        do {
            mpz_urandomb(result, rng_state, bits);
            mpz_setbit(result, bits - 1); // Ensure it's the right bit length
            mpz_setbit(result, 0);        // Ensure it's odd
            mpz_nextprime(result, result);
        } while (mpz_sizeinbase(result, 2) != bits);
    }
    
    // Convert bytes to mpz_t
    void bytes_to_mpz(mpz_t result, const unsigned char* data, size_t len) {
        // Use GMP's import function which handles the conversion properly
        mpz_import(result, len, 1, 1, 1, 0, data);
    }
    
    // Convert mpz_t to bytes (returns actual number of bytes written)
    size_t mpz_to_bytes(unsigned char* buffer, size_t buffer_size, const mpz_t num) {
        // Use GMP's export function which handles the conversion properly
        size_t count;
        memset(buffer, 0, buffer_size);
        
        // Export the number as binary data
        mpz_export(buffer, &count, 1, 1, 1, 0, num);
        
        return count;
    }
    
public:
    RSA(size_t bits = 2048) : key_size(bits) {
        // Initialize GMP integers
        mpz_init(n);
        mpz_init(e);
        mpz_init(d);
        
        // Initialize random state
        gmp_randinit_default(rng_state);
        gmp_randseed_ui(rng_state, std::random_device{}());
        
        generate_keys();
        
        // Calculate block sizes
        block_size = (key_size / 8) - 11; // Leave room for padding
        encrypted_block_size = (key_size + 7) / 8; // Size of encrypted block in bytes
    }
    
    ~RSA() {
        mpz_clear(n);
        mpz_clear(e);
        mpz_clear(d);
        gmp_randclear(rng_state);
    }
    
    void generate_keys() {
        std::cout << "Generating RSA keys..." << std::endl;
        
        mpz_t p, q, phi, temp;
        mpz_init(p);
        mpz_init(q);
        mpz_init(phi);
        mpz_init(temp);
        
        // Generate two large primes
        generate_prime(p, key_size / 2);
        generate_prime(q, key_size / 2);
        
        // Calculate n = p * q
        mpz_mul(n, p, q);
        
        // Calculate phi(n) = (p-1) * (q-1)
        mpz_sub_ui(p, p, 1);
        mpz_sub_ui(q, q, 1);
        mpz_mul(phi, p, q);
        
        // Choose e (commonly 65537)
        mpz_set_ui(e, 65537);
        
        // Calculate d = e^(-1) mod phi(n)
        mpz_invert(d, e, phi);
        
        mpz_clear(p);
        mpz_clear(q);
        mpz_clear(phi);
        mpz_clear(temp);
        
        std::cout << "Keys generated successfully!" << std::endl;
        std::cout << "Key size: " << key_size << " bits" << std::endl;
        std::cout << "Block size: " << block_size << " bytes" << std::endl;
        std::cout << "Encrypted block size: " << encrypted_block_size << " bytes" << std::endl;
    }
    
    std::vector<unsigned char> encrypt(const unsigned char* data, size_t data_len) {
        size_t num_blocks = (data_len + block_size - 1) / block_size;
        std::vector<unsigned char> encrypted_data;
        
        // Reserve space: 4 bytes for original length + encrypted blocks
        encrypted_data.reserve(4 + num_blocks * encrypted_block_size);
        
        // Store original data length in first 4 bytes (big-endian)
        encrypted_data.push_back((data_len >> 24) & 0xFF);
        encrypted_data.push_back((data_len >> 16) & 0xFF);
        encrypted_data.push_back((data_len >> 8) & 0xFF);
        encrypted_data.push_back(data_len & 0xFF);
        
        mpz_t m, c;
        mpz_init(m);
        mpz_init(c);
        
        for (size_t i = 0; i < data_len; i += block_size) {
            size_t current_block_size = std::min(block_size, data_len - i);
            
            // Convert block to mpz_t
            bytes_to_mpz(m, data + i, current_block_size);
            
            // Encrypt: c = m^e mod n
            mpz_powm(c, m, e, n);
            
            // Convert encrypted block to bytes
            unsigned char encrypted_block[encrypted_block_size];
            memset(encrypted_block, 0, encrypted_block_size);
            
            size_t actual_bytes;
            mpz_export(encrypted_block + (encrypted_block_size - mpz_sizeinbase(c, 256)), 
                      &actual_bytes, 1, 1, 1, 0, c);
            
            // Add to result
            encrypted_data.insert(encrypted_data.end(), 
                                encrypted_block, 
                                encrypted_block + encrypted_block_size);
        }
        
        mpz_clear(m);
        mpz_clear(c);
        
        return encrypted_data;
    }
    
    std::vector<unsigned char> encrypt(const std::string& message) {
        return encrypt(reinterpret_cast<const unsigned char*>(message.c_str()), 
                      message.length());
    }
    
    std::vector<unsigned char> decrypt(const unsigned char* encrypted_data, size_t encrypted_len) {
        if (encrypted_len < 4) {
            throw std::runtime_error("Invalid encrypted data - too short");
        }
        
        // Extract original data length from first 4 bytes
        size_t original_len = ((size_t)encrypted_data[0] << 24) |
                             ((size_t)encrypted_data[1] << 16) |
                             ((size_t)encrypted_data[2] << 8) |
                             ((size_t)encrypted_data[3]);
        
        // Skip the length prefix
        encrypted_data += 4;
        encrypted_len -= 4;
        
        if (encrypted_len % encrypted_block_size != 0) {
            throw std::runtime_error("Invalid encrypted data length");
        }
        
        size_t num_blocks = encrypted_len / encrypted_block_size;
        std::vector<unsigned char> decrypted_data;
        decrypted_data.reserve(original_len);
        
        mpz_t c, m;
        mpz_init(c);
        mpz_init(m);
        
        for (size_t i = 0; i < num_blocks; i++) {
            const unsigned char* encrypted_block = encrypted_data + (i * encrypted_block_size);
            
            // Convert encrypted block to mpz_t
            bytes_to_mpz(c, encrypted_block, encrypted_block_size);
            
            // Decrypt: m = c^d mod n
            mpz_powm(m, c, d, n);
            
            // Calculate how many bytes this block should produce
            size_t remaining_bytes = original_len - decrypted_data.size();
            size_t expected_block_size = std::min(block_size, remaining_bytes);
            
            // Convert decrypted block to bytes
            unsigned char decrypted_block[block_size];
            memset(decrypted_block, 0, sizeof(decrypted_block));
            
            size_t actual_bytes;
            mpz_export(decrypted_block + (expected_block_size - mpz_sizeinbase(m, 256)), 
                      &actual_bytes, 1, 1, 1, 0, m);
            
            // Add the expected number of bytes to result
            decrypted_data.insert(decrypted_data.end(), 
                                decrypted_block, 
                                decrypted_block + expected_block_size);
        }
        
        mpz_clear(c);
        mpz_clear(m);
        
        return decrypted_data;
    }
    
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& encrypted_data) {
        return decrypt(encrypted_data.data(), encrypted_data.size());
    }
    
    void print_public_key() {
        std::cout << "\nPublic Key:" << std::endl;
        std::cout << "n = ";
        mpz_out_str(stdout, 10, n);
        std::cout << std::endl;
        std::cout << "e = ";
        mpz_out_str(stdout, 10, e);
        std::cout << std::endl;
    }
    
    void print_private_key() {
        std::cout << "\nPrivate Key:" << std::endl;
        std::cout << "n = ";
        mpz_out_str(stdout, 10, n);
        std::cout << std::endl;
        std::cout << "d = ";
        mpz_out_str(stdout, 10, d);
        std::cout << std::endl;
    }
};

// Helper function to print binary data as hex
void print_hex(const std::vector<unsigned char>& data, const std::string& label, size_t max_bytes = 64) {
    if (!label.empty()) {
        std::cout << label << " (" << data.size() << " bytes):" << std::endl;
    }
    for (size_t i = 0; i < std::min(data.size(), max_bytes); i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0) std::cout << std::endl;
        else if ((i + 1) % 4 == 0) std::cout << " ";
    }
    if (data.size() > max_bytes) {
        std::cout << "... (truncated)";
    }
    std::cout << std::endl;
}

void test_large_buffer() {
    std::cout << "\n=== Test 4: Large Buffer (100 bytes) ===" << std::endl;
    RSA rsa(1024);
    
    std::vector<unsigned char> input;
    for (int i = 0; i < 100; i++) {
        input.push_back(i % 256);
    }
    
    std::cout << "Original (" << input.size() << " bytes): ";
    print_hex(input, "", 32);
    
    std::vector<unsigned char> encrypted = rsa.encrypt(input.data(), input.size());
    std::cout << "Encrypted (" << encrypted.size() << " bytes): ";
    print_hex(encrypted, "", 32);
    
    std::vector<unsigned char> decrypted = rsa.decrypt(encrypted);
    std::cout << "Decrypted (" << decrypted.size() << " bytes): ";
    print_hex(decrypted, "", 32);
    
    assert(input == decrypted);
    std::cout << "✅ Success: Large buffer test passed!" << std::endl;
}

void test_empty_buffer() {
    std::cout << "\n=== Test 5: Empty Buffer ===" << std::endl;
    RSA rsa(1024);
    
    std::vector<unsigned char> input = {};
    
    std::cout << "Original (0 bytes): <empty>" << std::endl;
    std::vector<unsigned char> encrypted = rsa.encrypt(input.data(), input.size());
    std::cout << "Encrypted (" << encrypted.size() << " bytes): ";
    print_hex(encrypted, "", 32);
    
    std::vector<unsigned char> decrypted = rsa.decrypt(encrypted);
    std::cout << "Decrypted (" << decrypted.size() << " bytes): ";
    print_hex(decrypted, "", 32);
    
    assert(input == decrypted);
    std::cout << "✅ Success: Empty buffer test passed!" << std::endl;
}

void test_single_byte() {
    std::cout << "\n=== Test 6: Single Byte ===" << std::endl;
    RSA rsa(1024);
    
    std::vector<unsigned char> input = {0x42};
    
    std::cout << "Original (1 byte): ";
    print_hex(input, "", 32);
    
    std::vector<unsigned char> encrypted = rsa.encrypt(input.data(), input.size());
    std::cout << "Encrypted (" << encrypted.size() << " bytes): ";
    print_hex(encrypted, "", 32);
    
    std::vector<unsigned char> decrypted = rsa.decrypt(encrypted);
    std::cout << "Decrypted (" << decrypted.size() << " bytes): ";
    print_hex(decrypted, "", 32);
    
    assert(input == decrypted);
    std::cout << "✅ Success: Single byte test passed!" << std::endl;
}

void test_small_buffer() {
    std::cout << "\n=== Test 7: Small Buffer (8 bytes) ===" << std::endl;
    RSA rsa(1024);
    
    std::vector<unsigned char> input = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    
    std::cout << "Original (" << input.size() << " bytes): ";
    print_hex(input, "", 32);
    
    std::vector<unsigned char> encrypted = rsa.encrypt(input.data(), input.size());
    std::cout << "Encrypted (" << encrypted.size() << " bytes): ";
    print_hex(encrypted, "", 32);
    
    std::vector<unsigned char> decrypted = rsa.decrypt(encrypted);
    std::cout << "Decrypted (" << decrypted.size() << " bytes): ";
    print_hex(decrypted, "", 32);
    
    assert(input == decrypted);
    std::cout << "✅ Success: Small buffer test passed!" << std::endl;
}

void test_text_data() {
    std::cout << "\n=== Test 8: Text Data ===" << std::endl;
    RSA rsa(1024);
    
    std::string text = "Hello, World! This is a test message for RSA encryption.";
    std::vector<unsigned char> input(text.begin(), text.end());
    
    std::cout << "Original (" << input.size() << " bytes): " << text << std::endl;
    std::cout << "Original (hex): ";
    print_hex(input, "", 32);
    
    std::vector<unsigned char> encrypted = rsa.encrypt(input.data(), input.size());
    std::cout << "Encrypted (" << encrypted.size() << " bytes): ";
    print_hex(encrypted, "", 32);
    
    std::vector<unsigned char> decrypted = rsa.decrypt(encrypted);
    std::cout << "Decrypted (" << decrypted.size() << " bytes): ";
    print_hex(decrypted, "", 32);
    
    std::string decrypted_text(decrypted.begin(), decrypted.end());
    std::cout << "Decrypted (text): " << decrypted_text << std::endl;
    
    assert(input == decrypted);
    std::cout << "✅ Success: Text data test passed!" << std::endl;
}

void test_random_data() {
    std::cout << "\n=== Test 9: Random Data ===" << std::endl;
    RSA rsa(1024);
    
    // Generate random data
    std::srand(std::time(nullptr));
    std::vector<unsigned char> input;
    for (int i = 0; i < 50; i++) {
        input.push_back(std::rand() % 256);
    }
    
    std::cout << "Original (" << input.size() << " bytes): ";
    print_hex(input, "", 32);
    
    std::vector<unsigned char> encrypted = rsa.encrypt(input.data(), input.size());
    std::cout << "Encrypted (" << encrypted.size() << " bytes): ";
    print_hex(encrypted, "", 32);
    
    std::vector<unsigned char> decrypted = rsa.decrypt(encrypted);
    std::cout << "Decrypted (" << decrypted.size() << " bytes): ";
    print_hex(decrypted, "", 32);
    
    assert(input == decrypted);
    std::cout << "✅ Success: Random data test passed!" << std::endl;
}

void test_edge_cases() {
    std::cout << "\n=== Test 10: Edge Cases ===" << std::endl;
    RSA rsa(1024);
    
    // Test case 1: All zeros
    std::vector<unsigned char> input1(16, 0);
    std::cout << "Test 10a: All zeros (" << input1.size() << " bytes)" << std::endl;
    std::vector<unsigned char> encrypted1 = rsa.encrypt(input1.data(), input1.size());
    std::vector<unsigned char> decrypted1 = rsa.decrypt(encrypted1);
    assert(input1 == decrypted1);
    std::cout << "✅ Success: All zeros test passed!" << std::endl;
    
    // Test case 2: All ones
    std::vector<unsigned char> input2(16, 0xFF);
    std::cout << "Test 10b: All ones (" << input2.size() << " bytes)" << std::endl;
    std::vector<unsigned char> encrypted2 = rsa.encrypt(input2.data(), input2.size());
    std::vector<unsigned char> decrypted2 = rsa.decrypt(encrypted2);
    assert(input2 == decrypted2);
    std::cout << "✅ Success: All ones test passed!" << std::endl;
    
    // Test case 3: Alternating pattern
    std::vector<unsigned char> input3;
    for (int i = 0; i < 32; i++) {
        input3.push_back(i % 2 == 0 ? 0xAA : 0x55);
    }
    std::cout << "Test 10c: Alternating pattern (" << input3.size() << " bytes)" << std::endl;
    std::vector<unsigned char> encrypted3 = rsa.encrypt(input3.data(), input3.size());
    std::vector<unsigned char> decrypted3 = rsa.decrypt(encrypted3);
    assert(input3 == decrypted3);
    std::cout << "✅ Success: Alternating pattern test passed!" << std::endl;
}

void test_multiple_keys() {
    std::cout << "\n=== Test 11: Multiple Key Pairs ===" << std::endl;
    
    for (int test_num = 1; test_num <= 3; test_num++) {
        std::cout << "Key pair " << test_num << ":" << std::endl;
        RSA rsa(1024);
        
        std::vector<unsigned char> input = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
        
        std::vector<unsigned char> encrypted = rsa.encrypt(input.data(), input.size());
        std::vector<unsigned char> decrypted = rsa.decrypt(encrypted);
        
        assert(input == decrypted);
        std::cout << "✅ Success: Key pair " << test_num << " test passed!" << std::endl;
    }
}

void test_many_blocks() {
    std::cout << "\n=== Test 12: Many Blocks (1000 bytes) ===" << std::endl;
    RSA rsa(1024);
    
    // Create a 1000-byte buffer with a repeating pattern
    std::vector<unsigned char> input;
    for (int i = 0; i < 1000; i++) {
        input.push_back((i * 7 + 13) % 256);  // Some pattern to make it interesting
    }
    
    std::cout << "Original (" << input.size() << " bytes): ";
    // Show first 32 bytes and last 32 bytes
    for (size_t i = 0; i < 32; i++) {
        printf("%02X ", input[i]);
    }
    std::cout << "... ";
    for (size_t i = input.size() - 32; i < input.size(); i++) {
        printf("%02X ", input[i]);
    }
    std::cout << std::endl;
    
    std::vector<unsigned char> encrypted = rsa.encrypt(input.data(), input.size());
    std::cout << "Encrypted (" << encrypted.size() << " bytes): ";
    // Show first 32 bytes and last 32 bytes
    for (size_t i = 0; i < 32; i++) {
        printf("%02X ", encrypted[i]);
    }
    std::cout << "... ";
    for (size_t i = encrypted.size() - 32; i < encrypted.size(); i++) {
        printf("%02X ", encrypted[i]);
    }
    std::cout << std::endl;
    
    std::vector<unsigned char> decrypted = rsa.decrypt(encrypted);
    std::cout << "Decrypted (" << decrypted.size() << " bytes): ";
    // Show first 32 bytes and last 32 bytes
    for (size_t i = 0; i < 32; i++) {
        printf("%02X ", decrypted[i]);
    }
    std::cout << "... ";
    for (size_t i = decrypted.size() - 32; i < decrypted.size(); i++) {
        printf("%02X ", decrypted[i]);
    }
    std::cout << std::endl;
    
    assert(input == decrypted);
    std::cout << "✅ Success: Many blocks test passed!" << std::endl;
}

void test_extreme_blocks() {
    std::cout << "\n=== Test 13: Extreme Blocks (5000 bytes) ===" << std::endl;
    RSA rsa(1024);
    
    // Create a 5000-byte buffer with a more complex pattern
    std::vector<unsigned char> input;
    for (int i = 0; i < 5000; i++) {
        // Create a more complex pattern: Fibonacci-like sequence mod 256
        unsigned char val = (i * i * 7 + i * 13 + 17) % 256;
        input.push_back(val);
    }
    
    std::cout << "Original (" << input.size() << " bytes): ";
    // Show first 16 bytes and last 16 bytes
    for (size_t i = 0; i < 16; i++) {
        printf("%02X ", input[i]);
    }
    std::cout << "... ";
    for (size_t i = input.size() - 16; i < input.size(); i++) {
        printf("%02X ", input[i]);
    }
    std::cout << std::endl;
    
    std::vector<unsigned char> encrypted = rsa.encrypt(input.data(), input.size());
    std::cout << "Encrypted (" << encrypted.size() << " bytes): ";
    // Show first 16 bytes and last 16 bytes
    for (size_t i = 0; i < 16; i++) {
        printf("%02X ", encrypted[i]);
    }
    std::cout << "... ";
    for (size_t i = encrypted.size() - 16; i < encrypted.size(); i++) {
        printf("%02X ", encrypted[i]);
    }
    std::cout << std::endl;
    
    std::vector<unsigned char> decrypted = rsa.decrypt(encrypted);
    std::cout << "Decrypted (" << decrypted.size() << " bytes): ";
    // Show first 16 bytes and last 16 bytes
    for (size_t i = 0; i < 16; i++) {
        printf("%02X ", decrypted[i]);
    }
    std::cout << "... ";
    for (size_t i = decrypted.size() - 16; i < decrypted.size(); i++) {
        printf("%02X ", decrypted[i]);
    }
    std::cout << std::endl;
    
    assert(input == decrypted);
    std::cout << "✅ Success: Extreme blocks test passed!" << std::endl;
}

void test_rsa_binary_buffer() {
    std::cout << "\n=== Test 14: Original Test Case ===" << std::endl;
    RSA rsa(1024);
    
    std::cout << "Generating RSA keys..." << std::endl;
    
    std::vector<unsigned char> input = {
        0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0xCC, 0xDD, 0xEE, 0xFF, 0x10, 0x20, 0x30, 0x40
    };
    
    std::cout << "Original (" << input.size() << " bytes): ";
    print_hex(input, "", 32);
    
    std::vector<unsigned char> encrypted = rsa.encrypt(input.data(), input.size());
    std::cout << "Encrypted (" << encrypted.size() << " bytes): ";
    print_hex(encrypted, "", 32);
    
    std::vector<unsigned char> decrypted = rsa.decrypt(encrypted);
    std::cout << "Decrypted (" << decrypted.size() << " bytes): ";
    print_hex(decrypted, "", 32);
    
    assert(input == decrypted);
    std::cout << "✅ Success: Original test case passed!" << std::endl;
}

int main() {
    try {
        std::cout << "RSA Encryption/Decryption Test Suite" << std::endl;
        std::cout << "=====================================" << std::endl;
        
        // Create RSA instance with 1024-bit keys (use 2048 or higher for production)
        RSA rsa(1024);
        
        // Print keys
        rsa.print_public_key();
        rsa.print_private_key();
        
        // Test message - can be arbitrarily long
        std::string message = "This is a test message for RSA encryption! "
                            "It can be very long and will be automatically "
                            "broken into blocks for encryption. Each block "
                            "is encrypted separately using RSA. This allows "
                            "us to encrypt messages of any length, not just "
                            "those smaller than the RSA modulus. Pretty cool, right? "
                            "Let's add some more text to make it even longer... "
                            "The quick brown fox jumps over the lazy dog. "
                            "This sentence contains every letter of the alphabet! "
                            "Here's some binary data too: \x00\x01\x02\xFF\xFE\xFD";
        
        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "Original message (" << message.length() << " bytes):" << std::endl;
        std::cout << message << std::endl;
        
        // Show original as hex
        std::vector<unsigned char> original_data(message.begin(), message.end());
        print_hex(original_data, "\nOriginal data", 128);
        
        // Encrypt
        std::cout << "\nEncrypting..." << std::endl;
        std::vector<unsigned char> encrypted = rsa.encrypt(message);
        std::cout << "Encrypted into " << (encrypted.size() / 128) << " blocks." << std::endl;
        
        // Print encrypted data as hex
        print_hex(encrypted, "\nEncrypted data", 256);
        
        // Decrypt
        std::cout << "\nDecrypting..." << std::endl;
        std::vector<unsigned char> decrypted = rsa.decrypt(encrypted);
        
        // Convert decrypted data back to string
        std::string decrypted_message(decrypted.begin(), decrypted.end());
        
        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "Decrypted message (" << decrypted_message.length() << " bytes):" << std::endl;
        std::cout << decrypted_message << std::endl;
        
        // Show decrypted as hex
        print_hex(decrypted, "\nDecrypted data", 128);
        
        // Verify
        std::cout << "\n" << std::string(60, '=') << std::endl;
        if (message == decrypted_message) {
            std::cout << "✓ SUCCESS: Original and decrypted messages match!" << std::endl;
        } else {
            std::cout << "✗ ERROR: Messages don't match!" << std::endl;
            std::cout << "Original length: " << message.length() << std::endl;
            std::cout << "Decrypted length: " << decrypted_message.length() << std::endl;
        }
        
        // Run comprehensive test suite
        test_large_buffer();
        test_empty_buffer();
        test_single_byte();
        test_small_buffer();
        test_text_data();
        test_random_data();
        test_edge_cases();
        test_multiple_keys();
        test_many_blocks();
        test_extreme_blocks();
        test_rsa_binary_buffer();
        
        std::cout << "\n🎉 All tests passed successfully!" << std::endl;
        std::cout << "RSA implementation is working correctly." << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Test failed with exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "❌ Test failed with unknown exception" << std::endl;
        return 1;
    }
    
    return 0;
}