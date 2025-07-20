#include <iostream>
#include <vector>
#include <string>
#include <gmp.h>
#include <ctime>
#include <cassert>
#include <cstring>
#include <exception>

using namespace std;

const int BIT_SIZE = 1024;

// === Binary ↔ mpz_t ===

void bufferToMpz(mpz_t rop, const vector<uint8_t> &buf) {
    mpz_import(rop, buf.size(), 1, 1, 0, 0, buf.data());
}

vector<uint8_t> mpzToBuffer(const mpz_t op, size_t expected_size = 0) {
    size_t count;
    void *data = mpz_export(NULL, &count, 1, 1, 0, 0, op);
    vector<uint8_t> buf((uint8_t*)data, (uint8_t*)data + count);
    free(data);
    
    // If expected_size is provided and larger than actual size, pad with zeros
    if (expected_size > 0 && buf.size() < expected_size) {
        vector<uint8_t> padded(expected_size, 0);
        copy(buf.begin(), buf.end(), padded.begin() + (expected_size - buf.size()));
        return padded;
    }
    
    return buf;
}

// === RSA ===

void generate_keys(mpz_t n, mpz_t e, mpz_t d) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    mpz_t p, q, phi, gcd, tmp1, tmp2;
    mpz_inits(p, q, phi, gcd, tmp1, tmp2, NULL);

    while (true) {
        mpz_urandomb(p, state, BIT_SIZE / 2);
        mpz_nextprime(p, p);
        mpz_urandomb(q, state, BIT_SIZE / 2);
        mpz_nextprime(q, q);

        mpz_mul(n, p, q);

        mpz_sub_ui(tmp1, p, 1);
        mpz_sub_ui(tmp2, q, 1);
        mpz_mul(phi, tmp1, tmp2);

        mpz_set_ui(e, 65537);
        mpz_gcd(gcd, e, phi);

        if (mpz_cmp_ui(gcd, 1) == 0) break;
    }

    if (mpz_invert(d, e, phi) == 0) {
        cerr << "Error: e and phi(n) are not coprime!" << endl;
        exit(1);
    }

    mpz_clears(p, q, phi, gcd, tmp1, tmp2, NULL);
    gmp_randclear(state);
}

void rsa_encrypt(mpz_t c, const mpz_t m, const mpz_t e, const mpz_t n) {
    mpz_powm(c, m, e, n);
}

void rsa_decrypt(mpz_t m, const mpz_t c, const mpz_t d, const mpz_t n) {
    mpz_powm(m, c, d, n);
}

// === Block Encryption/Decryption ===

vector<uint8_t> encrypt_buffer(const vector<uint8_t> &data, const mpz_t e, const mpz_t n) {
    size_t max_input_block = (mpz_sizeinbase(n, 2) - 1) / 8;
    size_t enc_block_bytes = (mpz_sizeinbase(n, 2) + 7) / 8;

    vector<uint8_t> encrypted;

    for (size_t i = 0; i < data.size(); i += max_input_block) {
        size_t len = min(max_input_block, data.size() - i);
        vector<uint8_t> block(data.begin() + i, data.begin() + i + len);

        mpz_t m, c;
        mpz_inits(m, c, NULL);
        bufferToMpz(m, block);
        rsa_encrypt(c, m, e, n);

        // Export to fixed size buffer
        vector<uint8_t> cbuf(enc_block_bytes, 0);
        size_t count;
        void *tmp = mpz_export(NULL, &count, 1, 1, 0, 0, c);
        if (count > enc_block_bytes) {
            cerr << "Encrypted block too large!" << endl;
            exit(1);
        }
        memcpy(cbuf.data() + (enc_block_bytes - count), tmp, count);
        free(tmp);

        // Store the original block size as the first byte of encrypted data
        encrypted.push_back(len);
        encrypted.insert(encrypted.end(), cbuf.begin(), cbuf.end());
        mpz_clears(m, c, NULL);
    }

    return encrypted;
}

vector<uint8_t> decrypt_buffer(const vector<uint8_t> &encrypted, const mpz_t d, const mpz_t n) {
    size_t enc_block_bytes = (mpz_sizeinbase(n, 2) + 7) / 8;
    vector<uint8_t> decrypted;

    for (size_t i = 0; i < encrypted.size(); i += (enc_block_bytes + 1)) {
        if (i >= encrypted.size()) break;
        
        // Read the original block size
        size_t original_size = encrypted[i];
        
        mpz_t c, m;
        mpz_inits(c, m, NULL);

        mpz_import(c, enc_block_bytes, 1, 1, 0, 0, encrypted.data() + i + 1);
        rsa_decrypt(m, c, d, n);

        vector<uint8_t> buf = mpzToBuffer(m, original_size);
        
        decrypted.insert(decrypted.end(), buf.begin(), buf.end());

        mpz_clears(c, m, NULL);
    }

    return decrypted;
}

// === Utility ===

void print_hex(const vector<uint8_t> &data) {
    for (uint8_t b : data)
        printf("%02X ", b);
    printf("\n");
}

// === Test ===

void test_empty_buffer() {
    cout << "\n=== Test 1: Empty Buffer ===" << endl;
    mpz_t n, e, d;
    mpz_inits(n, e, d, NULL);

    generate_keys(n, e, d);
    vector<uint8_t> input = {};

    cout << "Original (0 bytes): <empty>" << endl;
    vector<uint8_t> encrypted = encrypt_buffer(input, e, n);
    cout << "Encrypted (" << encrypted.size() << " bytes): ";
    print_hex(encrypted);

    vector<uint8_t> decrypted = decrypt_buffer(encrypted, d, n);
    cout << "Decrypted (" << decrypted.size() << " bytes): ";
    print_hex(decrypted);

    assert(input == decrypted);
    cout << "✅ Success: Empty buffer test passed!" << endl;

    mpz_clears(n, e, d, NULL);
}

void test_single_byte() {
    cout << "\n=== Test 2: Single Byte ===" << endl;
    mpz_t n, e, d;
    mpz_inits(n, e, d, NULL);

    generate_keys(n, e, d);
    vector<uint8_t> input = {0x42};

    cout << "Original (1 byte): ";
    print_hex(input);

    vector<uint8_t> encrypted = encrypt_buffer(input, e, n);
    cout << "Encrypted (" << encrypted.size() << " bytes): ";
    print_hex(encrypted);

    vector<uint8_t> decrypted = decrypt_buffer(encrypted, d, n);
    cout << "Decrypted (" << decrypted.size() << " bytes): ";
    print_hex(decrypted);

    assert(input == decrypted);
    cout << "✅ Success: Single byte test passed!" << endl;

    mpz_clears(n, e, d, NULL);
}

void test_small_buffer() {
    cout << "\n=== Test 3: Small Buffer (8 bytes) ===" << endl;
    mpz_t n, e, d;
    mpz_inits(n, e, d, NULL);

    generate_keys(n, e, d);
    vector<uint8_t> input = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    cout << "Original (" << input.size() << " bytes): ";
    print_hex(input);

    vector<uint8_t> encrypted = encrypt_buffer(input, e, n);
    cout << "Encrypted (" << encrypted.size() << " bytes): ";
    print_hex(encrypted);

    vector<uint8_t> decrypted = decrypt_buffer(encrypted, d, n);
    cout << "Decrypted (" << decrypted.size() << " bytes): ";
    print_hex(decrypted);

    assert(input == decrypted);
    cout << "✅ Success: Small buffer test passed!" << endl;

    mpz_clears(n, e, d, NULL);
}

void test_large_buffer() {
    cout << "\n=== Test 4: Large Buffer (100 bytes) ===" << endl;
    mpz_t n, e, d;
    mpz_inits(n, e, d, NULL);

    generate_keys(n, e, d);
    vector<uint8_t> input;
    for (int i = 0; i < 100; i++) {
        input.push_back(i % 256);
    }

    cout << "Original (" << input.size() << " bytes): ";
    print_hex(input);

    vector<uint8_t> encrypted = encrypt_buffer(input, e, n);
    cout << "Encrypted (" << encrypted.size() << " bytes): ";
    print_hex(encrypted);

    vector<uint8_t> decrypted = decrypt_buffer(encrypted, d, n);
    cout << "Decrypted (" << decrypted.size() << " bytes): ";
    print_hex(decrypted);

    assert(input == decrypted);
    cout << "✅ Success: Large buffer test passed!" << endl;

    mpz_clears(n, e, d, NULL);
}

void test_text_data() {
    cout << "\n=== Test 5: Text Data ===" << endl;
    mpz_t n, e, d;
    mpz_inits(n, e, d, NULL);

    generate_keys(n, e, d);
    string text = "Hello, World! This is a test message for RSA encryption.";
    vector<uint8_t> input(text.begin(), text.end());

    cout << "Original (" << input.size() << " bytes): " << text << endl;
    cout << "Original (hex): ";
    print_hex(input);

    vector<uint8_t> encrypted = encrypt_buffer(input, e, n);
    cout << "Encrypted (" << encrypted.size() << " bytes): ";
    print_hex(encrypted);

    vector<uint8_t> decrypted = decrypt_buffer(encrypted, d, n);
    cout << "Decrypted (" << decrypted.size() << " bytes): ";
    print_hex(decrypted);

    string decrypted_text(decrypted.begin(), decrypted.end());
    cout << "Decrypted (text): " << decrypted_text << endl;

    assert(input == decrypted);
    cout << "✅ Success: Text data test passed!" << endl;

    mpz_clears(n, e, d, NULL);
}

void test_random_data() {
    cout << "\n=== Test 6: Random Data ===" << endl;
    mpz_t n, e, d;
    mpz_inits(n, e, d, NULL);

    generate_keys(n, e, d);
    
    // Generate random data
    srand(time(NULL));
    vector<uint8_t> input;
    for (int i = 0; i < 50; i++) {
        input.push_back(rand() % 256);
    }

    cout << "Original (" << input.size() << " bytes): ";
    print_hex(input);

    vector<uint8_t> encrypted = encrypt_buffer(input, e, n);
    cout << "Encrypted (" << encrypted.size() << " bytes): ";
    print_hex(encrypted);

    vector<uint8_t> decrypted = decrypt_buffer(encrypted, d, n);
    cout << "Decrypted (" << decrypted.size() << " bytes): ";
    print_hex(decrypted);

    assert(input == decrypted);
    cout << "✅ Success: Random data test passed!" << endl;

    mpz_clears(n, e, d, NULL);
}

void test_edge_cases() {
    cout << "\n=== Test 7: Edge Cases ===" << endl;
    mpz_t n, e, d;
    mpz_inits(n, e, d, NULL);

    generate_keys(n, e, d);

    // Test case 1: All zeros
    vector<uint8_t> input1(16, 0);
    cout << "Test 7a: All zeros (" << input1.size() << " bytes)" << endl;
    vector<uint8_t> encrypted1 = encrypt_buffer(input1, e, n);
    vector<uint8_t> decrypted1 = decrypt_buffer(encrypted1, d, n);
    assert(input1 == decrypted1);
    cout << "✅ Success: All zeros test passed!" << endl;

    // Test case 2: All ones
    vector<uint8_t> input2(16, 0xFF);
    cout << "Test 7b: All ones (" << input2.size() << " bytes)" << endl;
    vector<uint8_t> encrypted2 = encrypt_buffer(input2, e, n);
    vector<uint8_t> decrypted2 = decrypt_buffer(encrypted2, d, n);
    assert(input2 == decrypted2);
    cout << "✅ Success: All ones test passed!" << endl;

    // Test case 3: Alternating pattern
    vector<uint8_t> input3;
    for (int i = 0; i < 32; i++) {
        input3.push_back(i % 2 == 0 ? 0xAA : 0x55);
    }
    cout << "Test 7c: Alternating pattern (" << input3.size() << " bytes)" << endl;
    vector<uint8_t> encrypted3 = encrypt_buffer(input3, e, n);
    vector<uint8_t> decrypted3 = decrypt_buffer(encrypted3, d, n);
    assert(input3 == decrypted3);
    cout << "✅ Success: Alternating pattern test passed!" << endl;

    mpz_clears(n, e, d, NULL);
}

void test_multiple_keys() {
    cout << "\n=== Test 8: Multiple Key Pairs ===" << endl;
    
    for (int test_num = 1; test_num <= 3; test_num++) {
        cout << "Key pair " << test_num << ":" << endl;
        mpz_t n, e, d;
        mpz_inits(n, e, d, NULL);

        generate_keys(n, e, d);
        vector<uint8_t> input = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};

        vector<uint8_t> encrypted = encrypt_buffer(input, e, n);
        vector<uint8_t> decrypted = decrypt_buffer(encrypted, d, n);

        assert(input == decrypted);
        cout << "✅ Success: Key pair " << test_num << " test passed!" << endl;

        mpz_clears(n, e, d, NULL);
    }
}

void test_many_blocks() {
    cout << "\n=== Test 9: Many Blocks (1000 bytes) ===" << endl;
    mpz_t n, e, d;
    mpz_inits(n, e, d, NULL);

    generate_keys(n, e, d);
    
    // Create a 1000-byte buffer with a repeating pattern
    vector<uint8_t> input;
    for (int i = 0; i < 1000; i++) {
        input.push_back((i * 7 + 13) % 256);  // Some pattern to make it interesting
    }

    cout << "Original (" << input.size() << " bytes): ";
    // Show first 32 bytes and last 32 bytes
    for (size_t i = 0; i < 32; i++) {
        printf("%02X ", input[i]);
    }
    cout << "... ";
    for (size_t i = input.size() - 32; i < input.size(); i++) {
        printf("%02X ", input[i]);
    }
    cout << endl;

    vector<uint8_t> encrypted = encrypt_buffer(input, e, n);
    cout << "Encrypted (" << encrypted.size() << " bytes): ";
    // Show first 32 bytes and last 32 bytes
    for (size_t i = 0; i < 32; i++) {
        printf("%02X ", encrypted[i]);
    }
    cout << "... ";
    for (size_t i = encrypted.size() - 32; i < encrypted.size(); i++) {
        printf("%02X ", encrypted[i]);
    }
    cout << endl;

    vector<uint8_t> decrypted = decrypt_buffer(encrypted, d, n);
    cout << "Decrypted (" << decrypted.size() << " bytes): ";
    // Show first 32 bytes and last 32 bytes
    for (size_t i = 0; i < 32; i++) {
        printf("%02X ", decrypted[i]);
    }
    cout << "... ";
    for (size_t i = decrypted.size() - 32; i < decrypted.size(); i++) {
        printf("%02X ", decrypted[i]);
    }
    cout << endl;

    assert(input == decrypted);
    cout << "✅ Success: Many blocks test passed!" << endl;

    mpz_clears(n, e, d, NULL);
}

void test_extreme_blocks() {
    cout << "\n=== Test 10: Extreme Blocks (5000 bytes) ===" << endl;
    mpz_t n, e, d;
    mpz_inits(n, e, d, NULL);

    generate_keys(n, e, d);
    
    // Create a 5000-byte buffer with a more complex pattern
    vector<uint8_t> input;
    for (int i = 0; i < 5000; i++) {
        // Create a more complex pattern: Fibonacci-like sequence mod 256
        uint8_t val = (i * i * 7 + i * 13 + 17) % 256;
        input.push_back(val);
    }

    cout << "Original (" << input.size() << " bytes): ";
    // Show first 16 bytes and last 16 bytes
    for (size_t i = 0; i < 16; i++) {
        printf("%02X ", input[i]);
    }
    cout << "... ";
    for (size_t i = input.size() - 16; i < input.size(); i++) {
        printf("%02X ", input[i]);
    }
    cout << endl;

    vector<uint8_t> encrypted = encrypt_buffer(input, e, n);
    cout << "Encrypted (" << encrypted.size() << " bytes): ";
    // Show first 16 bytes and last 16 bytes
    for (size_t i = 0; i < 16; i++) {
        printf("%02X ", encrypted[i]);
    }
    cout << "... ";
    for (size_t i = encrypted.size() - 16; i < encrypted.size(); i++) {
        printf("%02X ", encrypted[i]);
    }
    cout << endl;

    vector<uint8_t> decrypted = decrypt_buffer(encrypted, d, n);
    cout << "Decrypted (" << decrypted.size() << " bytes): ";
    // Show first 16 bytes and last 16 bytes
    for (size_t i = 0; i < 16; i++) {
        printf("%02X ", decrypted[i]);
    }
    cout << "... ";
    for (size_t i = decrypted.size() - 16; i < decrypted.size(); i++) {
        printf("%02X ", decrypted[i]);
    }
    cout << endl;

    assert(input == decrypted);
    cout << "✅ Success: Extreme blocks test passed!" << endl;

    mpz_clears(n, e, d, NULL);
}

void test_rsa_binary_buffer() {
    cout << "\n=== Test 11: Original Test Case ===" << endl;
    mpz_t n, e, d;
    mpz_inits(n, e, d, NULL);

    cout << "Generating RSA keys..." << endl;
    generate_keys(n, e, d);

    vector<uint8_t> input = {
        0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0xCC, 0xDD, 0xEE, 0xFF, 0x10, 0x20, 0x30, 0x40
    };

    cout << "Original (" << input.size() << " bytes): ";
    print_hex(input);

    vector<uint8_t> encrypted = encrypt_buffer(input, e, n);
    cout << "Encrypted (" << encrypted.size() << " bytes): ";
    print_hex(encrypted);

    vector<uint8_t> decrypted = decrypt_buffer(encrypted, d, n);
    cout << "Decrypted (" << decrypted.size() << " bytes): ";
    print_hex(decrypted);

    assert(input == decrypted);
    cout << "✅ Success: Original test case passed!" << endl;

    mpz_clears(n, e, d, NULL);
}

// === Main ===

int main() {
    cout << "RSA Encryption/Decryption Test Suite" << endl;
    cout << "=====================================" << endl;
    
    try {
        test_empty_buffer();
        test_single_byte();
        test_small_buffer();
        test_large_buffer();
        test_text_data();
        test_random_data();
        test_edge_cases();
        test_multiple_keys();
        test_many_blocks();
        test_extreme_blocks();
        test_rsa_binary_buffer();
        
        cout << "\n🎉 All tests passed successfully!" << endl;
        cout << "RSA implementation is working correctly." << endl;
        
    } catch (const exception& e) {
        cerr << "❌ Test failed with exception: " << e.what() << endl;
        return 1;
    } catch (...) {
        cerr << "❌ Test failed with unknown exception" << endl;
        return 1;
    }
    
    return 0;
}
