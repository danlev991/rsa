#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <random>
#include <ctime>

// Include CPU and GPU RSA implementations
#include "claude.cpp"   // For class RSA
#include "claude_cuda.cu" // For class CudaRSA

void print_hex(const std::vector<unsigned char>& data, const std::string& label = "", size_t max_bytes = 64) {
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

void test_vector(const std::vector<unsigned char>& input, const std::string& label) {
    std::cout << "\n=== Test: " << label << " ===" << std::endl;
    // CPU
    RSA cpu_rsa(1024);
    // GPU
    CudaRSA gpu_rsa(1024);

    // Encrypt
    std::vector<unsigned char> cpu_encrypted = cpu_rsa.encrypt(input.data(), input.size());
    std::vector<unsigned char> gpu_encrypted = gpu_rsa.encrypt(input.data(), input.size());

    // Decrypt
    std::vector<unsigned char> cpu_decrypted = cpu_rsa.decrypt(cpu_encrypted);
    std::vector<unsigned char> gpu_decrypted = gpu_rsa.decrypt(gpu_encrypted);

    // Print
    print_hex(input, "Original", 32);
    print_hex(cpu_encrypted, "CPU Encrypted", 32);
    print_hex(gpu_encrypted, "GPU Encrypted", 32);
    print_hex(cpu_decrypted, "CPU Decrypted", 32);
    print_hex(gpu_decrypted, "GPU Decrypted", 32);

    // Check
    if (input == cpu_decrypted) std::cout << "CPU: ✅ Decrypt matches input\n";
    else std::cout << "CPU: ❌ Decrypt does not match input!\n";
    if (input == gpu_decrypted) std::cout << "GPU: ✅ Decrypt matches input\n";
    else std::cout << "GPU: ❌ Decrypt does not match input!\n";
    if (cpu_encrypted != gpu_encrypted) std::cout << "Note: CPU and GPU ciphertexts may differ (different keys).\n";
    if (cpu_decrypted == gpu_decrypted && input == cpu_decrypted)
        std::cout << "Both: ✅ CPU and GPU outputs match and are correct!\n";
    else if (cpu_decrypted != gpu_decrypted)
        std::cout << "Both: ❌ CPU and GPU decrypted outputs differ!\n";
}

void test_cpu_gpu_interop() {
    std::cout << "\n=== Interop: CPU key, GPU encrypt, CPU decrypt ===" << std::endl;
    RSA cpu_rsa(1024);
    // Export public key
    auto n = cpu_rsa.export_n();
    auto e = cpu_rsa.export_e();
    // Import public key into GPU
    CudaRSA gpu_rsa(n, e, {}, 1024);
    // Test message
    std::string msg = "Interop test: CPU key, GPU encrypt, CPU decrypt!";
    std::vector<unsigned char> input(msg.begin(), msg.end());
    // Encrypt on GPU
    auto encrypted = gpu_rsa.encrypt(input.data(), input.size());
    // Decrypt on CPU
    auto decrypted = cpu_rsa.decrypt(encrypted);
    std::string decrypted_str(decrypted.begin(), decrypted.end());
    std::cout << "Original: " << msg << std::endl;
    std::cout << "Decrypted: " << decrypted_str << std::endl;
    if (input == decrypted) std::cout << "✅ Interop success!" << std::endl;
    else std::cout << "❌ Interop failed!" << std::endl;
}

void test_gpu_cpu_interop() {
    std::cout << "\n=== Interop: GPU key, CPU encrypt, GPU decrypt ===" << std::endl;
    CudaRSA gpu_rsa(1024);
    // Export public key
    auto n = gpu_rsa.export_n();
    auto e = gpu_rsa.export_e();
    // Import public key into CPU
    RSA cpu_rsa(n, e, {}, 1024);
    // Test message
    std::string msg = "Interop test: GPU key, CPU encrypt, GPU decrypt!";
    std::vector<unsigned char> input(msg.begin(), msg.end());
    // Encrypt on CPU
    auto encrypted = cpu_rsa.encrypt(input.data(), input.size());
    // Decrypt on GPU
    auto decrypted = gpu_rsa.decrypt(encrypted);
    std::string decrypted_str(decrypted.begin(), decrypted.end());
    std::cout << "Original: " << msg << std::endl;
    std::cout << "Decrypted: " << decrypted_str << std::endl;
    if (input == decrypted) std::cout << "✅ Interop success!" << std::endl;
    else std::cout << "❌ Interop failed!" << std::endl;
}

int main() {
    try {
        std::cout << "Unified RSA CPU/GPU Test Suite" << std::endl;
        std::cout << "==============================" << std::endl;

        // Test vectors
        test_vector({}, "Empty buffer");
        test_vector({0x42}, "Single byte");
        test_vector({0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08}, "Small buffer (8 bytes)");
        std::vector<unsigned char> large(100);
        for (int i = 0; i < 100; i++) large[i] = i % 256;
        test_vector(large, "Large buffer (100 bytes)");
        std::string text = "Hello, World! This is a test message for RSA encryption.";
        test_vector(std::vector<unsigned char>(text.begin(), text.end()), "Text data");
        std::vector<unsigned char> random_data(50);
        std::srand(std::time(nullptr));
        for (int i = 0; i < 50; i++) random_data[i] = std::rand() % 256;
        test_vector(random_data, "Random data (50 bytes)");
        // Edge cases
        test_vector(std::vector<unsigned char>(16, 0), "All zeros (16 bytes)");
        test_vector(std::vector<unsigned char>(16, 0xFF), "All ones (16 bytes)");
        std::vector<unsigned char> alt(32);
        for (int i = 0; i < 32; i++) alt[i] = (i % 2 == 0 ? 0xAA : 0x55);
        test_vector(alt, "Alternating pattern (32 bytes)");
        // Many blocks
        std::vector<unsigned char> many_blocks(1000);
        for (int i = 0; i < 1000; i++) many_blocks[i] = (i * 7 + 13) % 256;
        test_vector(many_blocks, "Many blocks (1000 bytes)");
        // Extreme blocks
        std::vector<unsigned char> extreme(5000);
        for (int i = 0; i < 5000; i++) extreme[i] = (i * i * 7 + i * 13 + 17) % 256;
        test_vector(extreme, "Extreme blocks (5000 bytes)");
        // Original test case
        std::vector<unsigned char> orig = {
            0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
            0xCC, 0xDD, 0xEE, 0xFF, 0x10, 0x20, 0x30, 0x40
        };
        test_vector(orig, "Original test case (24 bytes)");
        // Interop tests
        test_cpu_gpu_interop();
        test_gpu_cpu_interop();
        std::cout << "\n🎉 All unified tests completed!" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
} 