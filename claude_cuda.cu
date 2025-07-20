#include <cuda_runtime.h>
#include <cgbn/cgbn.h>
#include <curand_kernel.h>
#include <iostream>
#include <vector>
#include <random>
#include <cstring>

// CGBN context parameters - 2048-bit numbers
#define BITS 2048
#define TPI 32  // Threads per instance
#define INSTANCES (1024/TPI)  // Number of instances per thread block

// CGBN environment
typedef cgbn_context_t<TPI>         context_t;
typedef cgbn_env_t<context_t, BITS> env_t;
typedef typename env_t::cgbn_t      bn_t;

// CUDA error checking macro
#define CUDA_CHECK(call) \
    do { \
        cudaError_t err = call; \
        if (err != cudaSuccess) { \
            std::cerr << "CUDA error at " << __FILE__ << ":" << __LINE__ << " - " << cudaGetErrorString(err) << std::endl; \
            exit(1); \
        } \
    } while(0)

// CGBN error checking macro
#define CGBN_CHECK(report) \
    do { \
        if(cgbn_error_report_check(report)) { \
            std::cerr << "CGBN error" << std::endl; \
            exit(1); \
        } \
    } while(0)

// Structure to hold RSA key parameters
struct RSAParams {
    bn_t n;  // modulus
    bn_t e;  // public exponent
    bn_t d;  // private exponent
};

// Kernel for RSA encryption: c = m^e mod n
__global__ void rsa_encrypt_kernel(
    cgbn_error_report_t *report,
    RSAParams *params,
    uint32_t *messages,
    uint32_t *ciphertexts,
    uint32_t *message_lengths,
    uint32_t num_messages,
    uint32_t words_per_message
) {
    context_t      bn_context(cgbn_report_monitor, report, (uint32_t)blockIdx.x);
    env_t          bn_env(bn_context);
    bn_t           message, ciphertext;
    
    int32_t instance = (blockIdx.x * blockDim.x + threadIdx.x) / TPI;
    
    if(instance >= num_messages) return;
    
    // Load message from global memory
    cgbn_load(bn_env, message, &messages[instance * words_per_message]);
    
    // Perform modular exponentiation: c = m^e mod n
    cgbn_modular_power(bn_env, ciphertext, message, params->e, params->n);
    
    // Store result to global memory
    cgbn_store(bn_env, &ciphertexts[instance * words_per_message], ciphertext);
}

// Kernel for RSA decryption: m = c^d mod n
__global__ void rsa_decrypt_kernel(
    cgbn_error_report_t *report,
    RSAParams *params,
    uint32_t *ciphertexts,
    uint32_t *messages,
    uint32_t num_messages,
    uint32_t words_per_message
) {
    context_t      bn_context(cgbn_report_monitor, report, (uint32_t)blockIdx.x);
    env_t          bn_env(bn_context);
    bn_t           ciphertext, message;
    
    int32_t instance = (blockIdx.x * blockDim.x + threadIdx.x) / TPI;
    
    if(instance >= num_messages) return;
    
    // Load ciphertext from global memory
    cgbn_load(bn_env, ciphertext, &ciphertexts[instance * words_per_message]);
    
    // Perform modular exponentiation: m = c^d mod n
    cgbn_modular_power(bn_env, message, ciphertext, params->d, params->n);
    
    // Store result to global memory
    cgbn_store(bn_env, &messages[instance * words_per_message], message);
}

// Host-side key generation kernel
__global__ void generate_keys_kernel(
    cgbn_error_report_t *report,
    RSAParams *params,
    uint32_t *p_data,
    uint32_t *q_data,
    uint32_t words_per_number
) {
    context_t bn_context(cgbn_report_monitor, report, 0);
    env_t     bn_env(bn_context);
    bn_t      p, q, phi, temp, gcd_result;
    
    if(blockIdx.x != 0 || threadIdx.x != 0) return;
    
    // Load p and q from global memory
    cgbn_load(bn_env, p, p_data);
    cgbn_load(bn_env, q, q_data);
    
    // Calculate n = p * q
    cgbn_mul(bn_env, params->n, p, q);
    
    // Calculate phi(n) = (p-1) * (q-1)
    cgbn_sub_ui32(bn_env, p, p, 1);
    cgbn_sub_ui32(bn_env, q, q, 1);
    cgbn_mul(bn_env, phi, p, q);
    
    // Set e = 65537
    cgbn_set_ui32(bn_env, params->e, 65537);
    
    // Calculate d = e^(-1) mod phi(n) using extended Euclidean algorithm
    cgbn_modular_inverse(bn_env, params->d, params->e, phi);
}

class CudaRSA {
private:
    RSAParams *d_params;
    cgbn_error_report_t *report;
    size_t key_size;
    size_t block_size;
    size_t encrypted_block_size;
    uint32_t words_per_number;
    
    // Generate prime numbers on CPU (simplified for demonstration)
    void generate_cpu_primes(std::vector<uint32_t>& p_words, std::vector<uint32_t>& q_words) {
        // For demonstration, using small known primes
        // In practice, you'd use a proper prime generation algorithm
        
        // Clear the vectors
        p_words.assign(words_per_number, 0);
        q_words.assign(words_per_number, 0);
        
        // Example primes (in practice, generate large random primes)
        // Using larger numbers for demonstration
        // p = 2^512 + 569 (approximately)
        p_words[16] = 1;  // Set bit 512
        p_words[0] = 569;
        
        // q = 2^512 + 983 (approximately)  
        q_words[16] = 1;  // Set bit 512
        q_words[0] = 983;
    }
    
public:
    // New import constructor
    CudaRSA(const std::vector<unsigned char>& n_bytes,
            const std::vector<unsigned char>& e_bytes,
            const std::vector<unsigned char>& d_bytes = {},
            size_t bits = 2048) : key_size(bits) {
        words_per_number = (bits + 31) / 32;
        CUDA_CHECK(cudaMalloc(&d_params, sizeof(RSAParams)));
        CUDA_CHECK(cudaMalloc(&report, sizeof(cgbn_error_report_t)));
        CUDA_CHECK(cudaMemset(report, 0, sizeof(cgbn_error_report_t)));
        // Prepare host-side RSAParams
        RSAParams h_params;
        memset(&h_params, 0, sizeof(RSAParams));
        // Helper to load bytes into bn_t
        auto bytes_to_bn = [&](bn_t& bn, const std::vector<unsigned char>& bytes) {
            std::vector<uint32_t> words(words_per_number, 0);
            size_t byte_len = bytes.size();
            for (size_t i = 0; i < byte_len; i++) {
                size_t word_idx = i / 4;
                size_t byte_in_word = i % 4;
                if (word_idx < words_per_number)
                    words[word_idx] |= ((uint32_t)bytes[byte_len - 1 - i]) << (byte_in_word * 8);
            }
            context_t ctx(cgbn_report_monitor, nullptr, 0);
            env_t env(ctx);
            cgbn_load(env, bn, words.data());
        };
        bytes_to_bn(h_params.n, n_bytes);
        bytes_to_bn(h_params.e, e_bytes);
        if (!d_bytes.empty()) bytes_to_bn(h_params.d, d_bytes);
        CUDA_CHECK(cudaMemcpy(d_params, &h_params, sizeof(RSAParams), cudaMemcpyHostToDevice));
        block_size = (key_size / 8) - 11;
        encrypted_block_size = (key_size + 7) / 8;
    }
    // Export n as bytes
    std::vector<unsigned char> export_n() const {
        RSAParams h_params;
        CUDA_CHECK(cudaMemcpy(&h_params, d_params, sizeof(RSAParams), cudaMemcpyDeviceToHost));
        std::vector<uint32_t> words(words_per_number);
        context_t ctx(cgbn_report_monitor, nullptr, 0);
        env_t env(ctx);
        cgbn_store(env, words.data(), h_params.n);
        std::vector<unsigned char> bytes(words_per_number * 4);
        for (size_t i = 0; i < words_per_number; i++) {
            bytes[words_per_number * 4 - 1 - i * 4] = (words[i] >> 24) & 0xFF;
            bytes[words_per_number * 4 - 2 - i * 4] = (words[i] >> 16) & 0xFF;
            bytes[words_per_number * 4 - 3 - i * 4] = (words[i] >> 8) & 0xFF;
            bytes[words_per_number * 4 - 4 - i * 4] = (words[i]) & 0xFF;
        }
        // Remove leading zeros
        while (!bytes.empty() && bytes[0] == 0) bytes.erase(bytes.begin());
        return bytes;
    }
    // Export e as bytes
    std::vector<unsigned char> export_e() const {
        RSAParams h_params;
        CUDA_CHECK(cudaMemcpy(&h_params, d_params, sizeof(RSAParams), cudaMemcpyDeviceToHost));
        std::vector<uint32_t> words(words_per_number);
        context_t ctx(cgbn_report_monitor, nullptr, 0);
        env_t env(ctx);
        cgbn_store(env, words.data(), h_params.e);
        std::vector<unsigned char> bytes(words_per_number * 4);
        for (size_t i = 0; i < words_per_number; i++) {
            bytes[words_per_number * 4 - 1 - i * 4] = (words[i] >> 24) & 0xFF;
            bytes[words_per_number * 4 - 2 - i * 4] = (words[i] >> 16) & 0xFF;
            bytes[words_per_number * 4 - 3 - i * 4] = (words[i] >> 8) & 0xFF;
            bytes[words_per_number * 4 - 4 - i * 4] = (words[i]) & 0xFF;
        }
        while (!bytes.empty() && bytes[0] == 0) bytes.erase(bytes.begin());
        return bytes;
    }
    // Export d as bytes
    std::vector<unsigned char> export_d() const {
        RSAParams h_params;
        CUDA_CHECK(cudaMemcpy(&h_params, d_params, sizeof(RSAParams), cudaMemcpyDeviceToHost));
        std::vector<uint32_t> words(words_per_number);
        context_t ctx(cgbn_report_monitor, nullptr, 0);
        env_t env(ctx);
        cgbn_store(env, words.data(), h_params.d);
        std::vector<unsigned char> bytes(words_per_number * 4);
        for (size_t i = 0; i < words_per_number; i++) {
            bytes[words_per_number * 4 - 1 - i * 4] = (words[i] >> 24) & 0xFF;
            bytes[words_per_number * 4 - 2 - i * 4] = (words[i] >> 16) & 0xFF;
            bytes[words_per_number * 4 - 3 - i * 4] = (words[i] >> 8) & 0xFF;
            bytes[words_per_number * 4 - 4 - i * 4] = (words[i]) & 0xFF;
        }
        while (!bytes.empty() && bytes[0] == 0) bytes.erase(bytes.begin());
        return bytes;
    }
    
    CudaRSA(size_t bits = 2048) : key_size(bits) {
        // Calculate words per number (32-bit words)
        words_per_number = (bits + 31) / 32;
        
        // Allocate device memory for parameters
        CUDA_CHECK(cudaMalloc(&d_params, sizeof(RSAParams)));
        CUDA_CHECK(cudaMalloc(&report, sizeof(cgbn_error_report_t)));
        
        // Initialize error report
        CUDA_CHECK(cudaMemset(report, 0, sizeof(cgbn_error_report_t)));
        
        generate_keys();
        
        // Calculate block sizes (leave room for padding)
        block_size = (key_size / 8) - 11;
        encrypted_block_size = (key_size + 7) / 8;
        
        std::cout << "CGBN RSA initialized:" << std::endl;
        std::cout << "Key size: " << key_size << " bits" << std::endl;
        std::cout << "Block size: " << block_size << " bytes" << std::endl;
        std::cout << "Encrypted block size: " << encrypted_block_size << " bytes" << std::endl;
        std::cout << "Words per number: " << words_per_number << std::endl;
    }
    
    ~CudaRSA() {
        CUDA_CHECK(cudaFree(d_params));
        CUDA_CHECK(cudaFree(report));
    }
    
    void generate_keys() {
        std::cout << "Generating RSA keys using CGBN..." << std::endl;
        
        // Generate primes on CPU
        std::vector<uint32_t> p_words(words_per_number, 0);
        std::vector<uint32_t> q_words(words_per_number, 0);
        generate_cpu_primes(p_words, q_words);
        
        // Allocate device memory for primes
        uint32_t *d_p, *d_q;
        CUDA_CHECK(cudaMalloc(&d_p, words_per_number * sizeof(uint32_t)));
        CUDA_CHECK(cudaMalloc(&d_q, words_per_number * sizeof(uint32_t)));
        
        // Copy primes to device
        CUDA_CHECK(cudaMemcpy(d_p, p_words.data(), 
                             words_per_number * sizeof(uint32_t), cudaMemcpyHostToDevice));
        CUDA_CHECK(cudaMemcpy(d_q, q_words.data(), 
                             words_per_number * sizeof(uint32_t), cudaMemcpyHostToDevice));
        
        // Generate keys on GPU
        generate_keys_kernel<<<1, TPI>>>(report, d_params, d_p, d_q, words_per_number);
        
        CUDA_CHECK(cudaDeviceSynchronize());
        CGBN_CHECK(report);
        
        // Clean up
        CUDA_CHECK(cudaFree(d_p));
        CUDA_CHECK(cudaFree(d_q));
        
        std::cout << "Keys generated successfully!" << std::endl;
    }
    
    std::vector<unsigned char> encrypt(const unsigned char* data, size_t data_len) {
        // Calculate number of blocks needed
        size_t num_blocks = (data_len + block_size - 1) / block_size;
        size_t output_size = 4 + num_blocks * encrypted_block_size;  // 4 bytes for length prefix
        
        // Prepare input data - pad each block to words_per_number
        std::vector<uint32_t> input_words(num_blocks * words_per_number, 0);
        std::vector<uint32_t> message_lengths(num_blocks);
        
        for (size_t i = 0; i < num_blocks; i++) {
            size_t current_block_size = std::min(block_size, data_len - i * block_size);
            message_lengths[i] = current_block_size;
            
            // Convert bytes to words (little-endian)
            for (size_t j = 0; j < current_block_size; j++) {
                size_t byte_idx = i * block_size + j;
                size_t word_idx = i * words_per_number + j / 4;
                size_t byte_in_word = j % 4;
                
                input_words[word_idx] |= ((uint32_t)data[byte_idx] << (byte_in_word * 8));
            }
        }
        
        // Allocate device memory
        uint32_t *d_input, *d_output, *d_lengths;
        CUDA_CHECK(cudaMalloc(&d_input, num_blocks * words_per_number * sizeof(uint32_t)));
        CUDA_CHECK(cudaMalloc(&d_output, num_blocks * words_per_number * sizeof(uint32_t)));
        CUDA_CHECK(cudaMalloc(&d_lengths, num_blocks * sizeof(uint32_t)));
        
        // Copy data to device
        CUDA_CHECK(cudaMemcpy(d_input, input_words.data(), 
                             num_blocks * words_per_number * sizeof(uint32_t), cudaMemcpyHostToDevice));
        CUDA_CHECK(cudaMemcpy(d_lengths, message_lengths.data(), 
                             num_blocks * sizeof(uint32_t), cudaMemcpyHostToDevice));
        
        // Launch encryption kernel
        uint32_t blocks_per_grid = (num_blocks * TPI + 1023) / 1024;
        uint32_t threads_per_block = 1024;
        
        rsa_encrypt_kernel<<<blocks_per_grid, threads_per_block>>>(
            report, d_params, d_input, d_output, d_lengths, num_blocks, words_per_number
        );
        
        CUDA_CHECK(cudaDeviceSynchronize());
        CGBN_CHECK(report);
        
        // Copy results back
        std::vector<uint32_t> output_words(num_blocks * words_per_number);
        CUDA_CHECK(cudaMemcpy(output_words.data(), d_output, 
                             num_blocks * words_per_number * sizeof(uint32_t), cudaMemcpyDeviceToHost));
        
        // Convert to byte format
        std::vector<unsigned char> result(output_size);
        
        // Store original length in first 4 bytes
        result[0] = (data_len >> 24) & 0xFF;
        result[1] = (data_len >> 16) & 0xFF;
        result[2] = (data_len >> 8) & 0xFF;
        result[3] = data_len & 0xFF;
        
        // Convert words back to bytes
        for (size_t i = 0; i < num_blocks; i++) {
            size_t result_offset = 4 + i * encrypted_block_size;
            
            for (size_t j = 0; j < encrypted_block_size && j < words_per_number * 4; j++) {
                size_t word_idx = i * words_per_number + j / 4;
                size_t byte_in_word = j % 4;
                result[result_offset + j] = (output_words[word_idx] >> (byte_in_word * 8)) & 0xFF;
            }
        }
        
        // Clean up
        CUDA_CHECK(cudaFree(d_input));
        CUDA_CHECK(cudaFree(d_output));
        CUDA_CHECK(cudaFree(d_lengths));
        
        return result;
    }
    
    std::vector<unsigned char> encrypt(const std::string& message) {
        return encrypt(reinterpret_cast<const unsigned char*>(message.c_str()), message.length());
    }
    
    std::vector<unsigned char> decrypt(const unsigned char* encrypted_data, size_t encrypted_len) {
        if (encrypted_len < 4) {
            throw std::runtime_error("Invalid encrypted data - too short");
        }
        
        // Extract original data length
        size_t original_len = ((size_t)encrypted_data[0] << 24) |
                             ((size_t)encrypted_data[1] << 16) |
                             ((size_t)encrypted_data[2] << 8) |
                             ((size_t)encrypted_data[3]);
        
        size_t encrypted_data_len = encrypted_len - 4;
        if (encrypted_data_len % encrypted_block_size != 0) {
            throw std::runtime_error("Invalid encrypted data length");
        }
        
        size_t num_blocks = encrypted_data_len / encrypted_block_size;
        
        // Convert encrypted data to words
        std::vector<uint32_t> input_words(num_blocks * words_per_number, 0);
        
        for (size_t i = 0; i < num_blocks; i++) {
            size_t data_offset = 4 + i * encrypted_block_size;  // Skip length prefix
            
            for (size_t j = 0; j < encrypted_block_size && j < words_per_number * 4; j++) {
                size_t word_idx = i * words_per_number + j / 4;
                size_t byte_in_word = j % 4;
                input_words[word_idx] |= ((uint32_t)encrypted_data[data_offset + j] << (byte_in_word * 8));
            }
        }
        
        // Allocate device memory
        uint32_t *d_input, *d_output;
        CUDA_CHECK(cudaMalloc(&d_input, num_blocks * words_per_number * sizeof(uint32_t)));
        CUDA_CHECK(cudaMalloc(&d_output, num_blocks * words_per_number * sizeof(uint32_t)));
        
        // Copy data to device
        CUDA_CHECK(cudaMemcpy(d_input, input_words.data(), 
                             num_blocks * words_per_number * sizeof(uint32_t), cudaMemcpyHostToDevice));
        
        // Launch decryption kernel
        uint32_t blocks_per_grid = (num_blocks * TPI + 1023) / 1024;
        uint32_t threads_per_block = 1024;
        
        rsa_decrypt_kernel<<<blocks_per_grid, threads_per_block>>>(
            report, d_params, d_input, d_output, num_blocks, words_per_number
        );
        
        CUDA_CHECK(cudaDeviceSynchronize());
        CGBN_CHECK(report);
        
        // Copy results back
        std::vector<uint32_t> output_words(num_blocks * words_per_number);
        CUDA_CHECK(cudaMemcpy(output_words.data(), d_output, 
                             num_blocks * words_per_number * sizeof(uint32_t), cudaMemcpyDeviceToHost));
        
        // Convert words back to bytes
        std::vector<unsigned char> result(original_len);
        size_t result_idx = 0;
        
        for (size_t i = 0; i < num_blocks && result_idx < original_len; i++) {
            size_t remaining = original_len - result_idx;
            size_t current_block_size = std::min(block_size, remaining);
            
            for (size_t j = 0; j < current_block_size; j++) {
                size_t word_idx = i * words_per_number + j / 4;
                size_t byte_in_word = j % 4;
                result[result_idx++] = (output_words[word_idx] >> (byte_in_word * 8)) & 0xFF;
            }
        }
        
        // Clean up
        CUDA_CHECK(cudaFree(d_input));
        CUDA_CHECK(cudaFree(d_output));
        
        return result;
    }
    
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& encrypted_data) {
        return decrypt(encrypted_data.data(), encrypted_data.size());
    }
    
    void print_keys() {
        // For demonstration - in practice you'd copy keys back from GPU
        std::cout << "\nRSA keys generated using CGBN library" << std::endl;
        std::cout << "Key size: " << key_size << " bits" << std::endl;
        std::cout << "Public exponent: 65537" << std::endl;
    }
};

// Helper function to print binary data as hex
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

void test_large_buffer() {
    std::cout << "\n=== Test 4: Large Buffer (100 bytes) ===" << std::endl;
    CudaRSA rsa(1024);
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
    if (input == decrypted) std::cout << "✅ Success: Large buffer test passed!" << std::endl;
    else std::cout << "❌ Failure: Large buffer test failed!" << std::endl;
}

void test_empty_buffer() {
    std::cout << "\n=== Test 5: Empty Buffer ===" << std::endl;
    CudaRSA rsa(1024);
    std::vector<unsigned char> input = {};
    std::cout << "Original (0 bytes): <empty>" << std::endl;
    std::vector<unsigned char> encrypted = rsa.encrypt(input.data(), input.size());
    std::cout << "Encrypted (" << encrypted.size() << " bytes): ";
    print_hex(encrypted, "", 32);
    std::vector<unsigned char> decrypted = rsa.decrypt(encrypted);
    std::cout << "Decrypted (" << decrypted.size() << " bytes): ";
    print_hex(decrypted, "", 32);
    if (input == decrypted) std::cout << "✅ Success: Empty buffer test passed!" << std::endl;
    else std::cout << "❌ Failure: Empty buffer test failed!" << std::endl;
}

void test_single_byte() {
    std::cout << "\n=== Test 6: Single Byte ===" << std::endl;
    CudaRSA rsa(1024);
    std::vector<unsigned char> input = {0x42};
    std::cout << "Original (1 byte): ";
    print_hex(input, "", 32);
    std::vector<unsigned char> encrypted = rsa.encrypt(input.data(), input.size());
    std::cout << "Encrypted (" << encrypted.size() << " bytes): ";
    print_hex(encrypted, "", 32);
    std::vector<unsigned char> decrypted = rsa.decrypt(encrypted);
    std::cout << "Decrypted (" << decrypted.size() << " bytes): ";
    print_hex(decrypted, "", 32);
    if (input == decrypted) std::cout << "✅ Success: Single byte test passed!" << std::endl;
    else std::cout << "❌ Failure: Single byte test failed!" << std::endl;
}

void test_small_buffer() {
    std::cout << "\n=== Test 7: Small Buffer (8 bytes) ===" << std::endl;
    CudaRSA rsa(1024);
    std::vector<unsigned char> input = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    std::cout << "Original (" << input.size() << " bytes): ";
    print_hex(input, "", 32);
    std::vector<unsigned char> encrypted = rsa.encrypt(input.data(), input.size());
    std::cout << "Encrypted (" << encrypted.size() << " bytes): ";
    print_hex(encrypted, "", 32);
    std::vector<unsigned char> decrypted = rsa.decrypt(encrypted);
    std::cout << "Decrypted (" << decrypted.size() << " bytes): ";
    print_hex(decrypted, "", 32);
    if (input == decrypted) std::cout << "✅ Success: Small buffer test passed!" << std::endl;
    else std::cout << "❌ Failure: Small buffer test failed!" << std::endl;
}

void test_text_data() {
    std::cout << "\n=== Test 8: Text Data ===" << std::endl;
    CudaRSA rsa(1024);
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
    if (input == decrypted) std::cout << "✅ Success: Text data test passed!" << std::endl;
    else std::cout << "❌ Failure: Text data test failed!" << std::endl;
}

void test_random_data() {
    std::cout << "\n=== Test 9: Random Data ===" << std::endl;
    CudaRSA rsa(1024);
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
    if (input == decrypted) std::cout << "✅ Success: Random data test passed!" << std::endl;
    else std::cout << "❌ Failure: Random data test failed!" << std::endl;
}

void test_edge_cases() {
    std::cout << "\n=== Test 10: Edge Cases ===" << std::endl;
    CudaRSA rsa(1024);
    // All zeros
    std::vector<unsigned char> input1(16, 0);
    std::cout << "Test 10a: All zeros (" << input1.size() << " bytes)" << std::endl;
    std::vector<unsigned char> encrypted1 = rsa.encrypt(input1.data(), input1.size());
    std::vector<unsigned char> decrypted1 = rsa.decrypt(encrypted1);
    if (input1 == decrypted1) std::cout << "✅ Success: All zeros test passed!" << std::endl;
    else std::cout << "❌ Failure: All zeros test failed!" << std::endl;
    // All ones
    std::vector<unsigned char> input2(16, 0xFF);
    std::cout << "Test 10b: All ones (" << input2.size() << " bytes)" << std::endl;
    std::vector<unsigned char> encrypted2 = rsa.encrypt(input2.data(), input2.size());
    std::vector<unsigned char> decrypted2 = rsa.decrypt(encrypted2);
    if (input2 == decrypted2) std::cout << "✅ Success: All ones test passed!" << std::endl;
    else std::cout << "❌ Failure: All ones test failed!" << std::endl;
    // Alternating pattern
    std::vector<unsigned char> input3;
    for (int i = 0; i < 32; i++) {
        input3.push_back(i % 2 == 0 ? 0xAA : 0x55);
    }
    std::cout << "Test 10c: Alternating pattern (" << input3.size() << " bytes)" << std::endl;
    std::vector<unsigned char> encrypted3 = rsa.encrypt(input3.data(), input3.size());
    std::vector<unsigned char> decrypted3 = rsa.decrypt(encrypted3);
    if (input3 == decrypted3) std::cout << "✅ Success: Alternating pattern test passed!" << std::endl;
    else std::cout << "❌ Failure: Alternating pattern test failed!" << std::endl;
}

void test_multiple_keys() {
    std::cout << "\n=== Test 11: Multiple Key Pairs ===" << std::endl;
    for (int test_num = 1; test_num <= 3; test_num++) {
        std::cout << "Key pair " << test_num << ":" << std::endl;
        CudaRSA rsa(1024);
        std::vector<unsigned char> input = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
        std::vector<unsigned char> encrypted = rsa.encrypt(input.data(), input.size());
        std::vector<unsigned char> decrypted = rsa.decrypt(encrypted);
        if (input == decrypted) std::cout << "✅ Success: Key pair " << test_num << " test passed!" << std::endl;
        else std::cout << "❌ Failure: Key pair " << test_num << " test failed!" << std::endl;
    }
}

void test_many_blocks() {
    std::cout << "\n=== Test 12: Many Blocks (1000 bytes) ===" << std::endl;
    CudaRSA rsa(1024);
    std::vector<unsigned char> input;
    for (int i = 0; i < 1000; i++) {
        input.push_back((i * 7 + 13) % 256);
    }
    std::cout << "Original (" << input.size() << " bytes): ";
    for (size_t i = 0; i < 32; i++) printf("%02X ", input[i]);
    std::cout << "... ";
    for (size_t i = input.size() - 32; i < input.size(); i++) printf("%02X ", input[i]);
    std::cout << std::endl;
    std::vector<unsigned char> encrypted = rsa.encrypt(input.data(), input.size());
    std::cout << "Encrypted (" << encrypted.size() << " bytes): ";
    for (size_t i = 0; i < 32; i++) printf("%02X ", encrypted[i]);
    std::cout << "... ";
    for (size_t i = encrypted.size() - 32; i < encrypted.size(); i++) printf("%02X ", encrypted[i]);
    std::cout << std::endl;
    std::vector<unsigned char> decrypted = rsa.decrypt(encrypted);
    std::cout << "Decrypted (" << decrypted.size() << " bytes): ";
    for (size_t i = 0; i < 32; i++) printf("%02X ", decrypted[i]);
    std::cout << "... ";
    for (size_t i = decrypted.size() - 32; i < decrypted.size(); i++) printf("%02X ", decrypted[i]);
    std::cout << std::endl;
    if (input == decrypted) std::cout << "✅ Success: Many blocks test passed!" << std::endl;
    else std::cout << "❌ Failure: Many blocks test failed!" << std::endl;
}

void test_extreme_blocks() {
    std::cout << "\n=== Test 13: Extreme Blocks (5000 bytes) ===" << std::endl;
    CudaRSA rsa(1024);
    std::vector<unsigned char> input;
    for (int i = 0; i < 5000; i++) {
        unsigned char val = (i * i * 7 + i * 13 + 17) % 256;
        input.push_back(val);
    }
    std::cout << "Original (" << input.size() << " bytes): ";
    for (size_t i = 0; i < 16; i++) printf("%02X ", input[i]);
    std::cout << "... ";
    for (size_t i = input.size() - 16; i < input.size(); i++) printf("%02X ", input[i]);
    std::cout << std::endl;
    std::vector<unsigned char> encrypted = rsa.encrypt(input.data(), input.size());
    std::cout << "Encrypted (" << encrypted.size() << " bytes): ";
    for (size_t i = 0; i < 16; i++) printf("%02X ", encrypted[i]);
    std::cout << "... ";
    for (size_t i = encrypted.size() - 16; i < encrypted.size(); i++) printf("%02X ", encrypted[i]);
    std::cout << std::endl;
    std::vector<unsigned char> decrypted = rsa.decrypt(encrypted);
    std::cout << "Decrypted (" << decrypted.size() << " bytes): ";
    for (size_t i = 0; i < 16; i++) printf("%02X ", decrypted[i]);
    std::cout << "... ";
    for (size_t i = decrypted.size() - 16; i < decrypted.size(); i++) printf("%02X ", decrypted[i]);
    std::cout << std::endl;
    if (input == decrypted) std::cout << "✅ Success: Extreme blocks test passed!" << std::endl;
    else std::cout << "❌ Failure: Extreme blocks test failed!" << std::endl;
}

void test_rsa_binary_buffer() {
    std::cout << "\n=== Test 14: Original Test Case ===" << std::endl;
    CudaRSA rsa(1024);
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
    if (input == decrypted) std::cout << "✅ Success: Original test case passed!" << std::endl;
    else std::cout << "❌ Failure: Original test case failed!" << std::endl;
}

int main() {
    try {
        std::cout << "CGBN RSA Encryption/Decryption Demo" << std::endl;
        CudaRSA rsa(2048);
        std::string message = "Hello, CGBN RSA World!";
        std::cout << "\nOriginal message: " << message << std::endl;
        // Encrypt
        std::cout << "\nEncrypting..." << std::endl;
        auto encrypted = rsa.encrypt(message);
        std::cout << "Encrypted size: " << encrypted.size() << " bytes" << std::endl;
        // Decrypt
        std::cout << "\nDecrypting..." << std::endl;
        auto decrypted = rsa.decrypt(encrypted);
        std::string decrypted_str(decrypted.begin(), decrypted.end());
        std::cout << "Decrypted message: " << decrypted_str << std::endl;
        // Verify
        if (message == decrypted_str) {
            std::cout << "\n✓ Encryption/Decryption successful!" << std::endl;
        } else {
            std::cout << "\n✗ Encryption/Decryption failed!" << std::endl;
        }
        rsa.print_keys();
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
        std::cout << "\n🎉 All CUDA tests completed!" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}