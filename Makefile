# Makefile for RSA encryption program

# Compiler
CXX = g++
NVCC = nvcc

# Compiler flags
CXXFLAGS = -std=c++11 -Wall -Wextra -O2
NVCCFLAGS = -O2 -arch=sm_60 -std=c++11

# Libraries
LIBS = -lgmp

# Target executables
CLAUDE_TARGET = claude_rsa
CHATGPT_TARGET = chatgpt_rsa
CUDA_TARGET = claude_cuda_rsa
BOTH_TARGET = test_rsa_both

# Source files
CLAUDE_SOURCES = claude.cpp
CHATGPT_SOURCES = chatgpt.cpp
CUDA_SOURCES = claude_cuda.cu
BOTH_SOURCES = test_rsa_both.cpp

# Object files
CLAUDE_OBJECTS = $(CLAUDE_SOURCES:.cpp=.o)
CHATGPT_OBJECTS = $(CHATGPT_SOURCES:.cpp=.o)
CUDA_OBJECTS = $(CUDA_SOURCES:.cu=.o)
BOTH_OBJECTS = $(BOTH_SOURCES:.cpp=.o)

# Default target
all: $(CLAUDE_TARGET) $(CHATGPT_TARGET) $(CUDA_TARGET) $(BOTH_TARGET)

# Build Claude RSA executable
$(CLAUDE_TARGET): $(CLAUDE_OBJECTS)
	$(CXX) $(CLAUDE_OBJECTS) -o $(CLAUDE_TARGET) $(LIBS)

# Build ChatGPT RSA executable
$(CHATGPT_TARGET): $(CHATGPT_OBJECTS)
	$(CXX) $(CHATGPT_OBJECTS) -o $(CHATGPT_TARGET) $(LIBS)

# Build CUDA RSA executable
$(CUDA_TARGET): $(CUDA_SOURCES)
	$(NVCC) $(NVCCFLAGS) $^ -o $@ $(LIBS)

# Build unified CPU/GPU test executable
$(BOTH_TARGET): $(BOTH_SOURCES) claude.cpp claude_cuda.cu
	$(NVCC) $(NVCCFLAGS) $^ -o $@ $(LIBS)

# Compile source files to object files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(CLAUDE_OBJECTS) $(CHATGPT_OBJECTS) $(CUDA_OBJECTS) $(BOTH_OBJECTS) \
		$(CLAUDE_TARGET) $(CHATGPT_TARGET) $(CUDA_TARGET) $(BOTH_TARGET)

# Install dependencies (for Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install -y libgmp-dev

# Install dependencies (for CentOS/RHEL/Fedora)
install-deps-rpm:
	sudo yum install -y gmp-devel
	# For Fedora: sudo dnf install -y gmp-devel

# Install dependencies (for macOS with Homebrew)
install-deps-mac:
	brew install gmp

# Run programs
run-claude: $(CLAUDE_TARGET)
	./$(CLAUDE_TARGET)

run-chatgpt: $(CHATGPT_TARGET)
	./$(CHATGPT_TARGET)

run-cuda: $(CUDA_TARGET)
	./$(CUDA_TARGET)

run-both: $(BOTH_TARGET)
	./$(BOTH_TARGET)

# Build individual targets
claude: $(CLAUDE_TARGET)

chatgpt: $(CHATGPT_TARGET)

cuda: $(CUDA_TARGET)

both: $(BOTH_TARGET)

# Show help
help:
	@echo "Available targets:"
	@echo "  all          - Build all RSA programs (default)"
	@echo "  claude       - Build Claude RSA program only"
	@echo "  chatgpt      - Build ChatGPT RSA program only"
	@echo "  cuda         - Build CUDA RSA program only"
	@echo "  both         - Build unified CPU/GPU test"
	@echo "  run-claude   - Build and run Claude RSA program"
	@echo "  run-chatgpt  - Build and run ChatGPT RSA program"
	@echo "  run-cuda     - Build and run CUDA RSA program"
	@echo "  run-both     - Build and run unified CPU/GPU test"
	@echo "  clean        - Remove build artifacts"
	@echo "  install-deps - Install GMP library (Ubuntu/Debian)"
	@echo "  install-deps-rpm - Install GMP library (CentOS/RHEL/Fedora)"
	@echo "  install-deps-mac - Install GMP library (macOS)"
	@echo "  help         - Show this help message"

.PHONY: all clean install-deps install-deps-rpm install-deps-mac run-claude run-chatgpt run-cuda run-both claude chatgpt cuda both help 