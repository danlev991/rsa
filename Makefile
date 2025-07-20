# Makefile for RSA encryption program

# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -std=c++11 -Wall -Wextra -O2

# Libraries
LIBS = -lgmp

# Target executables
CLAUDE_TARGET = claude_rsa
CHATGPT_TARGET = chatgpt_rsa

# Source files
CLAUDE_SOURCES = claude.cpp
CHATGPT_SOURCES = chatgpt.cpp

# Object files
CLAUDE_OBJECTS = $(CLAUDE_SOURCES:.cpp=.o)
CHATGPT_OBJECTS = $(CHATGPT_SOURCES:.cpp=.o)

# Default target
all: $(CLAUDE_TARGET) $(CHATGPT_TARGET)

# Build Claude RSA executable
$(CLAUDE_TARGET): $(CLAUDE_OBJECTS)
	$(CXX) $(CLAUDE_OBJECTS) -o $(CLAUDE_TARGET) $(LIBS)

# Build ChatGPT RSA executable
$(CHATGPT_TARGET): $(CHATGPT_OBJECTS)
	$(CXX) $(CHATGPT_OBJECTS) -o $(CHATGPT_TARGET) $(LIBS)

# Compile source files to object files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(CLAUDE_OBJECTS) $(CHATGPT_OBJECTS) $(CLAUDE_TARGET) $(CHATGPT_TARGET)

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

# Build individual targets
claude: $(CLAUDE_TARGET)

chatgpt: $(CHATGPT_TARGET)

# Show help
help:
	@echo "Available targets:"
	@echo "  all          - Build both RSA programs (default)"
	@echo "  claude       - Build Claude RSA program only"
	@echo "  chatgpt      - Build ChatGPT RSA program only"
	@echo "  run-claude   - Build and run Claude RSA program"
	@echo "  run-chatgpt  - Build and run ChatGPT RSA program"
	@echo "  clean        - Remove build artifacts"
	@echo "  install-deps - Install GMP library (Ubuntu/Debian)"
	@echo "  install-deps-rpm - Install GMP library (CentOS/RHEL/Fedora)"
	@echo "  install-deps-mac - Install GMP library (macOS)"
	@echo "  help         - Show this help message"

.PHONY: all clean install-deps install-deps-rpm install-deps-mac run-claude run-chatgpt claude chatgpt help 