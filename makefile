# Compilador
CXX = g++

# Bibliotecas
LIBS = -lssl -lcrypto -lsecp256k1 -fopenmp

# Flags de CPU avançadas
CPU_FLAGS = \
    -march=native \
    -mtune=native \
    -msha \
    -msse4.2 \
    -maes \
    # -mavx \
    # -mavx2 \
    # -mbmi2 \
    # -mpclmul \
    # -mpopcnt \
    # -madx \
    # -mrdrnd \
    # -mabm

# Flags de otimização específicas para criptografia
CRYPTO_FLAGS = \
    -O3 \
    # -fno-plt \
    # -fprefetch-loop-arrays \
    # -funroll-all-loops \
    # -fpeel-loops \
    # -ftracer

# Flags de performance para operações matemáticas e memória
PERFORMANCE_FLAGS = \
    -ffast-math \
    -funroll-loops \
    -fomit-frame-pointer \
    # -ftree-vectorize \
    # -fmerge-all-constants \
    # -fno-schedule-insns \
    # -fno-trapping-math \
    # -finline-functions \
    # -freorder-blocks-algorithm=stc \
    # -fcaller-saves \
    # -fcode-hoisting \
    # -pipe

# Link Time Optimization
LTO_FLAGS = -flto=auto -fuse-linker-plugin

# Combinação de todas as flags
CXXFLAGS = $(CPU_FLAGS) $(CRYPTO_FLAGS) $(PERFORMANCE_FLAGS) $(LTO_FLAGS)

# Arquivos fonte e destino
TARGET = challenge
SRC = challenge.cpp

# Alvo principal
all: release

# Build otimizado
release:
	$(CXX) -o $(TARGET) $(SRC) $(CXXFLAGS) -w $(LIBS)
	@echo "Done!"

# Build para debug
debug:
	$(CXX) -o $(TARGET)_debug $(SRC) -g -O0 -Wall -Wextra $(LIBS)

# Limpar
clean:
	rm -f $(TARGET) $(TARGET)_debug

.PHONY: all release debug clean