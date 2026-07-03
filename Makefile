# Flagi kompilacji i linkowania
ASM = nasm
ASM_FLAGS = -f elf64
LD = ld

# Nazwa pliku wynikowego
TARGET = pszyfr

all: $(TARGET)

$(TARGET): szyfrator.o
	$(LD) -o $(TARGET) szyfrator.o

szyfrator.o: szyfrator.asm
	$(ASM) $(ASM_FLAGS) szyfrator.asm -o szyfrator.o

clean:
	rm -f *.o $(TARGET)

