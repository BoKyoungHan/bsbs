hdump: hdump.o
	ld -o hdump hdump.o
hdump.o: hdump.asm
	nasm -f elf32 -g -F dwarf hdump.asm 
