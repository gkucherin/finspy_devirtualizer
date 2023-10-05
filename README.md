# Devirtualizer for FinSpy VM that I presented at VB2023

**How to Use**
1. Download a FinSpy sample from VXUnderground (https://samples.vx-underground.org/root/APTs/2015/2015.10.15%20-%20Mapping%20FinFisher%E2%80%99s%20Continuing%20Proliferation/Samples/94abf6df38f26530da2864d80e1a0b7cdfce63fd27b142993b89c52b3cee0389.7z)
2. Download the two scripts and the bytecode (extracted from that sample) from this repository.
3. Specify the path to the downloaded bytecode in the TranslateInstructions.py script.
4. Run the TranslateInstructions.py and FixDecompilation.py scripts.
5. Patch the bytes of JMP instruction at 0x405379 to E9 C6 D3 02 00 and define a function at 0x405362 (you can also test the script on other functions).
6. Decompile this function. You should be able to see readable code.

Please also read the paper published at (https://www.virusbulletin.com/conference/vb2023/abstracts/deobfuscating-virtualized-malware-using-hex-rays-decompiler/).

**If you encounter problems with this script**

Please open an issue or contact me on Twitter (@kucher1n)
