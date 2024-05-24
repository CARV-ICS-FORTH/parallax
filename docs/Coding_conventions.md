# Coding Conventions in Parallax
Parallax covers the majority of coding style guidelines in its clang-format file. However, there are the following rules that clang-format does not cover:
1. We do not use typedef struct A A_t. Instead use forward declare.
2. For the prefixes in the namespace of a header file use snake case with lower-case letters.
3. Do not use extern in function declaration in the header files.
