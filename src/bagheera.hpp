#include "includes.hpp"

using namespace asmjit;


class CMutagenSPE
{
public:
  //CMutagenSPE(void);
  //~CMutagenSPE(void);

  // the main function which performs the
  // encryption and generates the polymorphic
  // code
  int PolySPE( char * lpInputBuffer, \
                            unsigned long dwInputBuffer, \
                            unsigned char * *lpOutputBuffer, \
                            unsigned long * lpdwOutputSize);

private:

  // a structure describing the values of
  // the output registers
  typedef struct _SPE_OUTPUT_REGS {

    // target register
    x86::Gp regDst;

    // value to write in this register
    unsigned long dwValue;

  } SPE_OUTPUT_REGS, *P_SPE_OUTPUT_REGS;

  // description of an encryption operation
  typedef struct _SPE_CRYPT_OP {

    // TRUE if the operation is performed
    // on two registers; FALSE if it is
    // performed between the target register
    // and the value in dwCryptValue
    int bCryptWithReg;

    x86::Gp regDst;
    x86::Gp regSrc;

    // encryption operation
    unsigned char cCryptOp;

    // encryption value
    unsigned long dwCryptValue;

  } SPE_CRYPT_OP, *P_SPE_CRYPT_OP;

  enum
  {
    SPE_CRYPT_OP_ADD = 0,
    SPE_CRYPT_OP_SUB = 1,
    SPE_CRYPT_OP_XOR = 2,
    SPE_CRYPT_OP_NOT = 3,
    SPE_CRYPT_OP_NEG = 4,
  };

  // buffer with the encryption operations
  char *diCryptOps;

  // pointer to the table of encryption
  // operations
  P_SPE_CRYPT_OP lpcoCryptOps;

  // count of encryption operations
  unsigned long dwCryptOpsCount;

  // pointer to the encrypted data block
  char *diEncryptedData;

  // number of blocks of encrypted data
  unsigned long dwEncryptedBlocks;

  // encryption key
  unsigned long dwEncryptionKey;

  FileLogger logger;    // Logger should always survive CodeHolder.

  // the register which will store a pointer
  // to the data which is to be decrypted
  x86::Gp regSrc;

  // the register which will store a pointer
  // to the output buffer
  x86::Gp regDst;

  // the register which hold the size of the
  // encrypted data
  x86::Gp regSize;

  // the register with the encryption key
  x86::Gp regKey;

  // the register on which the decryption
  // instructions will operate
  x86::Gp regData;

  // the preserved registers (ESI EDI EBX in random order)
  x86::Gp regSafe1, regSafe2, regSafe3;

  // the delta_offset label
  Label lblDeltaOffset;

  // the position of the delta offset
  size_t posDeltaOffset;

  // the relative address of the encrypted data
  size_t posSrcPtr;

  // the size of the unused code between delta
  // offset and the instructions which get that
  // value from the stack
  unsigned long dwUnusedCodeSize;

  // helper methods
  void SelectRegisters();
  void GeneratePrologue(x86::Assembler& a);
  void GenerateDeltaOffset(x86::Assembler& a);
  void EncryptInputBuffer(char * lpInputBuffer, \
                          unsigned long dwInputBuffer, \
                          unsigned long dwMinInstr, \
                          unsigned long dwMaxInstr);
  void SetupDecryptionKeys(x86::Assembler& a);
  void GenerateDecryption(x86::Assembler& a);
  void SetupOutputRegisters(SPE_OUTPUT_REGS *regOutput, \
                            unsigned long dwCount, \
                            x86::Assembler& a);
  void GenerateEpilogue(unsigned long dwParamCount, \
                        x86::Assembler& a);
  void AlignDecryptorBody(unsigned long dwAlignment, \
                          x86::Assembler& a, \
                          CodeHolder& code);
  void AppendEncryptedData(x86::Assembler& a);
  void UpdateDeltaOffsetAddressing(x86::Assembler& a);
  void WriteToFile(void *lpcDecryptionProc, unsigned long dwDecryptionProcSize);
};


