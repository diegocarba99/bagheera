#include "src/bagheera.hpp"
#include "src/includes.hpp"

typedef unsigned int(*DecryptionProc)(void *);

int main()
{

  srand(0);
  
  // input data (in this case a simple string,
  // although it could be any data buffer)
  std::cout << "Creating payload\n";

  // char payload[] = "There are few sources of energy so powerful as a procrastinating college student";
  char payload[] = "Hello world!";

  // create an instance of the polymorphic
  // engine,
  std::cout << "Creating bangheera PE instance\n";
  CMutagenSPE *speEngine = new CMutagenSPE();

  // a pointer to the generated decryption
  // function will be placed here
  std::cout << "Creating pointer to the generated decryption function\n";
  unsigned char *lpcDecryptionProc = NULL;

  // the size of the decryption code (and
  // its encrypted payload) will go here
  std::cout << "Defining size of the decryption code\n";
  unsigned long dwDecryptionProcSize = 0;

  // encrypt the input data and dynamically
  // generate a decryption function
  std::cout << "Call PolySPE function and encrypt data\n";
  speEngine->PolySPE(reinterpret_cast<unsigned char*>(payload), sizeof(payload), &lpcDecryptionProc, &dwDecryptionProcSize);

  // write the generated function to disk
  std::cout << "Creating file...\n";
  FILE *hFile = fopen("polymorphic_code.bin", "wb");

  std::cout << "Writting onto file\n";
  if (hFile != NULL)
  {
    fwrite(lpcDecryptionProc, dwDecryptionProcSize, 1, hFile);
    fclose(hFile);
  }

  // cast the function pointer to the right type
  DecryptionProc lpDecryptionProc = reinterpret_cast<DecryptionProc>(lpcDecryptionProc);

  // the output buffer for the decrypted data
  char szOutputBuffer[128];

  // call the decryption function via its
  // function pointer
  unsigned int dwOutputSize = lpDecryptionProc(szOutputBuffer);

  // display the decrypted text - if everything
  // went correctly this will show "Hello world!"
  std::cout << "returned size: " << dwOutputSize;
  std::cout << szOutputBuffer;

  return 0;
  
}


