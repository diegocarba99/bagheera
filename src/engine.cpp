#include "engine.h"

int engine_execution (options_t *options){

	 srand(time(NULL));

  // create an instance of the polymorphic engine
  CMutagenSPE *speEngine = new CMutagenSPE();

  // a pointer to the generated decryption function will be placed here
  unsigned char *lpcDecryptionProc = NULL;

  // the size of the decryption code (and its encrypted payload) will go here
  unsigned long dwDecryptionProcSize = 0;

  // encrypt the input data and dynamically generate a decryption function
  speEngine->PolySPE((unsigned char*)options->input, options->inputsz, &lpcDecryptionProc, &dwDecryptionProcSize);

  return 0;

}
