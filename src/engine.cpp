#include "engine.h"
#include "bagheera.hpp"

using namespace std;

int engine_execution (options_t *options){

	 srand(time(NULL));

  // create an instance of the polymorphic engine
  BagheeraPE *engine = new BagheeraPE();

  // encrypt the input data and dynamically generate a decryption function
  engine->execute((unsigned char*)options->input, options->inputsz);

  return EXIT_SUCCESS;

}


int engine_creation(options_t *options, char **lpcDecryptionProc, unsigned long *dwDecryptionProcSize){

  srand(time(NULL));

  // create an instance of the polymorphic engine
  BagheeraPE *engine = new BagheeraPE();

  // encrypt the input data and dynamically generate a decryption function
  engine->create((unsigned char*)options->input, options->inputsz, lpcDecryptionProc, dwDecryptionProcSize);

  if (VERBOSE) cout << "engine_creation - dwDecryptionProcSize = " << dwDecryptionProcSize << endl;
  if (VERBOSE) cout << "engine_creation - *dwDecryptionProcSize = " << *dwDecryptionProcSize << endl;
  if (VERBOSE) cout << "engine_creation - lpcDecryptionProc = " << lpcDecryptionProc << endl;
  if (VERBOSE) cout << "engine_creation - *lpcDecryptionProc = " << *lpcDecryptionProc << endl;


  return EXIT_SUCCESS;
}
