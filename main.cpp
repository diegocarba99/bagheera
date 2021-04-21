#include "src/bagheera.hpp"
#include "src/includes.hpp"




int main()
{

  srand(0);
  //srand(time(NULL));
  
  // input data (in this case a simple string,
  // although it could be any data buffer)
  //std::cout << "Creating payload\n";

  char payload[] = "Hello World";
  //std::ifstream ifs("hello_world");
  //std::string payload( (std::istreambuf_iterator<char>(ifs) ),
                       //(std::istreambuf_iterator<char>()    ) );
  //std::cout << payload.data() << std::endl;


  //char payload[] = "section     .text \n global      _start \n _start: \n     mov     edx,len \n     mov     ecx,msg \n     mov     ebx,1 \n     mov     eax,4 \n     int     0x80 \n     mov     eax,1 \n     int     0x80 \n section     .data \n msg     db  'Hello world',0xa \n len     equ $ - msg";

  // create an instance of the polymorphic
  // engine,
  //std::cout << "Creating bangheera PE instance\n";

  CMutagenSPE *speEngine = new CMutagenSPE();

  // a pointer to the generated decryption
  // function will be placed here
  //std::cout << "Creating pointer to the generated decryption function\n";
  unsigned char *lpcDecryptionProc = NULL;

  // the size of the decryption code (and
  // its encrypted payload) will go here
  //std::cout << "Defining size of the decryption code\n";
  unsigned long dwDecryptionProcSize = 0;

  // encrypt the input data and dynamically
  // generate a decryption function
  //std::cout << "Call PolySPE function and encrypt data\n";
  speEngine->PolySPE((char*)payload, sizeof(payload), &lpcDecryptionProc, &dwDecryptionProcSize);

 
  return 0;
  
}


