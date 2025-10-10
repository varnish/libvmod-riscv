#include <stdint.h>
#include <stdio.h>
#include <elf.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
static const char sElfMagic[] = "\x7f" "ELF";

#define ELF_EHDR  Elf32_Ehdr
#define ELF_PHDR  Elf32_Phdr

/* Change the permissions on a segment */
static void chperm32(char *pcFileAddr, int iSegNo, uint64_t ulPerm)
{
	ELF_EHDR *ptElfHdr;
	ELF_PHDR *ptElfPHdr;

	ptElfHdr = (ELF_EHDR *) pcFileAddr;
	if (memcmp(&(ptElfHdr->e_ident), sElfMagic, sizeof(sElfMagic) - 1)) {
		fprintf(stderr, "chperm: File does not appear to be an ELF file\n");
		exit(-1);
	}

	/* Does this file have the segment they requested?                 */
	if ((iSegNo < 0) || (iSegNo >= ptElfHdr->e_phnum)) {
		printf("chperm: Segment %d does not exist in the executable\n", iSegNo);
		exit(-1);
	}

	/* Get the segment header for the specified segment                */
	ptElfPHdr = (ELF_PHDR *) ((char *) pcFileAddr + ptElfHdr->e_phoff +
                               (ptElfHdr->e_phentsize * iSegNo));

	/* Set the permissions as specified                                */
	ptElfPHdr->p_flags = ulPerm;
}

#undef ELF_EHDR
#define ELF_EHDR  Elf64_Ehdr
#undef ELF_PHDR
#define ELF_PHDR  Elf64_Phdr

static void chperm64(char *pcFileAddr, int iSegNo, uint64_t ulPerm)
{
	ELF_EHDR *ptElfHdr;
	ELF_PHDR *ptElfPHdr;

	ptElfHdr = (ELF_EHDR *) pcFileAddr;
	if (memcmp(&(ptElfHdr->e_ident), sElfMagic, sizeof(sElfMagic) - 1)) {
		fprintf(stderr, "chperm: File does not appear to be an ELF file\n");
		exit(-1);
	}

	/* Does this file have the segment they requested?                 */
	if ((iSegNo < 0) || (iSegNo >= ptElfHdr->e_phnum)) {
		printf("chperm: Segment %d does not exist in the executable\n", iSegNo);
		exit(-1);
	}

	/* Get the segment header for the specified segment                */
	ptElfPHdr = (ELF_PHDR *) ((char *) pcFileAddr + ptElfHdr->e_phoff +
                               (ptElfHdr->e_phentsize * iSegNo));

	/* Set the permissions as specified                                */
	ptElfPHdr->p_flags = ulPerm;
}


int main(int argc, char *argv[])
{
	char *sInFile;
	unsigned long ulPerm = 0;
	int iSegNo, iInFd, i;
	char *pcFileAddr;
	struct stat tStatBuf;
	off_t tMapSize;

	if (argc != 4) {
		fprintf(stderr,
			"Usage: %s <file> <segment no> <segment permissions (e.g rwx)>\n",
			argv[0]);
		exit(1);
	}

	i = 0;
	while (argv[3][i]) {
	  switch(argv[3][i]) {
	     case 'x':
	        ulPerm |= PF_X; break;
	     case 'r':
	        ulPerm |= PF_R; break;
	     case 'w':
	        ulPerm |= PF_W; break;
		default:
			fprintf(stderr, "Permissions must be one of x, r, w - got %s\n", argv[3]);
			exit(1);
	  }
	  i++;
	}
	sInFile = argv[1];
	iSegNo = atoi(argv[2]);

	if (-1 == (iInFd = open(sInFile, O_RDWR))) {
		fprintf(stderr, "Could not open %s, %d %s\n", sInFile, errno, strerror(errno));
		exit(-1);
	}

	if (fstat(iInFd, &tStatBuf)) {
		fprintf(stderr, "Could not stat %s, %d %s\n", sInFile, errno, strerror(errno));
		exit(-1);
	}
	tMapSize = tStatBuf.st_size;

	if (!(pcFileAddr = mmap(0, tMapSize, PROT_READ | PROT_WRITE, MAP_SHARED, iInFd, 0))) { fprintf(stderr, "Could not mmap %s, %d %s\n", sInFile, errno, strerror(errno));
		exit(-1);
	}
	printf("File %s mapped at %p for %lu bytes\n", sInFile, pcFileAddr, tMapSize);

	switch (pcFileAddr[4]) {
	case 1: // ELFCLASS32
		chperm32(pcFileAddr, iSegNo, ulPerm);
		break;
	case 2: // ELFCLASS64
		chperm64(pcFileAddr, iSegNo, ulPerm);
		break;
	default:
		printf("File %s unknown ELF class: %u\n", sInFile, pcFileAddr[4]);
	}

	munmap(pcFileAddr, tMapSize);
	close(iInFd);

	return 0;
}
