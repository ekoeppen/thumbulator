#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

typedef int (*instruction_handler_func)(unsigned int addr, unsigned short instruction);

unsigned int read32(unsigned int);
unsigned int read_register(unsigned int);

#define DBUGFETCH   0
#define DBUGRAM     0
#define DBUGRAMW    0
#define DBUGREG     0
#define DBUG        0
#define DISS        0

#define RAM_START	0x20000000
#define PERIPH_START	0xE0000000

#define ROMADDMASK 0xFFFFF
#define RAMADDMASK 0xFFFFF

#define ROMSIZE (ROMADDMASK+1)
#define RAMSIZE (RAMADDMASK+1)

#define MAX_INPUT (64 * 1024)

unsigned short rom[ROMSIZE >> 1];
unsigned short ram[RAMSIZE >> 1];

instruction_handler_func instruction_handler[ROMSIZE];
instruction_handler_func instruction_handler_ram[RAMSIZE];

#define CPSR_N (1 << 31)
#define CPSR_Z (1 << 30)
#define CPSR_C (1 << 29)
#define CPSR_V (1 << 28)
#define CPSR_Q (1 << 27)

unsigned int systick_ctrl;
unsigned int systick_reload;
unsigned int systick_count;
unsigned int systick_calibrate;

unsigned int halfadd;
unsigned int cpsr;
unsigned int handler_mode;
unsigned int reg_norm[16];  //normal execution mode,  do not have a thread mode

unsigned int cpuid;
char *output_file_name;

int read_fd;
int write_fd;
unsigned char input_buffer[MAX_INPUT];
size_t input_read_ptr = 0;
size_t input_write_ptr = 0;
int socket_fd = -1;

const char options[] = "c:o:d:m:v:p:";
const char *condition_str[] = {
	"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "", ""
};

inline void set_instruction_handler(unsigned int pc, instruction_handler_func handler) {
	if (pc < RAM_START) {
		instruction_handler[(pc & ~0x08000000) - 2] = handler;
	} else {
		instruction_handler_ram[(pc & ~0x20000000) - 2] = handler;
	}
}

inline instruction_handler_func get_instruction_handler(unsigned int pc) {
	if (pc < RAM_START) {
		return instruction_handler[(pc & ~0x08000000) - 2];
	} else {
		return instruction_handler_ram[(pc & ~0x20000000) - 2];
	}
}



void dump_registers(void) {
	int i;

	fprintf(stderr, "Registers:\n");
	for (i = 0; i < 16; i++) {
		switch (i) {
			case 13: fprintf(stderr, "sp:  "); break;
			case 14: fprintf(stderr, "lr:  "); break;
			case 15: fprintf(stderr, "pc:  "); break;
			default: fprintf(stderr, "r%d: %s", i, i < 10 ? " " : ""); break;
		}
		fprintf(stderr, "%08x\n", reg_norm[i]);
	}
}

unsigned int fetch16(unsigned int addr)
{
	unsigned int data;

	if (DBUGFETCH) fprintf(stderr, "fetch16(0x%08x) = ", addr);
	if (DBUG) fprintf(stderr, "fetch16(0x%08x) = ", addr);
	switch(addr & 0xFF000000)
	{
		case 0x08000000:
			addr &= ~(0x08000000);
		case 0x00000000: //ROM
			addr &= ROMADDMASK;

			//if (addr < 0x50)
			//{
			//    fprintf(stderr, "fetch16(0x%08x),  abort\n", addr);
			//    exit(1);
			//}

			addr >>= 1;
			data = rom[addr];
			if (DBUGFETCH) fprintf(stderr, "0x%04x\n", data);
			if (DBUG) fprintf(stderr, "0x%04x\n", data);
			return (data);
		case RAM_START: //RAM
			addr &= RAMADDMASK;
			addr >>= 1;
			data = ram[addr];
			if (DBUGFETCH) fprintf(stderr, "0x%04x\n", data);
			if (DBUG) fprintf(stderr, "0x%04x\n", data);
			return (data);
	}
	fprintf(stderr, "fetch16(0x%08x),  abort pc  =  0x%04x\n", addr, read_register(15));
	dump_registers();
	exit(1);
}

unsigned int fetch32(unsigned int addr)
{
	unsigned int data;

	if (DBUGFETCH) fprintf(stderr, "fetch32(0x%08x) = ", addr);
	if (DBUG) fprintf(stderr, "fetch32(0x%08x) = ", addr);
	switch(addr & 0xFF000000)
	{
		case 0x08000000:
			addr &= ~(0x08000000);
		case 0x00000000: //ROM
			if (addr < 0x50)
			{
				data = read32(addr);
				if (DBUGFETCH) fprintf(stderr, "0x%08x\n", data);
				if (DBUG) fprintf(stderr, "0x%08x\n", data);
				if (addr == 0x00000000) return (data);
				if (addr == 0x00000004) return (data);
				if (addr == 0x0000003C) return (data);
				fprintf(stderr, "fetch32(0x%08x),  abort pc  =  0x%04x\n", addr, read_register(15));
				dump_registers();
				exit(1);
			}
		case RAM_START: //RAM
			//data = fetch16(addr+0);
			//data |= ((unsigned int)fetch16(addr+2)) << 16;
			data = read32(addr);
			if (DBUGFETCH) fprintf(stderr, "0x%08x\n", data);
			if (DBUG) fprintf(stderr, "0x%08x\n", data);
			return (data);
	}
	fprintf(stderr, "fetch32(0x%08x),  abort pc 0x%04x\n", addr, read_register(15));
	dump_registers();
	exit(1);
}

void write16(unsigned int addr,  unsigned int data)
{
	if (DBUG) fprintf(stderr, "write16(0x%08x, 0x%04x)\n", addr, data);
	switch(addr & 0xFF000000)
	{
		case 0x08000000:
			addr &= ~(0x08000000);
		case 0x00000000: //ROM
			if (DBUGRAM) fprintf(stderr, "write16(0x%08x, 0x%04x)\n", addr, data);
			addr &= ROMADDMASK;
			addr >>= 1;
			rom[addr] = data & 0xFFFF;
			return;
		case RAM_START: //RAM
			if (DBUGRAM) fprintf(stderr, "write16(0x%08x, 0x%04x)\n", addr, data);
			addr &= RAMADDMASK;
			addr >>= 1;
			ram[addr] = data & 0xFFFF;
			return;
	}
	fprintf(stderr, "write16(0x%08x, 0x%04x),  abort pc 0x%04x\n", addr, data, read_register(15));
	dump_registers();
	exit(1);
}

void write32(unsigned int addr,  unsigned int data)
{
	if (DBUG) fprintf(stderr, "write32(0x%08x, 0x%08x)\n", addr, data);
	switch(addr & 0xFF000000)
	{
		case 0xF0000000: //halt
			exit(0);
		case PERIPH_START: //periph
			switch(addr)
			{
				case PERIPH_START:
					if (DISS) printf("uart: [");
					write(write_fd, &data, 1);
					if (DISS) printf("]\n");
					fflush(stdout);
					break;

				case 0xE000E010:
					{
						unsigned int old;

						old = systick_ctrl;
						systick_ctrl  =  data & 0x00010007;
						if (((old & 1) == 0) && (systick_ctrl & 1))
						{
							//timer started,  load count
							systick_count = systick_reload;
						}
						break;
					}
				case 0xE000E014:
					{
						systick_reload = data & 0x00FFFFFF;
						break;
					}
				case 0xE000E018:
					{
						systick_count = data & 0x00FFFFFF;
						break;
					}
				case 0xE000E01C:
					{
						systick_calibrate = data & 0x00FFFFFF;
						break;
					}
			}
			return;
		case 0xD0000000: //debug
			switch(addr & 0xFF)
			{
				case 0x00:
					{
						fprintf(stderr, "[0x%08x][0x%08x] 0x%08x\n", read_register(14), addr, data);
						return;
					}
				case 0x10:
					{
						printf("0x%08x ", data);
						return;
					}
				case 0x20:
					{
						printf("0x%08x\n", data);
						return;
					}
			}
		case 0x08000000:
			addr &= ~(0x08000000);
		case 0x00000000:
		case RAM_START: //RAM
			if (DBUGRAMW) fprintf(stderr, "write32(0x%08x, 0x%08x)\n", addr, data);
			write16(addr+0, (data >>  0) & 0xFFFF);
			write16(addr+2, (data >> 16) & 0xFFFF);
			return;
	}
	fprintf(stderr, "write32(0x%08x, 0x%08x),  ignored pc 0x%04x\n", addr, data, read_register(15));
	exit(1);
}

unsigned int read16(unsigned int addr)
{
	unsigned int data;

	if (DBUG) fprintf(stderr, "read16(0x%08x) = ", addr);
	switch(addr & 0xFF000000)
	{
		case 0x08000000:
			addr &= ~(0x08000000);
		case 0x00000000: //ROM
			addr &= ROMADDMASK;
			addr >>= 1;
			data = rom[addr];
			if (DBUG) fprintf(stderr, "0x%04x\n", data);
			return (data);
		case RAM_START: //RAM
			if (DBUGRAM) fprintf(stderr, "read16(0x%08x) = ", addr);
			addr &= RAMADDMASK;
			addr >>= 1;
			data = ram[addr];
			if (DBUG) fprintf(stderr, "0x%04x\n", data);
			if (DBUGRAM) fprintf(stderr, "0x%04x\n", data);
			return (data);
	}
	fprintf(stderr, "read16(0x%08x),  abort pc 0x%04x\n", addr, read_register(15));
	dump_registers();
	exit(1);
}

unsigned int read32(unsigned int addr)
{
	unsigned int data;

	if (DBUG) fprintf(stderr, "read32(0x%08x) = ", addr);
	switch(addr & 0xFF000000)
	{
		case 0x08000000:
			addr &= ~(0x08000000);
		case 0x00000000: //ROM
		case RAM_START: //RAM
			if (DBUGRAMW) fprintf(stderr, "read32(0x%08x) = ", addr);
			data  = read16(addr+0);
			data |= ((unsigned int)read16(addr+2)) << 16;
			if (DBUG) fprintf(stderr, "0x%08x\n", data);
			if (DBUGRAMW) fprintf(stderr, "0x%08x\n", data);
			return (data);
		case PERIPH_START:
			{
				switch(addr)
				{
					case PERIPH_START:
						if (DISS) printf("uart: [%d %d", input_read_ptr, input_write_ptr);
						if (input_read_ptr != input_write_ptr) {
							data = input_buffer[input_read_ptr++];
							if (input_read_ptr == MAX_INPUT) input_read_ptr = 0;
						}
						if (DISS) printf("%c]\n", data);
						return (data);
					case PERIPH_START + 4:
						if (input_read_ptr != input_write_ptr) {
							data = -1;
						} else {
							data = 0;
						}
					case PERIPH_START + 8:
						{
							read(read_fd, &data, 1);
						}
						return (data);
					case 0xE000E010:
						{
							data  =  systick_ctrl;
							systick_ctrl &= (~0x00010000);
							return (data);
						}
					case 0xE000E014:
						{
							data = systick_reload;
							return (data);
						}
					case 0xE000E018:
						{
							data = systick_count;
							return (data);
						}
					case 0xE000E01C:
						{
							data = systick_calibrate;
							return (data);
						}
					case 0xE000ED00:
						{
							data = cpuid;
							return (data);
						}
				}
			}
	}
	fprintf(stderr, "read32(0x%08x),  abort pc 0x%04x\n", addr, read_register(15));
	dump_registers();
	exit(1);
}

unsigned int read_register(unsigned int reg)
{
	return reg != 15 ? reg_norm[reg] : reg_norm[reg] & ~(0x1);
}

void write_register(unsigned int reg,  unsigned int data)
{
	reg_norm[reg] = (reg < 15 ? data : data & ~(0x1));
}

void do_zflag(unsigned int x)
{
	if (x == 0) cpsr |= CPSR_Z;  else cpsr &= ~CPSR_Z;
}

void do_nflag(unsigned int x)
{
	if (x & 0x80000000) cpsr |= CPSR_N;  else cpsr &= ~CPSR_N;
}

void do_cflag(unsigned int a,  unsigned int b,  unsigned int c)
{
	unsigned int rc;

	cpsr &= ~CPSR_C;
	rc = (a & 0x7FFFFFFF)+(b & 0x7FFFFFFF)+c;  //carry in
	rc  = (rc >> 31)+(a >> 31)+(b >> 31);   //carry out
	if (rc & 2) cpsr |= CPSR_C;
}

void do_vflag(unsigned int a,  unsigned int b,  unsigned int c)
{
	unsigned int rc;
	unsigned int rd;

	cpsr &= ~CPSR_V;
	rc = (a & 0x7FFFFFFF)+(b & 0x7FFFFFFF)+c;  //carry in
	rc >>= 31;  //carry in in lsbit
	rd = (rc & 1)+((a >> 31) & 1)+((b >> 31) & 1);  //carry out
	rd >>= 1;  //carry out in lsbit
	rc = (rc^rd) & 1;  //if carry in ! =  carry out then signed overflow
	if (rc) cpsr |= CPSR_V;
}

void do_cflag_bit(unsigned int x)
{
	if (x) cpsr |= CPSR_C;  else cpsr &= ~CPSR_C;
}

void do_vflag_bit(unsigned int x)
{
	if (x) cpsr |= CPSR_V;  else cpsr &= ~CPSR_V;
}

unsigned int ror_c(unsigned int x, unsigned int width, unsigned int shift)
{
	unsigned int m = shift % width;
	return (x >> m) | (x << (width - m));
}

unsigned int thumb_expand_imm_c(unsigned int imm)
{
	unsigned int type;
	unsigned int r = 0;

	if (imm & 0b110000000000 == 0) {
		type = (imm & 0b001100000000) >> 8;
		imm &= 0xff;
		switch (type) {
		case 0: r = imm; break;
		case 1: r = (imm << 16) | imm; break;
		case 2: r = (imm << 24) | (imm << 8); break;
		case 3: r = (imm << 24) | (imm << 16) | (imm << 8) | imm; break;
		}
	} else {
		r = ror_c(0b10000000 | (imm & 0b1111111), 32, (imm & 0b111110000000) >> 7);
	}
	return r;
}

int condition_met(int condition)
{
	switch (condition) {
		case 0x0: //b eq  z set
			return (cpsr & CPSR_Z);
		case 0x1: //b ne  z clear
			return (!(cpsr & CPSR_Z));
		case 0x2: //b cs c set
			return (cpsr & CPSR_C);
		case 0x3: //b cc c clear
			return (!(cpsr & CPSR_C));
		case 0x4: //b mi n set
			return (cpsr & CPSR_N);
		case 0x5: //b pl n clear
			return (!(cpsr & CPSR_N));
		case 0x6: //b vs v set
			return (cpsr & CPSR_V);
		case 0x7: //b vc v clear
			return (!(cpsr & CPSR_V));
		case 0x8: //b hi c set z clear
			return ((cpsr & CPSR_C) && (!(cpsr & CPSR_Z)));
		case 0x9: //b ls c clear or z set
			return ((cpsr & CPSR_Z) || (!(cpsr & CPSR_C)));
		case 0xA: //b ge N  ==  V
			return ((cpsr & CPSR_N) && (cpsr & CPSR_V)) || ((!(cpsr & CPSR_N)) && (!(cpsr & CPSR_V)));
		case 0xB: //b lt N ! =  V
			return ((!(cpsr & CPSR_N)) && (cpsr & CPSR_V)) || ((!(cpsr & CPSR_V)) && (cpsr & CPSR_N));
		case 0xC: //b gt Z == 0 and N  ==  V
			return !(cpsr & CPSR_Z) &&
				(((cpsr & CPSR_N) && (cpsr & CPSR_V)) || ((!(cpsr & CPSR_N)) && (!(cpsr & CPSR_V))));
		case 0xD: //b le Z == 1 or N ! =  V
			return (cpsr & CPSR_Z) ||
				((!(cpsr & CPSR_N)) && (cpsr & CPSR_V)) ||
				((!(cpsr & CPSR_V)) && (cpsr & CPSR_N));
		case 0xE:
			return 1;
		case 0xF:
			return 0;
	}
	return 0;
}

void wait_for_input(void)
{
	fd_set s_rd;

	if (input_read_ptr == input_write_ptr) {
		FD_ZERO(&s_rd);
		FD_SET(read_fd, &s_rd);
		select(read_fd + 1, &s_rd, NULL, NULL, NULL);
	}
}

int handle_bkpt(unsigned int bp, unsigned int arg)
{
	int r = 1;
	FILE *f;
	int s, e, n;
	unsigned int sp;

	sp = read_register(13);
	switch (arg) {
		case 0x18:
			fprintf(stderr, "Exiting.\n");
			break;
		case 0x80:
			s = read32(sp + 8);
			e = read32(sp + 4);
			fprintf(stderr, "Dumping from %08x to %08x into %s...\n",
					s, e, output_file_name);
			f = fopen(output_file_name, "wb");
			while (s != e) {
				n = read32(s);
				fwrite(&n, 2, 1, f);
				s += 2;
			}
			fclose(f);
			write_register(13, read_register(13) + 8);
			r = 0;
			break;
		case 0x81:
			dump_registers();
			r = 0;
			break;
		case 0x82:
			wait_for_input();
			r = 0;
			break;
		default:
			fprintf(stderr, "bkpt 0x%02X %08x\n", bp, arg);
			break;
	}
	write_register(13, read_register(13) + 4);
	return r;
}

int ldr1_handler(unsigned int pc, unsigned short inst)
{
	unsigned int sp;

	unsigned int ra, rb, rc;
	unsigned int rm, rd, rn, rs;
	unsigned int op;

	if (DISS) fprintf(stderr, "--- 0x%08x: 0x%04x ", (pc-4), inst);

	rd = (inst >> 0) & 0x07;
	rn = (inst >> 3) & 0x07;
	rb = (inst >> 6) & 0x1F;
	rb <<= 2;
	if (DISS) fprintf(stderr, "ldr r%u, [r%u, #0x%x]\n", rd, rn, rb);
	rb = read_register(rn)+rb;
	rc = read32(rb);
	write_register(rd, rc);
	return 0;
}

int bx_handler(unsigned int pc, unsigned short inst)
{
	unsigned int sp;

	unsigned int ra, rb, rc;
	unsigned int rm, rd, rn, rs;
	unsigned int op;

	if (DISS) fprintf(stderr, "--- 0x%08x: 0x%04x ", (pc-4), inst);

	rm = (inst >> 3) & 0xF;
	if (DISS) fprintf(stderr, "--- 0x%08x: bx r%u\n", (pc-4), rm);
	rc = read_register(rm);
	rc += 2;
	// if (DISS) fprintf(stderr, "bx r%u 0x%x 0x%x\n", rm, rc, pc);
	if (rc & 1)
	{
		rc &= ~1;
		write_register(15, rc);
		return (0);
	}
	else
	{
		fprintf(stderr, "cannot branch to ARM code at %08x (pc = 0x%08x, inst = 0x%04x)\n", rc, pc, inst);
		dump_registers();
		return (1);
	}
	return 0;
}

int add2_handler(unsigned int pc, unsigned short inst)
{
	unsigned int sp;

	unsigned int ra, rb, rc;
	unsigned int rm, rd, rn, rs;
	unsigned int op;

	if (DISS) fprintf(stderr, "--- 0x%08x: 0x%04x ", (pc-4), inst);
	//ADD(2) big immediate one register
	rb = (inst >> 0) & 0xFF;
	rd = (inst >> 8) & 0x7;
	if (DISS) fprintf(stderr, "adds r%u, #0x%02X\n", rd, rb);
	ra = read_register(rd);
	rc = ra+rb;
	write_register(rd, rc);
	do_nflag(rc);
	do_zflag(rc);
	do_cflag(ra, rb, 0);
	do_vflag(ra, rb, 0);
	return (0);
}

int pop_handler(unsigned int pc, unsigned short inst) {
	unsigned int sp;

	unsigned int ra, rb, rc;
	unsigned int rm, rd, rn, rs;
	unsigned int op;

	if (DISS) fprintf(stderr, "--- 0x%08x: 0x%04x ", (pc-4), inst);
	if (DISS)
	{
		fprintf(stderr, "pop {");
		for (ra = 0, rb = 0x01, rc = 0; rb; rb = (rb << 1) & 0xFF, ra++)
		{
			if (inst & rb)
			{
				if (rc) fprintf(stderr, ", ");
				fprintf(stderr, "r%u", ra);
				rc++;
			}
		}
		if (inst & 0x100)
		{
			if (rc) fprintf(stderr, ", ");
			fprintf(stderr, "pc");
		}
		fprintf(stderr, "}\n");
	}

	sp = read_register(13);
	for (ra = 0, rb = 0x01; rb; rb = (rb << 1) & 0xFF, ra++)
	{
		if (inst & rb)
		{
			write_register(ra, read32(sp));
			sp += 4;
		}
	}
	if (inst & 0x100)
	{
		rc = read32(sp);
		if ((rc & 1) == 0)
		{
			fprintf(stderr, "pop {rc} with an ARM address pc 0x%08x popped 0x%08x\n", pc, rc);
			//exit(1);
			rc &= ~1;
		}
		rc += 2;
		write_register(15, rc);
		sp += 4;
	}
	write_register(13, sp);
	return (0);
}

int push_handler(unsigned int pc, unsigned short inst) {
	unsigned int sp;

	unsigned int ra, rb, rc;
	unsigned int rm, rd, rn, rs;
	unsigned int op;

	if (DISS) fprintf(stderr, "--- 0x%08x: 0x%04x ", (pc-4), inst);
	if (DISS)
	{
		fprintf(stderr, "push {");
		for (ra = 0, rb = 0x01, rc = 0; rb; rb = (rb << 1) & 0xFF, ra++)
		{
			if (inst & rb)
			{
				if (rc) fprintf(stderr, ", ");
				fprintf(stderr, "r%u", ra);
				rc++;
			}
		}
		if (inst & 0x100)
		{
			if (rc) fprintf(stderr, ", ");
			fprintf(stderr, "lr");
		}
		fprintf(stderr, "}\n");
	}

	sp = read_register(13);
	//fprintf(stderr, "sp 0x%08x\n", sp);
	for (ra = 0, rb = 0x01, rc = 0; rb; rb = (rb << 1) & 0xFF, ra++)
	{
		if (inst & rb)
		{
			rc++;
		}
	}
	if (inst & 0x100) rc++;
	rc <<= 2;
	sp -= rc;
	rd = sp;
	for (ra = 0, rb = 0x01; rb; rb = (rb << 1) & 0xFF, ra++)
	{
		if (inst & rb)
		{
			write32(rd, read_register(ra));
			rd += 4;
		}
	}
	if (inst & 0x100)
	{
		rc = read_register(14);
		write32(rd, rc);  //read_register(14));

		if ((rc & 1) == 0)
		{
			fprintf(stderr, "push {lr} with an ARM address pc 0x%08x popped 0x%08x\n", pc, rc);
			//                exit(1);
		}


	}
	write_register(13, sp);
	return (0);
}

int default_thumb2_handler(unsigned int pc, unsigned short inst)
{
	unsigned int sp;

	unsigned int ra, rb, rc;
	unsigned int rm, rd, rn, rs;
	unsigned int op, op1, op2, inst2;
	inst2 = fetch16(pc - 2);

	op1 = (inst & 0x1800) >> 11;
	op2 = (inst & 0x07f0) >> 4;
	op = (inst2 & 0xf000) >> 15;

	//fprintf(stderr, "Thumb-2: %01x %07x %01x\n", op1, op2, op);
	//BL(Thumb-2)
	switch (op1) {
		case 2:
			if (op == 1) {
				int j1, j2, s, imm_hi, imm_lo, offset;
				op = (inst2 & 0x3000) >> 12;

				offset = 0;
				s = (inst & 0x400) >> 10;
				j1 = (inst2 & 0x2000) >> 13;
				j2 = (inst2 & 0x800) >> 11;
				if ((op & 0x5) == 0 && (op2 & 0x38) != 0x38) {
					int cond = (inst & 0x3c0);
					if (condition_met(cond >> 6)) {
						struct {signed int x:20;} ext;
						imm_hi = (inst & 0x3F);
						imm_lo = (inst2 & 0x7FF);
						offset = (s << 20) + (!(j1 ^ s) << 19) + (!(j2 ^ s) << 18) + (imm_hi << 12) | (imm_lo << 1);
						offset = (ext.x = offset) + 1;
					}
					if (DISS) fprintf(stderr, "--- 0x%08x: b%s.w %08x\n", (pc - 4), condition_str[cond], pc + offset);
				} else if ((op & 0x5) == 1) {
					struct {signed int x:24;} ext;
					imm_hi = (inst & 0x3FF);
					imm_lo = (inst2 & 0x7FF);
					offset = (s << 24) + (!(j1 ^ s) << 23) + (!(j2 ^ s) << 22) + (imm_hi << 12) | (imm_lo << 1);
					offset = (ext.x = offset) + 1;
					write_register(14, pc | 1);
					if (DISS) fprintf(stderr, "--- 0x%08x: bl %08x\n", (pc - 4), pc + offset);
				}

				if (offset) {
					if ((pc + 2 + offset) & 1) {
						rc &= ~1;
						write_register(15, pc + 2 + offset);
						return (0);
					} else {
						fprintf(stderr, "cannot branch to ARM location %08x (pc = 0x%08x, inst = 0x%04x)\n",
								pc + 2 + offset + 1, pc, inst);
						return (1);
					}
				} else {
					write_register(15, pc + 2);
					return 0;
				}
			} else {
				if ((op2 & 0b010000) == 0b010000) {
				} else {
					int op, rd, imm8, imm3, i;
					op = (inst >> 4) & 0x1e;
					rd = (inst2 >> 8) & 0xf;
					rn = inst & 0xf;
					imm3 = (inst2 >> 12) & 0x7; imm8 = (inst2 & 0xff); i = (inst >> 10) & 0x1;
					//fprintf(stderr, "Thumb-2: op = %02x rd = %1x rn = %1x i = %d\n", op, rd, rn, i);
					switch (op) {
					case 4: if (rn != 15) {
							if (!i) {
								write_register(rd, read_register(rn) | (imm3 << 8) | imm8);
								write_register(15, pc + 2);
								return (0);
							}
						} else {
							write_register(rd, thumb_expand_imm_c((i << 11) | (imm3 << 8) | imm8));
							write_register(15, pc + 2);
							return (0);
						}
						break;
					}
				}
				fprintf(stderr, "Thumb-2 instruction 0x%0x %04x at 0x%08x not implemented (1)\n", inst, inst2, pc - 4);
				return (1);
			}
			break;
		case 1:
			fprintf(stderr, "Thumb-2 instruction 0x%0x %04x at 0x%08x not implemented (2)\n", inst, inst2, pc - 4);
			return (1);
		case 3:
			if ((op2 & 0x38) == 0x38) {
				op1 = (inst >> 4) & 0x7;
				op2 = (inst2 >> 4) & 0xf;
				switch (op1) {
				case 1:
					if (op2 == 0xf) {
						rn = inst & 0xf;
						rm = inst2 & 0xf;
						rd = (inst2 >> 8) & 0xf;
						write_register(rd, read_register(rn) / read_register(rm));
						write_register(15, pc + 2);
						return 0;
					}
					break;
				case 3:
					rn = inst & 0xf;
					rm = inst2 & 0xf;
					rd = (inst2 >> 8) & 0xf;
					write_register(rd, (unsigned int) read_register(rn) / (unsigned int) read_register(rm));
					write_register(15, pc + 2);
					return 0;
				default:
					fprintf(stderr, "Thumb-2: %02x %02x\n", op1, op2);
					break;
				}
			} else if ((op2 & 0x38) == 0x30) {
				int ra;
				op1 = (inst >> 4) & 0x7;
				op2 = (inst2 >> 4) & 0x3;
				ra = (inst2 >> 12) & 0xf;
				switch (op1) {
				case 0:
					rn = inst & 0xf;
					rm = inst2 & 0xf;
					rd = (inst2 >> 8) & 0xf;
					ra = (inst2 >> 12) & 0xf;
					if (op2 == 0) {
						if (ra == 0xf) {
						} else {
						}
					} else {
						write_register(rd, read_register(ra) - read_register(rm) * read_register(rn));
						write_register(15, pc + 2);
						return (0);
					}
				default:
				fprintf(stderr, "Thumb-2: %01x %07x %01x\n", op1, op2, ra);
				break;

				}
			} else if ((op2 & 0x67) == 0x05) {
				op1 = (inst >> 7) & 0x3;
				op2 = (inst2 >> 6) & 0x3f;
				rn = (inst & 0xf);
				//fprintf(stderr, "Thumb-2: %01x %07x %01x\n", op1, op2, rn);
				if (rn == 0xf) {
					int rt, imm12, u;
					rt = (inst2 >> 12) & 0xf;
					imm12 = inst2 & 0x7ff;
					u = (inst >> 6) & 0x1;
					imm12 = inst2 & 0x7ff;
					write_register(rt, read32(read_register(15) + (u ? imm12 : -imm12)));
					write_register(15, pc + 2);
					return (0);
				} else {
					if (op1 == 0x00 && op2 == 0x00) {
					} else if (op1 == 0x00 && (((op2 & 0x24) == 0x24) || ((op2 & 0b111100) == 0b110000))) {
					} else if (op1 == 0x01) {
						int rt, imm12;
						rt = (inst2 >> 12) & 0xf;
						imm12 = inst2 & 0x7ff;
						write_register(rt, read32(read_register(rn) + imm12));
						write_register(15, read_register(15) + 2);
						return (0);
					}
				}
			} else if ((op2 & 0b1110001) == 0b0000000) {
				op1 = (inst >> 5) & 0x7;
				op2 = (inst2 >> 6) & 0x3f;
				rn = inst & 0xf;
				//fprintf(stderr, "Thumb-2: %01x %07x %1x\n", op1, op2, rn);
				if (op1 == 0x3) {
				} else if (op1 == 0x2) {
					if ((op2 & 0b100000) == 0b100000) {
						int rt, imm8, p, u, w;
						rt = (inst2 >> 12) & 0xf;
						imm8 = inst2 & 0xff;
						p = (inst2 >> 10) & 0x1;
						u = (inst2 >> 9) & 0x1;
						w = (inst2 >> 8) & 0x1;
						write32(read_register(rn) + (p ? (u ? imm8 : -imm8) : 0), read_register(rt));
						if (w) write_register(rn, read_register(rn) + (u ? imm8 : -imm8));
						write_register(15, pc + 2);
						return (0);
					} else {
					}
				}
			}
			fprintf(stderr, "Thumb-2 instruction 0x%0x %04x at 0x%08x not implemented (3)\n", inst, inst2, pc - 4);
			return (1);
	}
	fprintf(stderr, "invalid Thumb-2 instruction 0x%08x 0x%04x\n", pc-4, inst);
	return (1);
}

int default_thumb_handler(unsigned int pc, unsigned short inst)
{
	unsigned int sp;

	unsigned int ra, rb, rc;
	unsigned int rm, rd, rn, rs;
	unsigned int op;

	//LDR(1) two register immediate
	if ((inst & 0xF800) == 0x6800) {
		set_instruction_handler(pc, ldr1_handler);
		return ldr1_handler(pc, inst);
	}

	//BX
	if ((inst & 0xFF87) == 0x4700) {
		set_instruction_handler(pc, bx_handler);
		return bx_handler(pc, inst);
	}

	//ADD(2) big immediate one register
	if ((inst & 0xF800) == 0x3000) {
		set_instruction_handler(pc, add2_handler);
		return add2_handler(pc, inst);
	}

	//POP
	if ((inst & 0xFE00) == 0xBC00) {
		set_instruction_handler(pc, pop_handler);
		return pop_handler(pc, inst);
	}

	//PUSH
	if ((inst & 0xFE00) == 0xB400)
	{
		set_instruction_handler(pc, push_handler);
		return push_handler(pc, inst);
	}

	if (DISS) fprintf(stderr, "--- 0x%08x: 0x%04x ", (pc-4), inst);

	//ADC
	if ((inst & 0xFFC0) == 0x4140)
	{
		rd = (inst >> 0) & 0x07;
		rm = (inst >> 3) & 0x07;
		if (DISS) fprintf(stderr, "adc r%u, r%u\n", rd, rm);
		ra = read_register(rd);
		rb = read_register(rm);
		rc = ra+rb;
		if (cpsr & CPSR_C) rc++;
		write_register(rd, rc);
		do_nflag(rc);
		do_zflag(rc);
		if (cpsr & CPSR_C) { do_cflag(ra, rb, 1);  do_vflag(ra, rb, 1);  }
		else            { do_cflag(ra, rb, 0);  do_vflag(ra, rb, 0);  }
		return (0);
	}

	//ADD(1) small immediate two registers
	if ((inst & 0xFE00) == 0x1C00)
	{
		rd = (inst >> 0) & 0x7;
		rn = (inst >> 3) & 0x7;
		rb = (inst >> 6) & 0x7;
		if (rb)
		{
			if (DISS) fprintf(stderr, "adds r%u, r%u, #0x%x\n", rd, rn, rb);
			ra = read_register(rn);
			rc = ra+rb;
			//fprintf(stderr, "0x%08x  =  0x%08x + 0x%08x\n", rc, ra, rb);
			write_register(rd, rc);
			do_nflag(rc);
			do_zflag(rc);
			do_cflag(ra, rb, 0);
			do_vflag(ra, rb, 0);
			return (0);
		}
		else
		{
			//this is a mov
		}
	}

	//ADD(3) three registers
	if ((inst & 0xFE00) == 0x1800)
	{
		rd = (inst >> 0) & 0x7;
		rn = (inst >> 3) & 0x7;
		rm = (inst >> 6) & 0x7;
		if (DISS) fprintf(stderr, "adds r%u, r%u, r%u\n", rd, rn, rm);
		ra = read_register(rn);
		rb = read_register(rm);
		rc = ra+rb;
		write_register(rd, rc);
		do_nflag(rc);
		do_zflag(rc);
		do_cflag(ra, rb, 0);
		do_vflag(ra, rb, 0);
		return (0);
	}

	//ADD(4) two registers one or both high no flags
	if ((inst & 0xFF00) == 0x4400)
	{
		if ((inst >> 6) & 3)
		{
			//UNPREDICTABLE
		}
		rd = (inst >> 0) & 0x7;
		rd |= (inst >> 4) & 0x8;
		rm = (inst >> 3) & 0xF;
		if (DISS) fprintf(stderr, "add r%u, r%u\n", rd, rm);
		ra = read_register(rd);
		rb = read_register(rm);
		rc = ra+rb;
		if (rd == 15)
		{
			if ((rc & 1) == 0)
			{
				fprintf(stderr, "add pc, ... produced an arm address 0x%08x 0x%08x\n", pc, rc);
				exit(1);
			}
			rc &= ~1;  //write_register may do this as well
			rc += 2;  //The program counter is special
		}
		//fprintf(stderr, "0x%08x  =  0x%08x + 0x%08x\n", rc, ra, rb);
		write_register(rd, rc);
		return (0);
	}

	//ADD(5) rd  =  pc plus immediate
	if ((inst & 0xF800) == 0xA000)
	{
		rb = (inst >> 0) & 0xFF;
		rd = (inst >> 8) & 0x7;
		rb <<= 2;
		if (DISS) fprintf(stderr, "add r%u, PC, #0x%02X\n", rd, rb);
		ra = read_register(15);
		rc = (ra & (~3))+rb;
		write_register(rd, rc);
		return (0);
	}

	//ADD(6) rd  =  sp plus immediate
	if ((inst & 0xF800) == 0xA800)
	{
		rb = (inst >> 0) & 0xFF;
		rd = (inst >> 8) & 0x7;
		rb <<= 2;
		if (DISS) fprintf(stderr, "add r%u, SP, #0x%02X\n", rd, rb);
		ra = read_register(13);
		rc = ra+rb;
		write_register(rd, rc);
		return (0);
	}

	//ADD(7) sp plus immediate
	if ((inst & 0xFF80) == 0xB000)
	{
		rb = (inst >> 0) & 0x7F;
		rb <<= 2;
		if (DISS) fprintf(stderr, "add SP, #0x%02X\n", rb);
		ra = read_register(13);
		rc = ra+rb;
		write_register(13, rc);
		return (0);
	}

	//AND
	if ((inst & 0xFFC0) == 0x4000)
	{
		rd = (inst >> 0) & 0x7;
		rm = (inst >> 3) & 0x7;
		if (DISS) fprintf(stderr, "ands r%u, r%u\n", rd, rm);
		ra = read_register(rd);
		rb = read_register(rm);
		rc = ra & rb;
		write_register(rd, rc);
		do_nflag(rc);
		do_zflag(rc);
		return (0);
	}

	//ASR(1) two register immediate
	if ((inst & 0xF800) == 0x1000)
	{
		rd = (inst >> 0) & 0x07;
		rm = (inst >> 3) & 0x07;
		rb = (inst >> 6) & 0x1F;
		if (DISS) fprintf(stderr, "asrs r%u, r%u, #0x%x\n", rd, rm, rb);
		rc = read_register(rm);
		if (rb == 0)
		{
			if (rc & 0x80000000)
			{
				do_cflag_bit(1);
				rc = ~0;
			}
			else
			{
				do_cflag_bit(0);
				rc = 0;
			}
		}
		else
		{
			do_cflag_bit(rc & (1 << (rb-1)));
			ra = rc & 0x80000000;
			rc >>= rb;
			if (ra) //asr,  sign is shifted in
			{
				rc |= (~0) << (32-rb);
			}
		}
		write_register(rd, rc);
		do_nflag(rc);
		do_zflag(rc);
		return (0);
	}

	//ASR(2) two register
	if ((inst & 0xFFC0) == 0x4100)
	{
		rd = (inst >> 0) & 0x07;
		rs = (inst >> 3) & 0x07;
		if (DISS) fprintf(stderr, "asrs r%u, r%u\n", rd, rs);
		rc = read_register(rd);
		rb = read_register(rs);
		rb &= 0xFF;
		if (rb == 0)
		{
		}
		else if (rb < 32)
		{
			do_cflag_bit(rc & (1 << (rb-1)));
			ra = rc & 0x80000000;
			rc >>= rb;
			if (ra) //asr,  sign is shifted in
			{
				rc |= (~0) << (32-rb);
			}
		}
		else
		{
			if (rc & 0x80000000)
			{
				do_cflag_bit(1);
				rc = (~0);
			}
			else
			{
				do_cflag_bit(0);
				rc = 0;
			}
		}
		write_register(rd, rc);
		do_nflag(rc);
		do_zflag(rc);
		return (0);
	}

	//B(1) conditional branch
	if ((inst & 0xF000) == 0xD000)
	{
		rb = (inst >> 0) & 0xFF;
		if (rb & 0x80) rb |= (~0) << 8;
		op = (inst >> 8) & 0xF;
		rb <<= 1;
		rb += pc;
		rb += 2;
		switch(op)
		{
		case 0x0: //b eq  z set
			if (DISS) fprintf(stderr, "beq 0x%08x\n", rb-3);
			if (cpsr & CPSR_Z)
			{
				write_register(15, rb);
			}
			return (0);

		case 0x1: //b ne  z clear
			if (DISS) fprintf(stderr, "bne 0x%08x\n", rb-3);
			if (!(cpsr & CPSR_Z))
			{
				write_register(15, rb);
			}
			return (0);

		case 0x2: //b cs c set
			if (DISS) fprintf(stderr, "bcs 0x%08x\n", rb-3);
			if (cpsr & CPSR_C)
			{
				write_register(15, rb);
			}
			return (0);

		case 0x3: //b cc c clear
			if (DISS) fprintf(stderr, "bcc 0x%08x\n", rb-3);
			if (!(cpsr & CPSR_C))
			{
				write_register(15, rb);
			}
			return (0);

		case 0x4: //b mi n set
			if (DISS) fprintf(stderr, "bmi 0x%08x\n", rb-3);
			if (cpsr & CPSR_N)
			{
				write_register(15, rb);
			}
			return (0);

		case 0x5: //b pl n clear
			if (DISS) fprintf(stderr, "bpl 0x%08x\n", rb-3);
			if (!(cpsr & CPSR_N))
			{
				write_register(15, rb);
			}
			return (0);


		case 0x6: //b vs v set
			if (DISS) fprintf(stderr, "bvs 0x%08x\n", rb-3);
			if (cpsr & CPSR_V)
			{
				write_register(15, rb);
			}
			return (0);

		case 0x7: //b vc v clear
			if (DISS) fprintf(stderr, "bvc 0x%08x\n", rb-3);
			if (!(cpsr & CPSR_V))
			{
				write_register(15, rb);
			}
			return (0);


		case 0x8: //b hi c set z clear
			if (DISS) fprintf(stderr, "bhi 0x%08x\n", rb-3);
			if ((cpsr & CPSR_C) && (!(cpsr & CPSR_Z)))
			{
				write_register(15, rb);
			}
			return (0);

		case 0x9: //b ls c clear or z set
			if (DISS) fprintf(stderr, "bls 0x%08x\n", rb-3);
			if ((cpsr & CPSR_Z) || (!(cpsr & CPSR_C)))
			{
				write_register(15, rb);
			}
			return (0);

		case 0xA: //b ge N  ==  V
			if (DISS) fprintf(stderr, "bge 0x%08x\n", rb-3);
			ra = 0;
			if ((cpsr & CPSR_N) && (cpsr & CPSR_V)) ra++;
			if ((!(cpsr & CPSR_N)) && (!(cpsr & CPSR_V))) ra++;
			if (ra)
			{
				write_register(15, rb);
			}
			return (0);

		case 0xB: //b lt N ! =  V
			if (DISS) fprintf(stderr, "blt 0x%08x\n", rb-3);
			ra = 0;
			if ((!(cpsr & CPSR_N)) && (cpsr & CPSR_V)) ra++;
			if ((!(cpsr & CPSR_V)) && (cpsr & CPSR_N)) ra++;
			if (ra)
			{
				write_register(15, rb);
			}
			return (0);

		case 0xC: //b gt Z == 0 and N  ==  V
			if (DISS) fprintf(stderr, "bgt 0x%08x\n", rb-3);
			ra = 0;
			if ((cpsr & CPSR_N) && (cpsr & CPSR_V)) ra++;
			if ((!(cpsr & CPSR_N)) && (!(cpsr & CPSR_V))) ra++;
			if (cpsr & CPSR_Z) ra = 0;
			if (ra)
			{
				write_register(15, rb);
			}
			return (0);

		case 0xD: //b le Z == 1 or N ! =  V
			if (DISS) fprintf(stderr, "ble 0x%08x\n", rb-3);
			ra = 0;
			if ((!(cpsr & CPSR_N)) && (cpsr & CPSR_V)) ra++;
			if ((!(cpsr & CPSR_V)) && (cpsr & CPSR_N)) ra++;
			if (cpsr & CPSR_Z) ra++;
			if (ra)
			{
				write_register(15, rb);
			}
			return (0);

		case 0xE:
			//undefined instruction
			break;
		case 0xF:
			//swi
			break;
		}
	}

	//B(2) unconditional branch
	if ((inst & 0xF800) == 0xE000)
	{
		rb = (inst >> 0) & 0x7FF;
		if (rb & (1 << 10)) rb |= (~0) << 11;
		rb <<= 1;
		rb += pc;
		rb += 2;
		if (DISS) fprintf(stderr, "b 0x%08x\n", rb-3);
		write_register(15, rb);
		return (0);
	}

	//BIC
	if ((inst & 0xFFC0) == 0x4380)
	{
		rd = (inst >> 0) & 0x7;
		rm = (inst >> 3) & 0x7;
		if (DISS) fprintf(stderr, "bics r%u, r%u\n", rd, rm);
		ra = read_register(rd);
		rb = read_register(rm);
		rc = ra & (~rb);
		write_register(rd, rc);
		do_nflag(rc);
		do_zflag(rc);
		return (0);
	}

	//BKPT
	if ((inst & 0xFF00) == 0xBE00)
	{
		rb = (inst >> 0) & 0xFF;
		return (handle_bkpt(rb, read32(read_register(13))));
	}

	//BL/BLX(1)
	if ((inst & 0xE000) == 0xE000) //BL, BLX
	{
		if ((inst & 0x1800) == 0x1000) //H = b10
		{
			if (DISS) fprintf(stderr, "\n");
			rb = inst & ((1 << 11)-1);
			if (rb & 1 << 10) rb |= (~((1 << 11)-1));  //sign extend
			rb <<= 12;
			rb += pc;
			write_register(14, rb);
			return (0);
		}
		else
			if ((inst & 0x1800) == 0x1800) //H = b11
			{
				//branch to thumb
				rb = read_register(14);
				rb += (inst & ((1 << 11)-1)) << 1; ;
				rb += 2;

				if (DISS) fprintf(stderr, "bl 0x%08x\n", rb-3);
				write_register(14, (pc-2) | 1);
				write_register(15, rb);
				return (0);
			}
			else
				if ((inst & 0x1800) == 0x0800) //H = b01
				{
					//fprintf(stderr, "cannot branch to arm 0x%08x 0x%04x\n", pc, inst);
					//return (1);
					//branch to thumb
					rb = read_register(14);
					rb += (inst & ((1 << 11)-1)) << 1; ;
					rb &= 0xFFFFFFFC;
					rb += 2;

					printf("hello\n");

					if (DISS) fprintf(stderr, "bl 0x%08x\n", rb-3);
					write_register(14, (pc-2) | 1);
					write_register(15, rb);
					return (0);



				}
	}

	//BLX(2)
	if ((inst & 0xFF87) == 0x4780)
	{
		rm = (inst >> 3) & 0xF;
		if (DISS) fprintf(stderr, "blx r%u\n", rm);
		rc = read_register(rm);
		//fprintf(stderr, "blx r%u 0x%x 0x%x\n", rm, rc, pc);
		rc += 2;
		if (rc & 1)
		{
			write_register(14, (pc-2) | 1);
			rc &= ~1;
			write_register(15, rc);
			return (0);
		}
		else
		{
			fprintf(stderr, "cannot branch to arm 0x%08x 0x%04x\n", pc, inst);
			return (1);
		}
	}

	//CMN
	if ((inst & 0xFFC0) == 0x42C0)
	{
		rn = (inst >> 0) & 0x7;
		rm = (inst >> 3) & 0x7;
		if (DISS) fprintf(stderr, "cmns r%u, r%u\n", rn, rm);
		ra = read_register(rn);
		rb = read_register(rm);
		rc = ra+rb;
		do_nflag(rc);
		do_zflag(rc);
		do_cflag(ra, rb, 0);
		do_vflag(ra, rb, 0);
		return (0);
	}

	//CMP(1) compare immediate
	if ((inst & 0xF800) == 0x2800)
	{
		rb = (inst >> 0) & 0xFF;
		rn = (inst >> 8) & 0x07;
		if (DISS) fprintf(stderr, "cmp r%u, #0x%02X\n", rn, rb);
		ra = read_register(rn);
		rc = ra-rb;
		//fprintf(stderr, "0x%08x 0x%08x\n", ra, rb);
		do_nflag(rc);
		do_zflag(rc);
		do_cflag(ra, ~rb, 1);
		do_vflag(ra, ~rb, 1);
		return (0);
	}

	//CMP(2) compare register
	if ((inst & 0xFFC0) == 0x4280)
	{
		rn = (inst >> 0) & 0x7;
		rm = (inst >> 3) & 0x7;
		if (DISS) fprintf(stderr, "cmps r%u, r%u\n", rn, rm);
		ra = read_register(rn);
		rb = read_register(rm);
		rc = ra-rb;
		//fprintf(stderr, "0x%08x 0x%08x\n", ra, rb);
		do_nflag(rc);
		do_zflag(rc);
		do_cflag(ra, ~rb, 1);
		do_vflag(ra, ~rb, 1);
		return (0);
	}

	//CMP(3) compare high register
	if ((inst & 0xFF00) == 0x4500)
	{
		if (((inst >> 6) & 3) == 0x0)
		{
			//UNPREDICTABLE
		}
		rn = (inst >> 0) & 0x7;
		rn |= (inst >> 4) & 0x8;
		if (rn == 0xF)
		{
			//UNPREDICTABLE
		}
		rm = (inst >> 3) & 0xF;
		if (DISS) fprintf(stderr, "cmps r%u, r%u\n", rn, rm);
		ra = read_register(rn);
		rb = read_register(rm);
		rc = ra-rb;
		do_nflag(rc);
		do_zflag(rc);
		do_cflag(ra, ~rb, 1);
		do_vflag(ra, ~rb, 1);
		return (0);
	}

	//CPS
	if ((inst & 0xFFE8) == 0xB660)
	{
		if (DISS) fprintf(stderr, "cps TODO\n");
		return (1);
	}

	//CPY copy high register
	if ((inst & 0xFFC0) == 0x4600)
	{
		//same as mov except you can use both low registers
		//going to let mov handle high registers
		rd = (inst >> 0) & 0x7;  //mov handles the high registers
		rm = (inst >> 3) & 0x7;  //mov handles the high registers
		if (DISS) fprintf(stderr, "cpy r%u, r%u\n", rd, rm);
		rc = read_register(rm);
		//if (rd == 15) //mov handles the high registers like r15
		//{
		//rc &= ~1;
		//rc += 2;  //The program counter is special
		//}
		write_register(rd, rc);
		return (0);
	}

	//EOR
	if ((inst & 0xFFC0) == 0x4040)
	{
		rd = (inst >> 0) & 0x7;
		rm = (inst >> 3) & 0x7;
		if (DISS) fprintf(stderr, "eors r%u, r%u\n", rd, rm);
		ra = read_register(rd);
		rb = read_register(rm);
		rc = ra^rb;
		write_register(rd, rc);
		do_nflag(rc);
		do_zflag(rc);
		return (0);
	}

	//LDMIA
	if ((inst & 0xF800) == 0xC800)
	{
		rn = (inst >> 8) & 0x7;
		if (DISS)
		{
			fprintf(stderr, "ldmia r%u!, {", rn);
			for (ra = 0, rb = 0x01, rc = 0; rb; rb = (rb << 1) & 0xFF, ra++)
			{
				if (inst & rb)
				{
					if (rc) fprintf(stderr, ", ");
					fprintf(stderr, "r%u", ra);
					rc++;
				}
			}
			fprintf(stderr, "}\n");
		}
		sp = read_register(rn);
		for (ra = 0, rb = 0x01; rb; rb = (rb << 1) & 0xFF, ra++)
		{
			if (inst & rb)
			{
				write_register(ra, read32(sp));
				sp += 4;
			}
		}
		write_register(rn, sp);
		return (0);
	}

	//LDR(2) three register
	if ((inst & 0xFE00) == 0x5800)
	{
		rd = (inst >> 0) & 0x7;
		rn = (inst >> 3) & 0x7;
		rm = (inst >> 6) & 0x7;
		if (DISS) fprintf(stderr, "ldr r%u, [r%u, r%u]\n", rd, rn, rm);
		rb = read_register(rn)+read_register(rm);
		rc = read32(rb);
		write_register(rd, rc);
		return (0);
	}

	//LDR(3)
	if ((inst & 0xF800) == 0x4800)
	{
		rb = (inst >> 0) & 0xFF;
		rd = (inst >> 8) & 0x07;
		rb <<= 2;
		if (DISS) fprintf(stderr, "ldr r%u, [PC+#0x%x] ", rd, rb);
		ra = read_register(15);
		ra &= ~3;
		rb += ra;
		if (DISS) fprintf(stderr, "; @ 0x%x\n", rb);
		rc = read32(rb);
		write_register(rd, rc);
		return (0);
	}

	//LDR(4)
	if ((inst & 0xF800) == 0x9800)
	{
		rb = (inst >> 0) & 0xFF;
		rd = (inst >> 8) & 0x07;
		rb <<= 2;
		if (DISS) fprintf(stderr, "ldr r%u, [SP+#0x%x]\n", rd, rb);
		ra = read_register(13);
		//ra &= ~3;
		rb += ra;
		rc = read32(rb);
		write_register(rd, rc);
		return (0);
	}

	//LDRB(1)
	if ((inst & 0xF800) == 0x7800)
	{
		rd = (inst >> 0) & 0x07;
		rn = (inst >> 3) & 0x07;
		rb = (inst >> 6) & 0x1F;
		if (DISS) fprintf(stderr, "ldrb r%u, [r%u, #0x%x]\n", rd, rn, rb);
		rb = read_register(rn)+rb;
		rc = read16(rb & (~1));
		if (rb & 1)
		{
			rc >>= 8;
		}
		else
		{
		}
		write_register(rd, rc & 0xFF);
		return (0);
	}

	//LDRB(2)
	if ((inst & 0xFE00) == 0x5C00)
	{
		rd = (inst >> 0) & 0x7;
		rn = (inst >> 3) & 0x7;
		rm = (inst >> 6) & 0x7;
		if (DISS) fprintf(stderr, "ldrb r%u, [r%u, r%u]\n", rd, rn, rm);
		rb = read_register(rn)+read_register(rm);
		rc = read16(rb & (~1));
		if (rb & 1)
		{
			rc >>= 8;
		}
		else
		{
		}
		write_register(rd, rc & 0xFF);
		return (0);
	}

	//LDRH(1)
	if ((inst & 0xF800) == 0x8800)
	{
		rd = (inst >> 0) & 0x07;
		rn = (inst >> 3) & 0x07;
		rb = (inst >> 6) & 0x1F;
		rb <<= 1;
		if (DISS) fprintf(stderr, "ldrh r%u, [r%u, #0x%x]\n", rd, rn, rb);
		rb = read_register(rn)+rb;
		rc = read16(rb);
		write_register(rd, rc & 0xFFFF);
		return (0);
	}

	//LDRH(2)
	if ((inst & 0xFE00) == 0x5A00)
	{
		rd = (inst >> 0) & 0x7;
		rn = (inst >> 3) & 0x7;
		rm = (inst >> 6) & 0x7;
		if (DISS) fprintf(stderr, "ldrh r%u, [r%u, r%u]\n", rd, rn, rm);
		rb = read_register(rn)+read_register(rm);
		rc = read16(rb);
		write_register(rd, rc & 0xFFFF);
		return (0);
	}

	//LDRSB
	if ((inst & 0xFE00) == 0x5600)
	{
		rd = (inst >> 0) & 0x7;
		rn = (inst >> 3) & 0x7;
		rm = (inst >> 6) & 0x7;
		if (DISS) fprintf(stderr, "ldrsb r%u, [r%u, r%u]\n", rd, rn, rm);
		rb = read_register(rn)+read_register(rm);
		rc = read16(rb & (~1));
		if (rb & 1)
		{
			rc >>= 8;
		}
		else
		{
		}
		rc &= 0xFF;
		if (rc & 0x80) rc |= ((~0) << 8);
		write_register(rd, rc);
		return (0);
	}

	//LDRSH
	if ((inst & 0xFE00) == 0x5E00)
	{
		rd = (inst >> 0) & 0x7;
		rn = (inst >> 3) & 0x7;
		rm = (inst >> 6) & 0x7;
		if (DISS) fprintf(stderr, "ldrsh r%u, [r%u, r%u]\n", rd, rn, rm);
		rb = read_register(rn)+read_register(rm);
		rc = read16(rb);
		rc &= 0xFFFF;
		if (rc & 0x8000) rc |= ((~0) << 16);
		write_register(rd, rc);
		return (0);
	}

	//LSL(1)
	if ((inst & 0xF800) == 0x0000)
	{
		rd = (inst >> 0) & 0x07;
		rm = (inst >> 3) & 0x07;
		rb = (inst >> 6) & 0x1F;
		if (DISS) fprintf(stderr, "lsls r%u, r%u, #0x%x\n", rd, rm, rb);
		rc = read_register(rm);
		if (rb == 0)
		{
			//if immed_5  ==  0
			//C unnaffected
			//result not shifted
		}
		else
		{
			//else immed_5  >  0
			do_cflag_bit(rc & (1 << (32-rb)));
			rc <<= rb;
		}
		write_register(rd, rc);
		do_nflag(rc);
		do_zflag(rc);
		return (0);
	}

	//LSL(2) two register
	if ((inst & 0xFFC0) == 0x4080)
	{
		rd = (inst >> 0) & 0x07;
		rs = (inst >> 3) & 0x07;
		if (DISS) fprintf(stderr, "lsls r%u, r%u\n", rd, rs);
		rc = read_register(rd);
		rb = read_register(rs);
		rb &= 0xFF;
		if (rb == 0)
		{
		}
		else if (rb < 32)
		{
			do_cflag_bit(rc & (1 << (32-rb)));
			rc <<= rb;
		}
		else if (rb == 32)
		{
			do_cflag_bit(rc & 1);
			rc = 0;
		}
		else
		{
			do_cflag_bit(0);
			rc = 0;
		}
		write_register(rd, rc);
		do_nflag(rc);
		do_zflag(rc);
		return (0);
	}

	//LSR(1) two register immediate
	if ((inst & 0xF800) == 0x0800)
	{
		rd = (inst >> 0) & 0x07;
		rm = (inst >> 3) & 0x07;
		rb = (inst >> 6) & 0x1F;
		if (DISS) fprintf(stderr, "lsrs r%u, r%u, #0x%x\n", rd, rm, rb);
		rc = read_register(rm);
		if (rb == 0)
		{
			do_cflag_bit(rc & 0x80000000);
			rc = 0;
		}
		else
		{
			do_cflag_bit(rc & (1 << (rb-1)));
			rc >>= rb;
		}
		write_register(rd, rc);
		do_nflag(rc);
		do_zflag(rc);
		return (0);
	}

	//LSR(2) two register
	if ((inst & 0xFFC0) == 0x40C0)
	{
		rd = (inst >> 0) & 0x07;
		rs = (inst >> 3) & 0x07;
		if (DISS) fprintf(stderr, "lsrs r%u, r%u\n", rd, rs);
		rc = read_register(rd);
		rb = read_register(rs);
		rb &= 0xFF;
		if (rb == 0)
		{
		}
		else if (rb < 32)
		{
			do_cflag_bit(rc & (1 << (rb-1)));
			rc >>= rb;
		}
		else if (rb == 32)
		{
			do_cflag_bit(rc & 0x80000000);
			rc = 0;
		}
		else
		{
			do_cflag_bit(0);
			rc = 0;
		}
		write_register(rd, rc);
		do_nflag(rc);
		do_zflag(rc);
		return (0);
	}

	//MOV(1) immediate
	if ((inst & 0xF800) == 0x2000)
	{
		rb = (inst >> 0) & 0xFF;
		rd = (inst >> 8) & 0x07;
		if (DISS) fprintf(stderr, "movs r%u, #0x%02X\n", rd, rb);
		write_register(rd, rb);
		do_nflag(rb);
		do_zflag(rb);
		return (0);
	}

	//MOV(2) two low registers
	if ((inst & 0xFFC0) == 0x1C00)
	{
		rd = (inst >> 0) & 7;
		rn = (inst >> 3) & 7;
		if (DISS) fprintf(stderr, "movs r%u, r%u\n", rd, rn);
		rc = read_register(rn);
		//fprintf(stderr, "0x%08x\n", rc);
		write_register(rd, rc);
		do_nflag(rc);
		do_zflag(rc);
		do_cflag_bit(0);
		do_vflag_bit(0);
		return (0);
	}

	//MOV(3)
	if ((inst & 0xFF00) == 0x4600)
	{
		rd = (inst >> 0) & 0x7;
		rd |= (inst >> 4) & 0x8;
		rm = (inst >> 3) & 0xF;
		if (DISS) fprintf(stderr, "mov r%u, r%u\n", rd, rm);
		rc = read_register(rm);
		if ((rd == 14) && (rm == 15))
		{
			//printf("mov lr, pc warning 0x%08x\n", pc-2);
			//rc |= 1;
		}
		if (rd == 15)
		{
			//if ((rc & 1) == 0)
			//{
			//fprintf(stderr, "cpy or mov pc, ... produced an ARM address 0x%08x 0x%08x\n", pc, rc);
			//exit(1);
			//}
			rc &= ~1;  //write_register may do this as well
			rc += 2;  //The program counter is special
		}
		write_register(rd, rc);
		return (0);
	}

	//MUL
	if ((inst & 0xFFC0) == 0x4340)
	{
		rd = (inst >> 0) & 0x7;
		rm = (inst >> 3) & 0x7;
		if (DISS) fprintf(stderr, "muls r%u, r%u\n", rd, rm);
		ra = read_register(rd);
		rb = read_register(rm);
		rc = ra*rb;
		write_register(rd, rc);
		do_nflag(rc);
		do_zflag(rc);
		return (0);
	}

	//MVN
	if ((inst & 0xFFC0) == 0x43C0)
	{
		rd = (inst >> 0) & 0x7;
		rm = (inst >> 3) & 0x7;
		if (DISS) fprintf(stderr, "mvns r%u, r%u\n", rd, rm);
		ra = read_register(rm);
		rc = (~ra);
		write_register(rd, rc);
		do_nflag(rc);
		do_zflag(rc);
		return (0);
	}

	//NEG
	if ((inst & 0xFFC0) == 0x4240)
	{
		rd = (inst >> 0) & 0x7;
		rm = (inst >> 3) & 0x7;
		if (DISS) fprintf(stderr, "negs r%u, r%u\n", rd, rm);
		ra = read_register(rm);
		rc = 0-ra;
		write_register(rd, rc);
		do_nflag(rc);
		do_zflag(rc);
		do_cflag(0, ~ra, 1);
		do_vflag(0, ~ra, 1);
		return (0);
	}

	//ORR
	if ((inst & 0xFFC0) == 0x4300)
	{
		rd = (inst >> 0) & 0x7;
		rm = (inst >> 3) & 0x7;
		if (DISS) fprintf(stderr, "orrs r%u, r%u\n", rd, rm);
		ra = read_register(rd);
		rb = read_register(rm);
		rc = ra | rb;
		write_register(rd, rc);
		do_nflag(rc);
		do_zflag(rc);
		return (0);
	}

	//REV
	if ((inst & 0xFFC0) == 0xBA00)
	{
		rd = (inst >> 0) & 0x7;
		rn = (inst >> 3) & 0x7;
		if (DISS) fprintf(stderr, "rev r%u, r%u\n", rd, rn);
		ra = read_register(rn);
		rc  = ((ra >>  0) & 0xFF) << 24;
		rc |= ((ra >>  8) & 0xFF) << 16;
		rc |= ((ra >> 16) & 0xFF) <<  8;
		rc |= ((ra >> 24) & 0xFF) <<  0;
		write_register(rd, rc);
		return (0);
	}

	//REV16
	if ((inst & 0xFFC0) == 0xBA40)
	{
		rd = (inst >> 0) & 0x7;
		rn = (inst >> 3) & 0x7;
		if (DISS) fprintf(stderr, "rev16 r%u, r%u\n", rd, rn);
		ra = read_register(rn);
		rc  = ((ra >>  0) & 0xFF) <<  8;
		rc |= ((ra >>  8) & 0xFF) <<  0;
		rc |= ((ra >> 16) & 0xFF) << 24;
		rc |= ((ra >> 24) & 0xFF) << 16;
		write_register(rd, rc);
		return (0);
	}

	//REVSH
	if ((inst & 0xFFC0) == 0xBAC0)
	{
		rd = (inst >> 0) & 0x7;
		rn = (inst >> 3) & 0x7;
		if (DISS) fprintf(stderr, "revsh r%u, r%u\n", rd, rn);
		ra = read_register(rn);
		rc  = ((ra >>  0) & 0xFF) <<  8;
		rc |= ((ra >>  8) & 0xFF) <<  0;
		if (rc & 0x8000) rc |= 0xFFFF0000;
		else          rc &= 0x0000FFFF;
		write_register(rd, rc);
		return (0);
	}

	//ROR
	if ((inst & 0xFFC0) == 0x41C0)
	{
		rd = (inst >> 0) & 0x7;
		rs = (inst >> 3) & 0x7;
		if (DISS) fprintf(stderr, "rors r%u, r%u\n", rd, rs);
		rc = read_register(rd);
		ra = read_register(rs);
		ra &= 0xFF;
		if (ra == 0)
		{
		}
		else
		{
			ra &= 0x1F;
			if (ra == 0)
			{
				do_cflag_bit(rc & 0x80000000);
			}
			else
			{
				do_cflag_bit(rc & (1 << (ra-1)));
				rb = rc << (32-ra);
				rc >>= ra;
				rc |= rb;
			}
		}
		write_register(rd, rc);
		do_nflag(rc);
		do_zflag(rc);
		return (0);
	}

	//SBC
	if ((inst & 0xFFC0) == 0x4180)
	{
		rd = (inst >> 0) & 0x7;
		rm = (inst >> 3) & 0x7;
		if (DISS) fprintf(stderr, "sbc r%u, r%u\n", rd, rm);
		ra = read_register(rd);
		rb = read_register(rm);
		rc = ra-rb;
		if (!(cpsr & CPSR_C)) rc--;
		write_register(rd, rc);
		do_nflag(rc);
		do_zflag(rc);
		if (cpsr & CPSR_C)
		{
			do_cflag(ra, ~rb, 1);
			do_vflag(ra, ~rb, 1);
		}
		else
		{
			do_cflag(ra, ~rb, 0);
			do_vflag(ra, ~rb, 0);
		}
		return (0);
	}

	//SETEND
	if ((inst & 0xFFF7) == 0xB650)
	{
		fprintf(stderr, "setend not implemented\n");
		return (1);
	}

	//STMIA
	if ((inst & 0xF800) == 0xC000)
	{
		rn = (inst >> 8) & 0x7;

		if (DISS)
		{
			fprintf(stderr, "stmia r%u!, {", rn);
			for (ra = 0, rb = 0x01, rc = 0; rb; rb = (rb << 1) & 0xFF, ra++)
			{
				if (inst & rb)
				{
					if (rc) fprintf(stderr, ", ");
					fprintf(stderr, "r%u", ra);
					rc++;
				}
			}
			fprintf(stderr, "}\n");
		}
		sp = read_register(rn);
		for (ra = 0, rb = 0x01; rb; rb = (rb << 1) & 0xFF, ra++)
		{
			if (inst & rb)
			{
				write32(sp, read_register(ra));
				sp += 4;
			}
		}
		write_register(rn, sp);
		return (0);
	}

	//STR(1)
	if ((inst & 0xF800) == 0x6000)
	{
		rd = (inst >> 0) & 0x07;
		rn = (inst >> 3) & 0x07;
		rb = (inst >> 6) & 0x1F;
		rb <<= 2;
		if (DISS) fprintf(stderr, "str r%u, [r%u, #0x%x]\n", rd, rn, rb);
		rb = read_register(rn)+rb;
		rc = read_register(rd);
		write32(rb, rc);
		return (0);
	}

	//STR(2)
	if ((inst & 0xFE00) == 0x5000)
	{
		rd = (inst >> 0) & 0x7;
		rn = (inst >> 3) & 0x7;
		rm = (inst >> 6) & 0x7;
		if (DISS) fprintf(stderr, "str r%u, [r%u, r%u]\n", rd, rn, rm);
		rb = read_register(rn)+read_register(rm);
		rc = read_register(rd);
		write32(rb, rc);
		return (0);
	}

	//STR(3)
	if ((inst & 0xF800) == 0x9000)
	{
		rb = (inst >> 0) & 0xFF;
		rd = (inst >> 8) & 0x07;
		rb <<= 2;
		if (DISS) fprintf(stderr, "str r%u, [SP, #0x%x]\n", rd, rb);
		rb = read_register(13)+rb;
		//fprintf(stderr, "0x%08x\n", rb);
		rc = read_register(rd);
		write32(rb, rc);
		return (0);
	}

	//STRB(1)
	if ((inst & 0xF800) == 0x7000)
	{
		rd = (inst >> 0) & 0x07;
		rn = (inst >> 3) & 0x07;
		rb = (inst >> 6) & 0x1F;
		if (DISS) fprintf(stderr, "strb r%u, [r%u, #0x%x]\n", rd, rn, rb);
		rb = read_register(rn)+rb;
		rc = read_register(rd);
		ra = read16(rb & (~1));
		if (rb & 1)
		{
			ra &= 0x00FF;
			ra |= rc << 8;
		}
		else
		{
			ra &= 0xFF00;
			ra |= rc & 0x00FF;
		}
		write16(rb & (~1), ra & 0xFFFF);
		return (0);
	}

	//STRB(2)
	if ((inst & 0xFE00) == 0x5400)
	{
		rd = (inst >> 0) & 0x7;
		rn = (inst >> 3) & 0x7;
		rm = (inst >> 6) & 0x7;
		if (DISS) fprintf(stderr, "strb r%u, [r%u, r%u]\n", rd, rn, rm);
		rb = read_register(rn)+read_register(rm);
		rc = read_register(rd);
		ra = read16(rb & (~1));
		if (rb & 1)
		{
			ra &= 0x00FF;
			ra |= rc << 8;
		}
		else
		{
			ra &= 0xFF00;
			ra |= rc & 0x00FF;
		}
		write16(rb & (~1), ra & 0xFFFF);
		return (0);
	}

	//STRH(1)
	if ((inst & 0xF800) == 0x8000)
	{
		rd = (inst >> 0) & 0x07;
		rn = (inst >> 3) & 0x07;
		rb = (inst >> 6) & 0x1F;
		rb <<= 1;
		if (DISS) fprintf(stderr, "strh r%u, [r%u, #0x%x]\n", rd, rn, rb);
		rb = read_register(rn)+rb;
		rc = read_register(rd);
		write16(rb, rc & 0xFFFF);
		return (0);
	}

	//STRH(2)
	if ((inst & 0xFE00) == 0x5200)
	{
		rd = (inst >> 0) & 0x7;
		rn = (inst >> 3) & 0x7;
		rm = (inst >> 6) & 0x7;
		if (DISS) fprintf(stderr, "strh r%u, [r%u, r%u]\n", rd, rn, rm);
		rb = read_register(rn)+read_register(rm);
		rc = read_register(rd);
		write16(rb, rc & 0xFFFF);
		return (0);
	}

	//SUB(1)
	if ((inst & 0xFE00) == 0x1E00)
	{
		rd = (inst >> 0) & 7;
		rn = (inst >> 3) & 7;
		rb = (inst >> 6) & 7;
		if (DISS) fprintf(stderr, "subs r%u, r%u, #0x%x\n", rd, rn, rb);
		ra = read_register(rn);
		rc = ra-rb;
		write_register(rd, rc);
		do_nflag(rc);
		do_zflag(rc);
		do_cflag(ra, ~rb, 1);
		do_vflag(ra, ~rb, 1);
		return (0);
	}

	//SUB(2)
	if ((inst & 0xF800) == 0x3800)
	{
		rb = (inst >> 0) & 0xFF;
		rd = (inst >> 8) & 0x07;
		if (DISS) fprintf(stderr, "subs r%u, #0x%02X\n", rd, rb);
		ra = read_register(rd);
		rc = ra-rb;
		write_register(rd, rc);
		do_nflag(rc);
		do_zflag(rc);
		do_cflag(ra, ~rb, 1);
		do_vflag(ra, ~rb, 1);
		return (0);
	}

	//SUB(3)
	if ((inst & 0xFE00) == 0x1A00)
	{
		rd = (inst >> 0) & 0x7;
		rn = (inst >> 3) & 0x7;
		rm = (inst >> 6) & 0x7;
		if (DISS) fprintf(stderr, "subs r%u, r%u, r%u\n", rd, rn, rm);
		ra = read_register(rn);
		rb = read_register(rm);
		rc = ra-rb;
		write_register(rd, rc);
		do_nflag(rc);
		do_zflag(rc);
		do_cflag(ra, ~rb, 1);
		do_vflag(ra, ~rb, 1);
		return (0);
	}

	//SUB(4)
	if ((inst & 0xFF80) == 0xB080)
	{
		rb = inst & 0x7F;
		rb <<= 2;
		if (DISS) fprintf(stderr, "sub SP, #0x%02X\n", rb);
		ra = read_register(13);
		ra -= rb;
		write_register(13, ra);
		return (0);
	}

	//SWI
	if ((inst & 0xFF00) == 0xDF00)
	{
		rb = inst & 0xFF;
		if (DISS) fprintf(stderr, "swi 0x%02X\n", rb);

		if ((inst & 0xFF) == 0xCC)
		{
			write_register(0, cpsr);
			return (0);
		}
		else
		{
			fprintf(stderr, "\n\nswi 0x%02X\n", rb);
			return (1);
		}
	}

	//SXTB
	if ((inst & 0xFFC0) == 0xB240)
	{
		rd = (inst >> 0) & 0x7;
		rm = (inst >> 3) & 0x7;
		if (DISS) fprintf(stderr, "sxtb r%u, r%u\n", rd, rm);
		ra = read_register(rm);
		rc = ra & 0xFF;
		if (rc & 0x80) rc |= (~0) << 8;
		write_register(rd, rc);
		return (0);
	}

	//SXTH
	if ((inst & 0xFFC0) == 0xB200)
	{
		rd = (inst >> 0) & 0x7;
		rm = (inst >> 3) & 0x7;
		if (DISS) fprintf(stderr, "sxth r%u, r%u\n", rd, rm);
		ra = read_register(rm);
		rc = ra & 0xFFFF;
		if (rc & 0x8000) rc |= (~0) << 16;
		write_register(rd, rc);
		return (0);
	}

	//TST
	if ((inst & 0xFFC0) == 0x4200)
	{
		rn = (inst >> 0) & 0x7;
		rm = (inst >> 3) & 0x7;
		if (DISS) fprintf(stderr, "tst r%u, r%u\n", rn, rm);
		ra = read_register(rn);
		rb = read_register(rm);
		rc = ra & rb;
		do_nflag(rc);
		do_zflag(rc);
		return (0);
	}

	//UXTB
	if ((inst & 0xFFC0) == 0xB2C0)
	{
		rd = (inst >> 0) & 0x7;
		rm = (inst >> 3) & 0x7;
		if (DISS) fprintf(stderr, "uxtb r%u, r%u\n", rd, rm);
		ra = read_register(rm);
		rc = ra & 0xFF;
		write_register(rd, rc);
		return (0);
	}

	//UXTH
	if ((inst & 0xFFC0) == 0xB280)
	{
		rd = (inst >> 0) & 0x7;
		rm = (inst >> 3) & 0x7;
		if (DISS) fprintf(stderr, "uxth r%u, r%u\n", rd, rm);
		ra = read_register(rm);
		rc = ra & 0xFFFF;
		write_register(rd, rc);
		return (0);
	}

	//UDIV
	if ((inst & 0xFFF0) == 0xFBB0)
	{
		rn = (inst >> 0) & 0x7;
		inst = fetch16(pc);
		pc += 2;
		write_register(15, pc);
		rd = (inst >> 8) & 0x7;
		rm = (inst >> 0) & 0x7;
		if (DISS) fprintf(stderr, "udiv r%u, r%u, r%u\n", rd, rn, rm);
		write_register(rd, read_register(rn) / read_register(rm));
		return (0);
	}

	fprintf(stderr, "invalid instruction 0x%08x 0x%04x\n", pc-4, inst);
	return (1);
}

int default_handler(unsigned int pc, unsigned short inst)
{
	if ((inst & 0xe000) == 0xe000 && (inst & 0x1800) != 0x0000) return default_thumb2_handler(pc, inst);
	else return default_thumb_handler(pc, inst);
}

int execute(void)
{
	unsigned int pc;
	unsigned int sp;
	unsigned int inst;

	unsigned int ra, rb, rc;
	unsigned int rm, rd, rn, rs;
	unsigned int op;

	pc = read_register(15);
	//fprintf(stderr, "%08x [%08x %08x %08x]\n", pc - 2, reg_norm[0], reg_norm[5], reg_norm[6]);

	if (handler_mode)
	{
		if ((pc & 0xF0000000) == 0xF0000000)
		{
			unsigned int sp;

			handler_mode  =  0;
			//fprintf(stderr, "--leaving handler\n");
			sp = read_register(13);
			write_register(0, read32(sp));  sp += 4;
			write_register(1, read32(sp));  sp += 4;
			write_register(2, read32(sp));  sp += 4;
			write_register(3, read32(sp));  sp += 4;
			write_register(12, read32(sp));  sp += 4;
			write_register(14, read32(sp));  sp += 4;
			pc = read32(sp);  sp += 4;
			cpsr = read32(sp);  sp += 4;
			write_register(13, sp);
		}
	}
	if (systick_ctrl & 1)
	{
		if (systick_count)
		{
			systick_count--;
		}
		else
		{
			systick_count = systick_reload;
			systick_ctrl |= 0x00010000;
		}
	}

	if ((systick_ctrl & 3) == 3)
	{
		if (systick_ctrl & 0x00010000)
		{
			if (handler_mode == 0)
			{
				unsigned int sp;

				sp = read_register(13);
				sp -= 4;  write32(sp, cpsr);
				sp -= 4;  write32(sp, pc);
				sp -= 4;  write32(sp, read_register(14));
				sp -= 4;  write32(sp, read_register(12));
				sp -= 4;  write32(sp, read_register(3));
				sp -= 4;  write32(sp, read_register(2));
				sp -= 4;  write32(sp, read_register(1));
				sp -= 4;  write32(sp, read_register(0));
				write_register(13, sp);
				pc = fetch32(0x0000003C);  //systick vector
				pc += 2;
				write_register(14, 0xFFFFFFF9);

				handler_mode = 1;
			}
		}
	}

	inst = fetch16(pc - 2);
	pc += 2;
	write_register(15, pc);

	return get_instruction_handler(pc)(pc, inst);
}

int reset(void)
{
	memset(ram, 0x00, sizeof(ram));

	systick_ctrl = 0x00000004;
	systick_reload = 0x00000000;
	systick_count = 0x00000000;
	systick_calibrate = 0x00ABCDEF;
	handler_mode = 0;
	cpsr = 0;

	reg_norm[13] = fetch32(0x00000000);  //cortex-m
	reg_norm[14] = 0xFFFFFFFF;
	reg_norm[15] = fetch32(0x00000004);  //cortex-m
	if ((reg_norm[15] & 1) == 0)
	{
		fprintf(stderr, "reset vector with an ARM address 0x%08x\n", reg_norm[15]);
		exit(1);
	}
	reg_norm[15] &= ~1;
	reg_norm[15] += 2;

	return (0);
}

int run(void)
{
	char c;
	reset();
	while (1)
	{
		while (read(read_fd, &c, 1) == 1) {
			input_buffer[input_write_ptr++] = c;
			if (input_write_ptr > MAX_INPUT) input_write_ptr = 0;
		}
		if (execute()) break;
	}
	return (0);
}

unsigned int load_binary(unsigned int addr, char *name)
{
	int f;
	int r;
	struct stat st;

	f = open(name, O_RDONLY);
	if (f < 0) {
		perror("Can't open file:");
		exit(1);
	}
	fstat(f, &st);
	memset(&rom[addr >> 1], 0x0a0a, st.st_size + 1);
	r = read(f, &rom[addr >> 1], st.st_size);
	close(f);
	return (r + 1) & ~0x1;
}

unsigned int htoi(char *h)
{
	unsigned int r = 0;

	while (*h) {
		r <<= 4;
		*h = toupper(*h);
		r += *h - (*h > '9' ? 55 : 48);
		h++;
	}
	return r;
}

int start_server(int port)
{
	struct sockaddr_in server, client;
	socklen_t c;
	int t = 1;

	socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(port);
	if (bind(socket_fd, (struct sockaddr *) &server, sizeof(server)) < 0) {
		perror("Failed to bind");
		exit(1);
	}
	if (listen(socket_fd, 1) < 0) {
		perror("Failed to listen");
		exit(1);
	}
	setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &t,sizeof(int));
	c = sizeof(struct sockaddr_in);
	fprintf(stderr, "Waiting for connection\n");
	read_fd = accept(socket_fd, (struct sockaddr *) &client, (socklen_t *) &c);
	write_fd = read_fd;
	fprintf(stderr, "Connected\n");
}

void stop_server(void)
{
	shutdown(read_fd, SHUT_RDWR);
	close(read_fd);
	close(socket_fd);
}

void handle_cmd_line(int argc, char *argv[])
{
	int c;
	unsigned int org = 0;

	while ((c = getopt(argc, argv, options)) != -1) {
		switch (c) {
		case 'c':
			cpuid = htoi(optarg);
			break;
		case 'm':
			org = htoi(optarg);
			break;
		case 'd':
			org += load_binary(org, optarg);
			break;
		case 'o':
			output_file_name = optarg;
			break;
		case 'p':
			start_server(atoi(optarg));
			break;
		}
	}
}

int main(int argc, char *argv[])
{
	int i, flags;

	cpuid = 0;
	read_fd = STDIN_FILENO;
	write_fd = STDOUT_FILENO;
	memset(rom, 0xff, sizeof(rom));
	memset(ram, 0x00, sizeof(ram));
	for (i = 0; i < ROMSIZE; i++) instruction_handler[i] = default_handler;
	for (i = 0; i < RAMSIZE; i++) instruction_handler_ram[i] = default_handler;
	handle_cmd_line(argc, argv);
	flags = fcntl(read_fd, F_GETFL, 0);
	fcntl(read_fd, F_SETFL, flags | O_NONBLOCK);
	run();
	if (socket_fd != -1) {
		stop_server();
	}
	return (0);
}
