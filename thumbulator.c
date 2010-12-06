
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned int read32 ( unsigned int );

unsigned int read_register ( unsigned int reg );

#define DBUG 0
#define DISS 0

#define ROMADDMASK 0xFFFFF
#define RAMADDMASK 0xFFFFF

#define ROMSIZE (ROMADDMASK+1)
#define RAMSIZE (RAMADDMASK+1)

unsigned short rom[ROMSIZE>>1];
unsigned short ram[RAMSIZE>>1];

//0b10000 User       PC, R14 to R0, CPSR
//0b10001 FIQ        PC, R14_fiq to R8_fiq, R7 to R0, CPSR, SPSR_fiq
//0b10010 IRQ        PC, R14_irq, R13_irq, R12 to R0, CPSR, SPSR_irq
//0b10011 Supervisor PC, R14_svc, R13_svc, R12 to R0, CPSR, SPSR_svc
//0b10111 Abort      PC, R14_abt, R13_abt, R12 to R0, CPSR, SPSR_abt
//0b11011 Undefined  PC, R14_und, R13_und, R12 to R0, CPSR, SPSR_und
//0b11111 System

#define MODE_USR 0x10
#define MODE_FIQ 0x11
#define MODE_IRQ 0x12
#define MODE_SVC 0x13
#define MODE_ABT 0x17
#define MODE_UND 0x1B
#define MODE_SYS 0x1F

#define CPSR_T (1<<5)
#define CPSR_F (1<<6)
#define CPSR_I (1<<7)
#define CPSR_N (1<<31)
#define CPSR_Z (1<<30)
#define CPSR_C (1<<29)
#define CPSR_V (1<<28)
#define CPSR_Q (1<<27)

unsigned int halfadd;
unsigned int cpsr;
unsigned int reg_usr[16]; //User mode
unsigned int reg_sys[16]; //System mode
unsigned int reg_svc[16]; //Supervisor mode
//unsigned int reg_abt[16]; //Abort mode
//unsigned int reg_und[16]; //Undefined mode
unsigned int reg_irq[16]; //Interrupt mode
//unsigned int reg_fiq[16]; //Fast Interrupt mode

unsigned long instructions;
unsigned long fetches;
unsigned long reads;
unsigned long writes;

//-------------------------------------------------------------------
void dump_counters ( void )
{
    printf("\n\n");
    printf("instructions %lu\n",instructions);
    printf("fetches      %lu\n",fetches);
    printf("reads        %lu\n",reads);
    printf("writes       %lu\n",writes);
    printf("memcycles    %lu\n",fetches+reads+writes);
}
//-------------------------------------------------------------------
unsigned int fetch16 ( unsigned int addr )
{
    unsigned int data;

    fetches++;


if(DBUG) fprintf(stderr,"fetch16(0x%08X)=",addr);
    switch(addr&0xF0000000)
    {
        case 0x00000000: //ROM
            addr&=ROMADDMASK;

if(addr<0x50)
{
    fprintf(stderr,"fetch16(0x%08X), abort\n",addr);
    exit(1);
}

            addr>>=1;
            data=rom[addr];
if(DBUG) fprintf(stderr,"0x%04X\n",data);
            return(data);
        case 0x40000000: //RAM
            addr&=RAMADDMASK;
            addr>>=1;
            data=ram[addr];
if(DBUG) fprintf(stderr,"0x%04X\n",data);
            return(data);
    }
    fprintf(stderr,"fetch16(0x%08X), abort\n",addr);
    exit(1);
}
//-------------------------------------------------------------------
unsigned int fetch32 ( unsigned int addr )
{
    unsigned int data;

if(DBUG) fprintf(stderr,"fetch32(0x%08X)=",addr);
    switch(addr&0xF0000000)
    {
        case 0x00000000: //ROM
            if(addr<0x50)
            {
                data=read32(addr);
if(DBUG) fprintf(stderr,"0x%08X\n",data);
                if(addr==0x00000000) return(data);
                if(addr==0x00000004) return(data);
                fprintf(stderr,"fetch32(0x%08X), abort\n",addr);
                exit(1);
            }
        case 0x40000000: //RAM
            data =fetch16(addr+2);
            data<<=16;
            data|=fetch16(addr+0);
if(DBUG) fprintf(stderr,"0x%08X\n",data);
            return(data);
    }
    fprintf(stderr,"fetch32(0x%08X), abort\n",addr);
    exit(1);
}
//-------------------------------------------------------------------
void write16 ( unsigned int addr, unsigned int data )
{

    writes++;


if(DBUG) fprintf(stderr,"write16(0x%08X,0x%08X)\n",addr,data);
    switch(addr&0xF0000000)
    {
        case 0x40000000: //RAM
            addr&=RAMADDMASK;
            addr>>=1;
            ram[addr]=data&0xFFFF;
            return;
    }
    fprintf(stderr,"write16(0x%08X,0x%08X), abort\n",addr,data);
    exit(1);
}
//-------------------------------------------------------------------
void write32 ( unsigned int addr, unsigned int data )
{
if(DBUG) fprintf(stderr,"write32(0x%08X,0x%08X)\n",addr,data);
    switch(addr&0xF0000000)
    {
        case 0xF0000000: //halt
            dump_counters();
            exit(0);
        case 0xE0000000: //periph
            switch(addr)
            {
                case 0xE0000000:
if(DISS) printf("uart: [");
                    printf("%c",data&0xFF);
if(DISS) printf("]\n");
fflush(stdout);
                    break;
            }
            return;
        case 0xD0000000: //debug
            fprintf(stderr,"[0x%08X][0x%08X] 0x%08X\n",read_register(14),addr,data);
            return;
        case 0x40000000: //RAM
            write16(addr+0,(data>> 0)&0xFFFF);
            write16(addr+2,(data>>16)&0xFFFF);
            return;
    }
    fprintf(stderr,"write32(0x%08X,0x%08X), abort\n",addr,data);
    exit(1);
}
//-----------------------------------------------------------------
unsigned int read16 ( unsigned int addr )
{
    unsigned int data;

    reads++;

if(DBUG) fprintf(stderr,"read16(0x%08X)=",addr);
    switch(addr&0xF0000000)
    {
        case 0x00000000: //ROM
            addr&=ROMADDMASK;
            addr>>=1;
            data=rom[addr];
if(DBUG) fprintf(stderr,"0x%04X\n",data);
            return(data);
        case 0x40000000: //RAM
            addr&=RAMADDMASK;
            addr>>=1;
            data=ram[addr];
if(DBUG) fprintf(stderr,"0x%04X\n",data);
            return(data);
    }
    fprintf(stderr,"read16(0x%08X), abort\n",addr);
    exit(1);
}
//-------------------------------------------------------------------
unsigned int read32 ( unsigned int addr )
{
    unsigned int data;

if(DBUG) fprintf(stderr,"read32(0x%08X)=",addr);
    switch(addr&0xF0000000)
    {
        case 0x00000000: //ROM
        case 0x40000000: //RAM
            data =read16(addr+2);
            data<<=16;
            data|=read16(addr+0);
if(DBUG) fprintf(stderr,"0x%08X\n",data);
            return(data);
    }
    fprintf(stderr,"read32(0x%08X), abort\n",addr);
    exit(1);
}
//-------------------------------------------------------------------
unsigned int read_register ( unsigned int reg )
{
    unsigned int data;

    reg&=0xF;
if(DBUG) fprintf(stderr,"read_register(%u)=",reg);
    switch(cpsr&0x1F)
    {
        case MODE_SVC:
            switch(reg)
            {
                default: data=reg_sys[reg]; break;
                case 13: case 14: data=reg_svc[reg]; break;
            }
if(DBUG) fprintf(stderr,"0x%08X\n",data);
            return(data);
    }
    fprintf(stderr,"invalid cpsr mode 0x%08X\n",cpsr);
    exit(1);
}
//-------------------------------------------------------------------
unsigned int write_register ( unsigned int reg, unsigned int data )
{
    reg&=0xF;
if(DBUG) fprintf(stderr,"write_register(%u,0x%08X)\n",reg,data);
    switch(cpsr&0x1F)
    {
        case MODE_SVC:
            switch(reg)
            {
                default: reg_sys[reg]=data; break;
                case 13: case 14: reg_svc[reg]=data; break;
            }
            return(data);
    }
    fprintf(stderr,"invalid cpsr mode 0x%08X\n",cpsr);
    exit(1);
}
//-------------------------------------------------------------------
void do_zflag ( unsigned int x )
{
    if(x==0) cpsr|=CPSR_Z; else cpsr&=~CPSR_Z;
}
//-------------------------------------------------------------------
void do_nflag ( unsigned int x )
{
    if(x&0x80000000) cpsr|=CPSR_N; else cpsr&=~CPSR_N;
}
//-------------------------------------------------------------------
void do_cflag ( unsigned int a, unsigned int b, unsigned int c )
{
    unsigned int rc;

    cpsr&=~CPSR_C;
    rc=(a&0x7FFFFFFF)+(b&0x7FFFFFFF)+c; //carry in
    rc = (rc>>31)+(a>>31)+(b>>31);  //carry out
    if(rc&2) cpsr|=CPSR_C;
}
//-------------------------------------------------------------------
void do_sub_vflag ( unsigned int a, unsigned int b, unsigned int c )
{
    cpsr&=~CPSR_V;
    //if the sign bits are different
    if((a&0x80000000)^(b&0x80000000))
    {
        //and result matches b
        if((b&0x80000000)==(c&0x80000000)) cpsr|=CPSR_V;
    }
}
//-------------------------------------------------------------------
void do_add_vflag ( unsigned int a, unsigned int b, unsigned int c )
{
   cpsr&=~CPSR_V;
   //if sign bits are the same
   if((a&0x80000000)==(b&0x80000000))
   {
       //and the result is different
       if((b&0x80000000)!=(c&0x80000000)) cpsr|=CPSR_V;
   }
}
//-------------------------------------------------------------------
void do_cflag_bit ( unsigned int x )
{
   if(x) cpsr|=CPSR_C; else cpsr&=~CPSR_C;
}
//-------------------------------------------------------------------
void do_vflag_bit ( unsigned int x )
{
   if(x) cpsr|=CPSR_V; else cpsr&=~CPSR_V;
}
//-------------------------------------------------------------------
//-------------------------------------------------------------------
//-------------------------------------------------------------------
int execute ( void )
{
    unsigned int pc;
    unsigned int sp;
    unsigned int inst;

    unsigned int ra,rb,rc;
    unsigned int rm,rd,rn,rs;
    unsigned int op;

    pc=read_register(15);
    inst=fetch16(pc-2);
    pc+=2;
    write_register(15,pc);
if(DISS) fprintf(stderr,"0x%08X: 0x%04X ",(pc-5),inst);

    instructions++;

    //ADC
    if((inst&0xFFC0)==0x4140)
    {
        rd=(inst>>0)&0x07;
        rm=(inst>>3)&0x07;
if(DISS) fprintf(stderr,"adc r%u,r%u\n",rd,rm);
        ra=read_register(rd);
        rb=read_register(rm);
        rc=ra+rb;
        if(cpsr&CPSR_C) rc++;
        write_register(rd,rc);
        do_nflag(rc);
        do_zflag(rc);
        if(cpsr&CPSR_C) do_cflag(ra,rb,1);
        else            do_cflag(ra,rb,0);
        do_add_vflag(ra,rb,rc);
        return(0);
    }

    //ADD(1) small immediate two registers
    if((inst&0xFE00)==0x1C00)
    {
        rd=(inst>>0)&0x7;
        rn=(inst>>3)&0x7;
        rb=(inst>>6)&0x7;
        if(rb)
        {
if(DISS) fprintf(stderr,"adds r%u,r%u,#0x%X\n",rd,rn,rb);
            ra=read_register(rn);
            rc=ra+rb;
//fprintf(stderr,"0x%08X = 0x%08X + 0x%08X\n",rc,ra,rb);
            write_register(rd,rc);
            do_nflag(rc);
            do_zflag(rc);
            do_cflag(ra,rb,0);
            do_add_vflag(ra,rb,rc);
            return(0);
        }
        else
        {
            //this is a mov
        }
    }

    //ADD(2) big immediate one register
    if((inst&0xF800)==0x3000)
    {
        rb=(inst>>0)&0xFF;
        rd=(inst>>8)&0x7;
if(DISS) fprintf(stderr,"adds r%u,#0x%02X\n",rd,rb);
        ra=read_register(rd);
        rc=ra+rb;
        write_register(rd,rc);
        do_nflag(rc);
        do_zflag(rc);
        do_cflag(ra,rb,0);
        do_add_vflag(ra,-rb,rc);
        return(0);
    }

    //ADD(3) three registers
    if((inst&0xFE00)==0x1800)
    {
        rd=(inst>>0)&0x7;
        rn=(inst>>3)&0x7;
        rm=(inst>>6)&0x7;
if(DISS) fprintf(stderr,"adds r%u,r%u,r%u\n",rd,rn,rm);
        ra=read_register(rn);
        rb=read_register(rm);
        rc=ra+rb;
        write_register(rd,rc);
        do_nflag(rc);
        do_zflag(rc);
        do_cflag(ra,rb,0);
        do_add_vflag(ra,rb,rc);
        return(0);
    }

    //ADD(4) two registers one or both high no flags
    if((inst&0xFF00)==0x4400)
    {
        if((inst>>6)&3)
        {
            //UNPREDICTABLE
        }
        rd=(inst>>0)&0x7;
        rd|=(inst>>4)&0x8;
        rm=(inst>>3)&0xF;
if(DISS) fprintf(stderr,"add r%u,r%u\n",rd,rm);
        ra=read_register(rd);
        rb=read_register(rm);
        rc=ra+rb;
//fprintf(stderr,"0x%08X = 0x%08X + 0x%08X\n",rc,ra,rb);
        write_register(rd,rc);
        return(0);
    }

    //ADD(5) rd = pc plus immediate
    if((inst&0xF800)==0xA000)
    {
        rb=(inst>>0)&0xFF;
        rd=(inst>>8)&0x7;
        rb<<=2;
if(DISS) fprintf(stderr,"add r%u,PC,#0x%02X\n",rd,rb);
        ra=read_register(15);
        rc=(ra&(~3))+rb;
        write_register(rd,rc);
        return(0);
    }

    //ADD(6) rd = sp plus immediate
    if((inst&0xF800)==0xA800)
    {
        rb=(inst>>0)&0xFF;
        rd=(inst>>8)&0x7;
        rb<<=2;
if(DISS) fprintf(stderr,"add r%u,SP,#0x%02X\n",rd,rb);
        ra=read_register(13);
        rc=ra+rb;
        write_register(rd,rc);
        return(0);
    }

    //ADD(7) sp plus immediate
    if((inst&0xFF80)==0xB000)
    {
        rb=(inst>>0)&0x7F;
        rb<<=2;
if(DISS) fprintf(stderr,"add SP,#0x%02X\n",rb);
        ra=read_register(13);
        rc=ra+rb;
        write_register(13,rc);
        return(0);
    }

    //AND
    if((inst&0xFFC0)==0x4000)
    {
        rd=(inst>>0)&0x7;
        rm=(inst>>3)&0x7;
if(DISS) fprintf(stderr,"ands r%u,r%u\n",rd,rm);
        ra=read_register(rd);
        rb=read_register(rm);
        rc=ra&rb;
        write_register(rd,rc);
        do_nflag(rc);
        do_zflag(rc);
        return(0);
    }

    //ASR(1) two register immediate
    if((inst&0xF800)==0x1000)
    {
        rd=(inst>>0)&0x07;
        rm=(inst>>3)&0x07;
        rb=(inst>>6)&0x1F;
if(DISS) fprintf(stderr,"asrs r%u,r%u,#0x%X\n",rd,rm,rb);
        rc=read_register(rm);
        if(rb==0)
        {
            if(rc&0x80000000)
            {
                do_cflag_bit(1);
                rc=~0;
            }
            else
            {
                do_cflag_bit(0);
                rc=0;
            }
        }
        else
        {
            do_cflag_bit(rc&(1<<(rb-1)));
            ra=rc&0x80000000;
            rc>>=rb;
            if(ra) //asr, sign is shifted in
            {
                rc|=(~0)<<(32-rb);
            }
        }
        write_register(rd,rc);
        do_nflag(rc);
        do_zflag(rc);
        return(0);
    }

    //ASR(2) two register
    if((inst&0xFFC0)==0x4100)
    {
        rd=(inst>>0)&0x07;
        rs=(inst>>3)&0x07;
if(DISS) fprintf(stderr,"asrs r%u,r%u\n",rd,rs);
        rc=read_register(rd);
        rb=read_register(rs);
        rb&=0xFF;
        if(rb==0)
        {
        }
        else if(rb<32)
        {
            do_cflag_bit(rc&(1<<(rb-1)));
            ra=rc&0x80000000;
            rc>>=rb;
            if(ra) //asr, sign is shifted in
            {
                rc|=(~0)<<(32-rb);
            }
        }
        else
        {
            if(rc&0x80000000)
            {
                do_cflag_bit(1);
                rc=(~0);
            }
            else
            {
                do_cflag_bit(0);
                rc=0;
            }
        }
        write_register(rd,rc);
        do_nflag(rc);
        do_zflag(rc);
        return(0);
    }

    //B(1) conditional branch
    if((inst&0xF000)==0xD000)
    {
        rb=(inst>>0)&0xFF;
        if(rb&0x80) rb|=(~0)<<8;
        op=(inst>>8)&0xF;
        rb<<=1;
        rb+=pc;
        rb+=2;
        switch(op)
        {
            case 0x0: //b eq  z set
if(DISS) fprintf(stderr,"beq 0x%08X\n",rb-3);
                if(cpsr&CPSR_Z)
                {
                    write_register(15,rb);
                }
                return(0);

            case 0x1: //b ne  z clear
if(DISS) fprintf(stderr,"bne 0x%08X\n",rb-3);
                if(!(cpsr&CPSR_Z))
                {
                    write_register(15,rb);
                }
                return(0);

            case 0x2: //b cs c set
if(DISS) fprintf(stderr,"bcs 0x%08X\n",rb-3);
                if(cpsr&CPSR_C)
                {
                    write_register(15,rb);
                }
                return(0);

            case 0x3: //b cc c clear
if(DISS) fprintf(stderr,"bcc 0x%08X\n",rb-3);
                if(!(cpsr&CPSR_C))
                {
                    write_register(15,rb);
                }
                return(0);

            case 0x4: //b mi n set
if(DISS) fprintf(stderr,"bmi 0x%08X\n",rb-3);
                if(cpsr&CPSR_N)
                {
                    write_register(15,rb);
                }
                return(0);

            case 0x5: //b pl n clear
if(DISS) fprintf(stderr,"bpl 0x%08X\n",rb-3);
                if(!(cpsr&CPSR_N))
                {
                    write_register(15,rb);
                }
                return(0);


            case 0x6: //b vs v set
if(DISS) fprintf(stderr,"bvs 0x%08X\n",rb-3);
                if(cpsr&CPSR_V)
                {
                    write_register(15,rb);
                }
                return(0);

            case 0x7: //b vc v clear
if(DISS) fprintf(stderr,"bvc 0x%08X\n",rb-3);
                if(!(cpsr&CPSR_V))
                {
                    write_register(15,rb);
                }
                return(0);


            case 0x8: //b hi c set z clear
if(DISS) fprintf(stderr,"bhi 0x%08X\n",rb-3);
                if((cpsr&CPSR_C)&&(!(cpsr&CPSR_Z)))
                {
                    write_register(15,rb);
                }
                return(0);

            case 0x9: //b ls c clear or z set
if(DISS) fprintf(stderr,"bls 0x%08X\n",rb-3);
                if((cpsr&CPSR_Z)||(!(cpsr&CPSR_C)))
                {
                    write_register(15,rb);
                }
                return(0);

            case 0xA: //b ge N == V
if(DISS) fprintf(stderr,"bge 0x%08X\n",rb-3);
                ra=0;
                if(  (cpsr&CPSR_N) &&  (cpsr&CPSR_V) ) ra++;
                if((!(cpsr&CPSR_N))&&(!(cpsr&CPSR_V))) ra++;
                if(ra)
                {
                    write_register(15,rb);
                }
                return(0);

            case 0xB: //b lt N != V
if(DISS) fprintf(stderr,"blt 0x%08X\n",rb-3);
                ra=0;
                if((!(cpsr&CPSR_N))&&(cpsr&CPSR_V)) ra++;
                if((!(cpsr&CPSR_V))&&(cpsr&CPSR_N)) ra++;
                if(ra)
                {
                    write_register(15,rb);
                }
                return(0);

            case 0xC: //b gt Z==0 and N == V
if(DISS) fprintf(stderr,"bgt 0x%08X\n",rb-3);
                ra=0;
                if(  (cpsr&CPSR_N) &&  (cpsr&CPSR_V) ) ra++;
                if((!(cpsr&CPSR_N))&&(!(cpsr&CPSR_V))) ra++;
                if(cpsr&CPSR_Z) ra=0;
                if(ra)
                {
                    write_register(15,rb);
                }
                return(0);

            case 0xD: //b le Z==1 or N != V
if(DISS) fprintf(stderr,"ble 0x%08X\n",rb-3);
                ra=0;
                if((!(cpsr&CPSR_N))&&(cpsr&CPSR_V)) ra++;
                if((!(cpsr&CPSR_V))&&(cpsr&CPSR_N)) ra++;
                if(cpsr&CPSR_Z) ra++;
                if(ra)
                {
                    write_register(15,rb);
                }
                return(0);

            case 0xE:
                //undefined instruction
                break;
            case 0xF:
                //swi
                break;
        }
    }

    //B(2) unconditional branch
    if((inst&0xF800)==0xE000)
    {
        rb=(inst>>0)&0x7FF;
        if(rb&(1<<10)) rb|=(~0)<<11;
        rb<<=1;
        rb+=pc;
        rb+=2;
if(DISS) fprintf(stderr,"B 0x%08X\n",rb-3);
        write_register(15,rb);
        return(0);
    }

    //BIC
    if((inst&0xFFC0)==0x4380)
    {
        rd=(inst>>0)&0x7;
        rm=(inst>>3)&0x7;
if(DISS) fprintf(stderr,"bics r%u,r%u\n",rd,rm);
        ra=read_register(rd);
        rb=read_register(rm);
        rc=ra&(~rb);
        write_register(rd,rc);
        do_nflag(rc);
        do_zflag(rc);
        return(0);
    }

    //BKPT
    if((inst&0xFF00)==0xBE00)
    {
        rb=(inst>>0)&0xFF;
        fprintf(stderr,"bkpt 0x%02X\n",rb);
        return(1);
    }

    //BL/BLX(1)
    if((inst&0xE000)==0xE000) //BL,BLX
    {
        if((inst&0x1800)==0x1000) //H=b10
        {
if(DISS) fprintf(stderr,"\n");
            halfadd=inst;
            return(0);
        }
        else
        if((inst&0x1800)==0x1800) //H=b11
        {
            //branch to thumb
            rb=halfadd&((1<<11)-1);
            if(rb&1<<10) rb|=(~((1<<11)-1)); //sign extend
            rb<<=11;
            rb|=inst&((1<<11)-1);
            rb<<=1;
            rb+=pc;
if(DISS) fprintf(stderr,"bl 0x%08X\n",rb-3);
            write_register(14,pc-2);
            write_register(15,rb);
            return(0);
        }
        else
        if((inst&0x1800)==0x0800) //H=b01
        {
            fprintf(stderr,"cannot branch to arm 0x%08X 0x%04X\n",pc,inst);
            return(1);
        }
    }

    //BLX(2)
    if((inst&0xFF87)==0x4780)
    {
        rm=(inst>>3)&0xF;
if(DISS) fprintf(stderr,"blx r%u\n",rm);
        rc=read_register(rm);
//fprintf(stderr,"blx r%u 0x%X 0x%X\n",rm,rc,pc);
        rc+=2;
        if(rc&1)
        {
            write_register(14,pc-2);
            write_register(15,rc);
            return(0);
        }
        else
        {
            fprintf(stderr,"cannot branch to arm 0x%08X 0x%04X\n",pc,inst);
            return(1);
        }
    }

    //BX
    if((inst&0xFF87)==0x4700)
    {
        rm=(inst>>3)&0xF;
if(DISS) fprintf(stderr,"bx r%u\n",rm);
        rc=read_register(rm);
        rc+=2;
//fprintf(stderr,"bx r%u 0x%X 0x%X\n",rm,rc,pc);
        if(rc&1)
        {
            write_register(15,rc);
            return(0);
        }
        else
        {
            fprintf(stderr,"cannot branch to arm 0x%08X 0x%04X\n",pc,inst);
            return(1);
        }
    }

    //CMN
    if((inst&0xFFC0)==0x42C0)
    {
        rn=(inst>>0)&0x7;
        rm=(inst>>3)&0x7;
if(DISS) fprintf(stderr,"cmns r%u,r%u\n",rn,rm);
        ra=read_register(rn);
        rb=read_register(rm);
        rc=ra+rb;
        do_nflag(rc);
        do_zflag(rc);
        do_cflag(ra,rb,0);
        do_add_vflag(ra,rb,rc);
        return(0);
    }

    //CMP(1) compare immediate
    if((inst&0xF800)==0x2800)
    {
        rb=(inst>>0)&0xFF;
        rn=(inst>>8)&0x07;
if(DISS) fprintf(stderr,"cmp r%u,#0x%02X\n",rn,rb);
        ra=read_register(rn);
        rc=ra-rb;
//fprintf(stderr,"0x%08X 0x%08X\n",ra,rb);
        do_nflag(rc);
        do_zflag(rc);
        do_cflag(ra,~rb,1);
        do_sub_vflag(ra,rb,rc);
        return(0);
    }

    //CMP(2) compare register
    if((inst&0xFFC0)==0x4280)
    {
        rn=(inst>>0)&0x7;
        rm=(inst>>3)&0x7;
if(DISS) fprintf(stderr,"cmps r%u,r%u\n",rn,rm);
        ra=read_register(rn);
        rb=read_register(rm);
        rc=ra-rb;
//fprintf(stderr,"0x%08X 0x%08X\n",ra,rb);
        do_nflag(rc);
        do_zflag(rc);
        do_cflag(ra,~rb,1);
        do_sub_vflag(ra,rb,rc);
        return(0);
    }

    //CMP(3) compare high register
    if((inst&0xFF00)==0x4500)
    {
        if(((inst>>6)&3)==0x0)
        {
            //UNPREDICTABLE
        }
        rn=(inst>>0)&0x7;
        rn|=(inst>>4)&0x8;
        if(rn==0xF)
        {
            //UNPREDICTABLE
        }
        rm=(inst>>3)&0xF;
if(DISS) fprintf(stderr,"cmps r%u,r%u\n",rn,rm);
        ra=read_register(rn);
        rb=read_register(rm);
        rc=ra-rb;
        do_nflag(rc);
        do_zflag(rc);
        do_cflag(ra,~rb,1);
        do_sub_vflag(ra,rb,rc);
if(0)
{
    if(cpsr&CPSR_N) fprintf(stderr,"N"); else fprintf(stderr,"n");
    if(cpsr&CPSR_Z) fprintf(stderr,"Z"); else fprintf(stderr,"z");
    if(cpsr&CPSR_C) fprintf(stderr,"C"); else fprintf(stderr,"c");
    if(cpsr&CPSR_V) fprintf(stderr,"V"); else fprintf(stderr,"v");
    fprintf(stderr," -- 0x%08X 0x%08X\n",ra,rb);
}
        return(0);
    }

    //CPS
    if((inst&0xFFE8)==0xB660)
    {
if(DISS) fprintf(stderr,"cps TODO\n");
        return(1);
    }

    //CPY copy high register
    if((inst&0xFFC0)==0x4600)
    {
        //same as mov except you can use both low registers
        //going to let mov handle high registers
        rd=(inst>>0)&0x7;
        rm=(inst>>3)&0x7;
if(DISS) fprintf(stderr,"cpy r%u,r%u\n",rd,rm);
        rc=read_register(rm);
        write_register(rd,rc);
        return(0);
    }

    //EOR
    if((inst&0xFFC0)==0x4040)
    {
        rd=(inst>>0)&0x7;
        rm=(inst>>3)&0x7;
if(DISS) fprintf(stderr,"eors r%u,r%u\n",rd,rm);
        ra=read_register(rd);
        rb=read_register(rm);
        rc=ra^rb;
        write_register(rd,rc);
        do_nflag(rc);
        do_zflag(rc);
        return(0);
    }

    //LDMIA
    if((inst&0xF800)==0xC800)
    {
        rn=(inst>>8)&0x7;
if(DISS)
{
    fprintf(stderr,"ldmia r%u!,{",rn);
    for(ra=0,rb=0x01,rc=0;rb;rb=(rb<<1)&0xFF,ra++)
    {
        if(inst&rb)
        {
            if(rc) fprintf(stderr,",");
            fprintf(stderr,"r%u",ra);
            rc++;
        }
    }
    fprintf(stderr,"}\n");
}
        sp=read_register(rn);
        for(ra=0,rb=0x01;rb;rb=(rb<<1)&0xFF,ra++)
        {
            if(inst&rb)
            {
                write_register(ra,read32(sp));
                sp+=4;
            }
        }
        write_register(rn,sp);
        return(0);
    }

    //LDR(1) two register immediate
    if((inst&0xF800)==0x6800)
    {
        rd=(inst>>0)&0x07;
        rn=(inst>>3)&0x07;
        rb=(inst>>6)&0x1F;
        rb<<=2;
if(DISS) fprintf(stderr,"ldr r%u,[r%u,#0x%X]\n",rd,rn,rb);
        rb=read_register(rn)+rb;
        rc=read32(rb);
        write_register(rd,rc);
        return(0);
    }

    //LDR(2) three register
    if((inst&0xFE00)==0x5800)
    {
        rd=(inst>>0)&0x7;
        rn=(inst>>3)&0x7;
        rm=(inst>>6)&0x7;
if(DISS) fprintf(stderr,"ldr r%u,[r%u,r%u]\n",rd,rn,rm);
        rb=read_register(rn)+read_register(rm);
        rc=read32(rb);
        write_register(rd,rc);
        return(0);
    }

    //LDR(3)
    if((inst&0xF800)==0x4800)
    {
        rb=(inst>>0)&0xFF;
        rd=(inst>>8)&0x07;
        rb<<=2;
if(DISS) fprintf(stderr,"ldr r%u,[PC+#0x%X] ",rd,rb);
        ra=read_register(15);
        ra&=~3;
        rb+=ra;
if(DISS) fprintf(stderr,";@ 0x%X\n",rb);
        rc=read32(rb);
        write_register(rd,rc);
        return(0);
    }

    //LDR(4)
    if((inst&0xF800)==0x9800)
    {
        rb=(inst>>0)&0xFF;
        rd=(inst>>8)&0x07;
        rb<<=2;
if(DISS) fprintf(stderr,"ldr r%u,[SP+#0x%X]\n",rd,rb);
        ra=read_register(13);
        //ra&=~3;
        rb+=ra;
        rc=read32(rb);
        write_register(rd,rc);
        return(0);
    }

    //LDRB(1)
    if((inst&0xF800)==0x7800)
    {
        rd=(inst>>0)&0x07;
        rn=(inst>>3)&0x07;
        rb=(inst>>6)&0x1F;
if(DISS) fprintf(stderr,"ldrb r%u,[r%u,#0x%X]\n",rd,rn,rb);
        rb=read_register(rn)+rb;
        rc=read16(rb&(~1));
        if(rb&1)
        {
            rc>>=8;
        }
        else
        {
        }
        write_register(rd,rc&0xFF);
        return(0);
    }

    //LDRB(2)
    if((inst&0xFE00)==0x5C00)
    {
        rd=(inst>>0)&0x7;
        rn=(inst>>3)&0x7;
        rm=(inst>>6)&0x7;
if(DISS) fprintf(stderr,"ldrb r%u,[r%u,r%u]\n",rd,rn,rm);
        rb=read_register(rn)+read_register(rm);
        rc=read16(rb&(~1));
        if(rb&1)
        {
            rc>>=8;
        }
        else
        {
        }
        write_register(rd,rc&0xFF);
        return(0);
    }

    //LDRH(1)
    if((inst&0xF800)==0x8800)
    {
        rd=(inst>>0)&0x07;
        rn=(inst>>3)&0x07;
        rb=(inst>>6)&0x1F;
        rb<<=1;
if(DISS) fprintf(stderr,"ldrh r%u,[r%u,#0x%X]\n",rd,rn,rb);
        rb=read_register(rn)+rb;
        rc=read16(rb);
        write_register(rd,rc&0xFFFF);
        return(0);
    }

    //LDRH(2)
    if((inst&0xFE00)==0x5A00)
    {
        rd=(inst>>0)&0x7;
        rn=(inst>>3)&0x7;
        rm=(inst>>6)&0x7;
if(DISS) fprintf(stderr,"ldrh r%u,[r%u,r%u]\n",rd,rn,rm);
        rb=read_register(rn)+read_register(rm);
        rc=read16(rb);
        write_register(rd,rc&0xFFFF);
        return(0);
    }

    //LDRSB
    if((inst&0xFE00)==0x5600)
    {
        rd=(inst>>0)&0x7;
        rn=(inst>>3)&0x7;
        rm=(inst>>6)&0x7;
if(DISS) fprintf(stderr,"ldrsb r%u,[r%u,r%u]\n",rd,rn,rm);
        rb=read_register(rn)+read_register(rm);
        rc=read16(rb&(~1));
        if(rb&1)
        {
            rc>>=8;
        }
        else
        {
        }
        rc&=0xFF;
        if(rc&0x80) rc|=((~0)<<8);
        write_register(rd,rc);
        return(0);
    }

    //LDRSH
    if((inst&0xFE00)==0x5E00)
    {
        rd=(inst>>0)&0x7;
        rn=(inst>>3)&0x7;
        rm=(inst>>6)&0x7;
if(DISS) fprintf(stderr,"ldrsh r%u,[r%u,r%u]\n",rd,rn,rm);
        rb=read_register(rn)+read_register(rm);
        rc=read16(rb);
        rc&=0xFFFF;
        if(rc&0x8000) rc|=((~0)<<16);
        write_register(rd,rc);
        return(0);
    }

    //LSL(1)
    if((inst&0xF800)==0x0000)
    {
        rd=(inst>>0)&0x07;
        rm=(inst>>3)&0x07;
        rb=(inst>>6)&0x1F;
if(DISS) fprintf(stderr,"lsls r%u,r%u,#0x%X\n",rd,rm,rb);
        rc=read_register(rm);
        if(rb==0)
        {
            //if immed_5 == 0
            //C unnaffected
            //result not shifted
        }
        else
        {
            //else immed_5 > 0
            do_cflag_bit(rc&(1<<(32-rb)));
            rc<<=rb;
        }
        write_register(rd,rc);
        do_nflag(rc);
        do_zflag(rc);
        return(0);
    }

    //LSL(2) two register
    if((inst&0xFFC0)==0x4080)
    {
        rd=(inst>>0)&0x07;
        rs=(inst>>3)&0x07;
if(DISS) fprintf(stderr,"lsls r%u,r%u\n",rd,rs);
        rc=read_register(rd);
        rb=read_register(rs);
        rb&=0xFF;
        if(rb==0)
        {
        }
        else if(rb<32)
        {
            do_cflag_bit(rc&(1<<(32-rb)));
            rc<<=rb;
        }
        else if(rb==32)
        {
            do_cflag_bit(rc&1);
            rc=0;
        }
        else
        {
            do_cflag_bit(0);
            rc=0;
        }
        write_register(rd,rc);
        do_nflag(rc);
        do_zflag(rc);
        return(0);
    }

    //LSR(1) two register immediate
    if((inst&0xF800)==0x0800)
    {
        rd=(inst>>0)&0x07;
        rm=(inst>>3)&0x07;
        rb=(inst>>6)&0x1F;
if(DISS) fprintf(stderr,"lsrs r%u,r%u,#0x%X\n",rd,rm,rb);
        rc=read_register(rm);
        if(rb==0)
        {
            do_cflag_bit(rc&0x80000000);
            rc=0;
        }
        else
        {
            do_cflag_bit(rc&(1<<(rb-1)));
            rc>>=rb;
        }
        write_register(rd,rc);
        do_nflag(rc);
        do_zflag(rc);
        return(0);
    }

    //LSR(2) two register
    if((inst&0xFFC0)==0x40C0)
    {
        rd=(inst>>0)&0x07;
        rs=(inst>>3)&0x07;
if(DISS) fprintf(stderr,"lsrs r%u,r%u\n",rd,rs);
        rc=read_register(rd);
        rb=read_register(rs);
        rb&=0xFF;
        if(rb==0)
        {
        }
        else if(rb<32)
        {
            do_cflag_bit(rc&(1<<(32-rb)));
            rc>>=rb;
        }
        else if(rb==32)
        {
            do_cflag_bit(rc&0x80000000);
            rc=0;
        }
        else
        {
            do_cflag_bit(0);
            rc=0;
        }
        write_register(rd,rc);
        do_nflag(rc);
        do_zflag(rc);
        return(0);
    }

    //MOV(1) immediate
    if((inst&0xF800)==0x2000)
    {
        rb=(inst>>0)&0xFF;
        rd=(inst>>8)&0x07;
if(DISS) fprintf(stderr,"movs r%u,#0x%02X\n",rd,rb);
        write_register(rd,rb);
        do_nflag(rb);
        do_zflag(rb);
        return(0);
    }

    //MOV(2) two low registers
    if((inst&0xFFC0)==0x1C00)
    {
        rd=(inst>>0)&7;
        rn=(inst>>3)&7;
if(DISS) fprintf(stderr,"movs r%u,r%u\n",rd,rn);
        rc=read_register(rn);
//fprintf(stderr,"0x%08X\n",rc);
        write_register(rd,rc);
        do_nflag(rc);
        do_zflag(rc);
        do_cflag_bit(0);
        do_vflag_bit(0);
        return(0);
    }

    //MOV(3)
    if((inst&0xFF00)==0x4600)
    {
        rd=(inst>>0)&0x7;
        rd|=(inst>>4)&0x8;
        rm=(inst>>3)&0xF;
if(DISS) fprintf(stderr,"mov r%u,r%u\n",rd,rm);
        rc=read_register(rm);
        write_register(rd,rc);
        return(0);
    }

    //MUL
    if((inst&0xFFC0)==0x4340)
    {
        rd=(inst>>0)&0x7;
        rm=(inst>>3)&0x7;
if(DISS) fprintf(stderr,"muls r%u,r%u\n",rd,rm);
        ra=read_register(rd);
        rb=read_register(rm);
        rc=ra*rb;
        write_register(rd,rc);
        do_nflag(rc);
        do_zflag(rc);
        return(0);
    }

    //MVN
    if((inst&0xFFC0)==0x43C0)
    {
        rd=(inst>>0)&0x7;
        rm=(inst>>3)&0x7;
if(DISS) fprintf(stderr,"mvns r%u,r%u\n",rd,rm);
        ra=read_register(rm);
        rc=(~ra);
        write_register(rd,rc);
        do_nflag(rc);
        do_zflag(rc);
        return(0);
    }

    //NEG
    if((inst&0xFFC0)==0x4240)
    {
        rd=(inst>>0)&0x7;
        rm=(inst>>3)&0x7;
if(DISS) fprintf(stderr,"negs r%u,r%u\n",rd,rm);
        ra=read_register(rm);
        rc=0-ra;
        write_register(rd,rc);
        do_nflag(rc);
        do_zflag(rc);
        do_cflag(0,~ra,1);
        do_sub_vflag(0,ra,rc);
        return(0);
    }

    //ORR
    if((inst&0xFFC0)==0x4300)
    {
        rd=(inst>>0)&0x7;
        rm=(inst>>3)&0x7;
if(DISS) fprintf(stderr,"orrs r%u,r%u\n",rd,rm);
        ra=read_register(rd);
        rb=read_register(rm);
        rc=ra|rb;
        write_register(rd,rc);
        do_nflag(rc);
        do_zflag(rc);
        return(0);
    }


    //POP
    if((inst&0xFE00)==0xBC00)
    {
if(DISS)
{
    fprintf(stderr,"pop {");
    for(ra=0,rb=0x01,rc=0;rb;rb=(rb<<1)&0xFF,ra++)
    {
        if(inst&rb)
        {
            if(rc) fprintf(stderr,",");
            fprintf(stderr,"r%u",ra);
            rc++;
        }
    }
    if(inst&0x100)
    {
        if(rc) fprintf(stderr,",");
        fprintf(stderr,"pc");
    }
    fprintf(stderr,"}\n");
}

        sp=read_register(13);
        for(ra=0,rb=0x01;rb;rb=(rb<<1)&0xFF,ra++)
        {
            if(inst&rb)
            {
                write_register(ra,read32(sp));
                sp+=4;
            }
        }
        if(inst&0x100)
        {
            rc=read32(sp);
            rc+=2;
            write_register(15,rc);
            sp+=4;
        }
        write_register(13,sp);
        return(0);
    }

    //PUSH
    if((inst&0xFE00)==0xB400)
    {

if(DISS)
{
    fprintf(stderr,"push {");
    for(ra=0,rb=0x01,rc=0;rb;rb=(rb<<1)&0xFF,ra++)
    {
        if(inst&rb)
        {
            if(rc) fprintf(stderr,",");
            fprintf(stderr,"r%u",ra);
            rc++;
        }
    }
    if(inst&0x100)
    {
        if(rc) fprintf(stderr,",");
        fprintf(stderr,"lr");
    }
    fprintf(stderr,"}\n");
}

        sp=read_register(13);
//fprintf(stderr,"sp 0x%08X\n",sp);
        for(ra=0,rb=0x01,rc=0;rb;rb=(rb<<1)&0xFF,ra++)
        {
            if(inst&rb)
            {
                rc++;
            }
        }
        if(inst&0x100) rc++;
        rc<<=2;
        sp-=rc;
        rd=sp;
        for(ra=0,rb=0x01;rb;rb=(rb<<1)&0xFF,ra++)
        {
            if(inst&rb)
            {
                write32(rd,read_register(ra));
                rd+=4;
            }
        }
        if(inst&0x100)
        {
            write32(rd,read_register(14));
        }
        write_register(13,sp);
        return(0);
    }

    //REV
    if((inst&0xFFC0)==0xBA00)
    {
        rd=(inst>>0)&0x7;
        rn=(inst>>3)&0x7;
if(DISS) fprintf(stderr,"rev r%u,r%u\n",rd,rn);
        ra=read_register(rn);
        rc =((ra>> 0)&0xFF)<<24;
        rc|=((ra>> 8)&0xFF)<<16;
        rc|=((ra>>16)&0xFF)<< 8;
        rc|=((ra>>24)&0xFF)<< 0;
        write_register(rd,rc);
        return(0);
    }

    //REV16
    if((inst&0xFFC0)==0xBA40)
    {
        rd=(inst>>0)&0x7;
        rn=(inst>>3)&0x7;
if(DISS) fprintf(stderr,"rev16 r%u,r%u\n",rd,rn);
        ra=read_register(rn);
        rc =((ra>> 0)&0xFF)<< 8;
        rc|=((ra>> 8)&0xFF)<< 0;
        rc|=((ra>>16)&0xFF)<<24;
        rc|=((ra>>24)&0xFF)<<16;
        write_register(rd,rc);
        return(0);
    }

    //REVSH
    if((inst&0xFFC0)==0xBAC0)
    {
        rd=(inst>>0)&0x7;
        rn=(inst>>3)&0x7;
if(DISS) fprintf(stderr,"revsh r%u,r%u\n",rd,rn);
        ra=read_register(rn);
        rc =((ra>> 0)&0xFF)<< 8;
        rc|=((ra>> 8)&0xFF)<< 0;
        if(rc&0x8000) rc|=0xFFFF0000;
        else          rc&=0x0000FFFF;
        write_register(rd,rc);
        return(0);
    }

    //ROR
    if((inst&0xFFC0)==0x41C0)
    {
        rd=(inst>>0)&0x7;
        rs=(inst>>3)&0x7;
if(DISS) fprintf(stderr,"rors r%u,r%u\n",rd,rs);
        rc=read_register(rd);
        ra=read_register(rs);
        ra&=0xFF;
        if(ra==0)
        {
        }
        else
        {
            ra&=0x1F;
            if(ra==0)
            {
                do_cflag_bit(rc&0x80000000);
            }
            else
            {
                do_cflag_bit(rc&(1<<(ra-1)));
                rb=rc<<(32-ra);
                rc>>=ra;
                rc|=rb;
            }
        }
        write_register(rd,rc);
        do_nflag(rc);
        do_zflag(rc);
        return(0);
    }

    //SBC
    if((inst&0xFFC0)==0x4180)
    {
        rd=(inst>>0)&0x7;
        rm=(inst>>3)&0x7;
if(DISS) fprintf(stderr,"sbc r%u,r%u\n",rd,rm);
        ra=read_register(rd);
        rb=read_register(rm);
        rc=ra-rb;
        if(!(cpsr&CPSR_C)) rc--;
        write_register(rd,rc);
        do_nflag(rc);
        do_zflag(rc);
        do_cflag(ra,rb,0);
        do_sub_vflag(ra,rb,rc);
        return(0);
    }

    //SETEND
    if((inst&0xFFF7)==0xB650)
    {
        fprintf(stderr,"setend not implemented\n");
        return(1);
    }

    //STMIA
    if((inst&0xF800)==0xC000)
    {
        rn=(inst>>8)&0x7;

if(DISS)
{
    fprintf(stderr,"stmia r%u!,{",rn);
    for(ra=0,rb=0x01,rc=0;rb;rb=(rb<<1)&0xFF,ra++)
    {
        if(inst&rb)
        {
            if(rc) fprintf(stderr,",");
            fprintf(stderr,"r%u",ra);
            rc++;
        }
    }
    fprintf(stderr,"}\n");
}
        sp=read_register(rn);
        for(ra=0,rb=0x01;rb;rb=(rb<<1)&0xFF,ra++)
        {
            if(inst&rb)
            {
                write32(sp,read_register(ra));
                sp+=4;
            }
        }
        write_register(rn,sp);
        return(0);
    }

    //STR(1)
    if((inst&0xF800)==0x6000)
    {
        rd=(inst>>0)&0x07;
        rn=(inst>>3)&0x07;
        rb=(inst>>6)&0x1F;
        rb<<=2;
if(DISS) fprintf(stderr,"str r%u,[r%u,#0x%X]\n",rd,rn,rb);
        rb=read_register(rn)+rb;
        rc=read_register(rd);
        write32(rb,rc);
        return(0);
    }

    //STR(2)
    if((inst&0xFE00)==0x5000)
    {
        rd=(inst>>0)&0x7;
        rn=(inst>>3)&0x7;
        rm=(inst>>6)&0x7;
if(DISS) fprintf(stderr,"str r%u,[r%u,r%u]\n",rd,rn,rm);
        rb=read_register(rn)+read_register(rm);
        rc=read_register(rd);
        write32(rb,rc);
        return(0);
    }

    //STR(3)
    if((inst&0xF800)==0x9000)
    {
        rb=(inst>>0)&0xFF;
        rd=(inst>>8)&0x07;
        rb<<=2;
if(DISS) fprintf(stderr,"str r%u,[SP,#0x%X]\n",rd,rb);
        rb=read_register(13)+rb;
//fprintf(stderr,"0x%08X\n",rb);
        rc=read_register(rd);
        write32(rb,rc);
        return(0);
    }

    //STRB(1)
    if((inst&0xF800)==0x7000)
    {
        rd=(inst>>0)&0x07;
        rn=(inst>>3)&0x07;
        rb=(inst>>6)&0x1F;
if(DISS) fprintf(stderr,"strb r%u,[r%u,#0x%X]\n",rd,rn,rb);
        rb=read_register(rn)+rb;
        rc=read_register(rd);
        ra=read16(rb&(~1));
        if(rb&1)
        {
            ra&=0x00FF;
            ra|=rc<<8;
        }
        else
        {
            ra&=0xFF00;
            ra|=rc&0x00FF;
        }
        write16(rb&(~1),ra&0xFFFF);
        return(0);
    }

    //STRB(2)
    if((inst&0xFE00)==0x5400)
    {
        rd=(inst>>0)&0x7;
        rn=(inst>>3)&0x7;
        rm=(inst>>6)&0x7;
if(DISS) fprintf(stderr,"strb r%u,[r%u,r%u]\n",rd,rn,rm);
        rb=read_register(rn)+read_register(rm);
        rc=read_register(rd);
        ra=read16(rb&(~1));
        if(rb&1)
        {
            ra&=0x00FF;
            ra|=rc<<8;
        }
        else
        {
            ra&=0xFF00;
            ra|=rc&0x00FF;
        }
        write16(rb&(~1),ra&0xFFFF);
        return(0);
    }

    //STRH(1)
    if((inst&0xF800)==0x8000)
    {
        rd=(inst>>0)&0x07;
        rn=(inst>>3)&0x07;
        rb=(inst>>6)&0x1F;
        rb<<1;
if(DISS) fprintf(stderr,"strh r%u,[r%u,#0x%X]\n",rd,rn,rb);
        rb=read_register(rn)+rb;
        rc=read_register(rd);
        write16(rb,rc&0xFFFF);
        return(0);
    }

    //STRH(2)
    if((inst&0xFE00)==0x5200)
    {
        rd=(inst>>0)&0x7;
        rn=(inst>>3)&0x7;
        rm=(inst>>6)&0x7;
if(DISS) fprintf(stderr,"strh r%u,[r%u,r%u]\n",rd,rn,rm);
        rb=read_register(rn)+read_register(rm);
        rc=read_register(rd);
        write16(rb,rc&0xFFFF);
        return(0);
    }

    //SUB(1)
    if((inst&0xFE00)==0x1E00)
    {
        rd=(inst>>0)&7;
        rn=(inst>>3)&7;
        rb=(inst>>6)&7;
if(DISS) fprintf(stderr,"subs r%u,r%u,#0x%X\n",rd,rn,rb);
        ra=read_register(rn);
        rc=ra-rb;
        write_register(rd,rc);
        do_nflag(rc);
        do_zflag(rc);
        do_cflag(ra,~rb,1);
        do_sub_vflag(ra,rb,rc);
        return(0);
    }

    //SUB(2)
    if((inst&0xF800)==0x3800)
    {
        rb=(inst>>0)&0xFF;
        rd=(inst>>8)&0x07;
if(DISS) fprintf(stderr,"subs r%u,#0x%02X\n",rd,rb);
        ra=read_register(rd);
        rc=ra-rb;
        write_register(rd,rc);
        do_nflag(rc);
        do_zflag(rc);
        do_cflag(ra,~rb,1);
        do_sub_vflag(ra,rb,rc);
        return(0);
    }

    //SUB(3)
    if((inst&0xFE00)==0x1A00)
    {
        rd=(inst>>0)&0x7;
        rn=(inst>>3)&0x7;
        rm=(inst>>6)&0x7;
if(DISS) fprintf(stderr,"subs r%u,r%u,r%u\n",rd,rn,rm);
        ra=read_register(rn);
        rb=read_register(rm);
        rc=ra-rb;
        write_register(rd,rc);
        do_nflag(rc);
        do_zflag(rc);
        do_cflag(ra,~rb,1);
        do_sub_vflag(ra,rb,rc);
        return(0);
    }

    //SUB(4)
    if((inst&0xFF80)==0xB080)
    {
        rb=inst&0x7F;
        rb<<=2;
if(DISS) fprintf(stderr,"sub SP,#0x%02X\n",rb);
        ra=read_register(13);
        ra-=rb;
        write_register(13,ra);
        return(0);
    }

    //SWI
    if((inst&0xFF00)==0xDF00)
    {
        rb=inst&0xFF;
if(DISS) fprintf(stderr,"swi 0x%02X\n",rb);
        fprintf(stderr,"\n\nswi 0x%02X\n",rb);
        return(1);
    }

    //SXTB
    if((inst&0xFFC0)==0xB240)
    {
        rd=(inst>>0)&0x7;
        rm=(inst>>3)&0x7;
if(DISS) fprintf(stderr,"sxtb r%u,r%u\n",rd,rm);
        ra=read_register(rm);
        rc=ra&0xFF;
        if(rc&0x80) rc|=(~0)<<8;
        write_register(rd,rc);
        return(0);
    }

    //SXTH
    if((inst&0xFFC0)==0xB200)
    {
        rd=(inst>>0)&0x7;
        rm=(inst>>3)&0x7;
if(DISS) fprintf(stderr,"sxth r%u,r%u\n",rd,rm);
        ra=read_register(rm);
        rc=ra&0xFFFF;
        if(rc&0x8000) rc|=(~0)<<16;
        write_register(rd,rc);
        return(0);
    }

    //TST
    if((inst&0xFFC0)==0x4200)
    {
        rn=(inst>>0)&0x7;
        rm=(inst>>3)&0x7;
if(DISS) fprintf(stderr,"tst r%u,r%u\n",rn,rm);
        ra=read_register(rn);
        rb=read_register(rm);
        rc=ra&rb;
        do_nflag(rc);
        do_zflag(rc);
        return(0);
    }

    //UXTB
    if((inst&0xFFC0)==0xB2C0)
    {
        rd=(inst>>0)&0x7;
        rm=(inst>>3)&0x7;
if(DISS) fprintf(stderr,"uxtb r%u,r%u\n",rd,rm);
        ra=read_register(rm);
        rc=ra&0xFF;
        write_register(rd,rc);
        return(0);
    }

    //UXTH
    if((inst&0xFFC0)==0xB280)
    {
        rd=(inst>>0)&0x7;
        rm=(inst>>3)&0x7;
if(DISS) fprintf(stderr,"uxth r%u,r%u\n",rd,rm);
        ra=read_register(rm);
        rc=ra&0xFFFF;
        write_register(rd,rc);
        return(0);
    }

    fprintf(stderr,"invalid instruction 0x%08X 0x%04X\n",pc,inst);
    return(1);
}
//-------------------------------------------------------------------
int reset ( void )
{
    memset(ram,0xFF,sizeof(ram));

    cpsr=CPSR_T|CPSR_I|CPSR_F|MODE_SVC;

    reg_svc[13]=fetch32(0x00000000); //cortex-m3
    reg_sys[15]=fetch32(0x00000004); //cortex-m3
    reg_sys[15]+=2;

    instructions=0;
    fetches=0;
    reads=0;
    writes=0;

    return(0);
}
//-------------------------------------------------------------------
int run ( void )
{
    reset();
    while(1)
    {
        if(execute()) break;
    }
    dump_counters();
    return(0);
}
//-------------------------------------------------------------------
int main ( int argc, char *argv[] )
{
    FILE *fp;

    unsigned int ra;

    if(argc<2)
    {
        fprintf(stderr,"bin file not specified\n");
        return(1);
    }
    fp=fopen(argv[1],"rb");
    if(fp==NULL)
    {
        fprintf(stderr,"Error opening file [%s]\n",argv[1]);
        return(1);
    }
    memset(rom,0xFF,sizeof(rom));
    ra=fread(rom,1,sizeof(rom),fp);
    fclose(fp);
    memset(ram,0x00,sizeof(ram));
    run();
    return(0);
}
//-------------------------------------------------------------------
//-------------------------------------------------------------------
//-------------------------------------------------------------------



