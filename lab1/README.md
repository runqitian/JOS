# MIT 6.828 lab 1
## Resource

## Prerequisite Knowledge


Before we get started, set up the environment following the lab instructions. 
## Part 1: PC Bootstrap
What happens during after we press down the power button? Let's have a look.

* Press down the power button.  
* The motherboard will supply power to the CPU, memory and other hardware on it.  
*  The CPU will load BIOS, which is provided by the motherboard, into a specific place in memory. And CPU will execute BIOS from pysical address 0xffff0.  
* BIOS will check the hardwares on the motherboard, make sure these hardwares are well prepared. Then it will load the first sector of a bootable disk into a specific place in memory, which is 0x7c00.  
* Next, the CPU will jump to the instruction at 0x7c00, execute the bootstrap instructions. Including set up protected mode, load the kernel.  


Above summarize the bootup process, this process happens before we load the kernel. Now let's dive into some details.  

* What CPU can our OS run?  
Intel 80386 or above. 80386 CPU has some important features, such as 32 bit addressing ability(it has 32 wires connected to the memory for addressing), support segmentation and paging (need a hardware unit called MMU), 32 bit general purpose registers, etc. Before 80286, CPU has only 20 bit addressing ability, so It can only use 1MB memorry. When we bootstrap our OS on a 80386 chip, we need to switch from real mode to pretected mode, to enable those new features.

* The memory space  
<img src="http://www.runqitian.com/content/jos_lab1/p1.png" style="width: 40%; display: block; margin-left: auto; margin-right: auto;">

Above 1MB is the "Extended Memory" because earlier CPU can only access 1MB memory. For backward compatibility, we use "Low Memory" for our boot process, where 0x7c00 is located. Besides, we can also find that 0xfffff is the last command in "BIOS ROM", it will jmp to the BIOS entry point.

## Part 2: The Boot Loader
Now we arrive at 0x7c00, let's see what happens next?

The first execution code is in "boot/boot.S".

* disable interruption.
* enable A20. check [A20 - a pain from the past](https://www.win.tue.nl/~aeb/linux/kbd/A20.html), if we do not enbale it, the 21th bit of address will be tied to 0. Thus there will be some problems when we access memory above 1MB.

*  load Global Descritor Table and switch to protected mode.

```
# Switch from real to protected mode, using a bootstrap GDT
# and segment translation that makes virtual addresses 
# identical to their physical addresses, so that the 
# effective memory map does not change during the switch.
lgdt    gdtdesc
movl    %cr0, %eax
orl     $CR0_PE_ON, %eax
movl    %eax, %cr0
```
check [link](http://www.jamesmolloy.co.uk/tutorial_html/4.-The%20GDT%20and%20IDT.html) and [link](https://resources.infosecinstitute.com/handling-memory-in-protected-mode/#:~:text=To%20select%20the%20appropriate%20value,the%20linear%20address%20are%20used.&text=Keep%20in%20mind%20that%20while,itself%2C%20or%20segmentation%20with%20paging.) for details about GDT. Follow is what our GDT, there are 2 segment, their base address is 0 and limit is 4G, which means they keeps the same as pysical address.

```
# Bootstrap GDT
.p2align 2                                # force 4 byte alignment
gdt:
  # convention: must set the first entry as null.
  SEG_NULL                              # null seg
  SEG(STA_X|STA_R, 0x0, 0xffffffff)     # code seg
  SEG(STA_W, 0x0, 0xffffffff)           # data seg
gdtdesc:
  .word   0x17                            # sizeof(gdt) - 1
  .long   gdt 
```

* After switch to protected mode, we will execute at 32 bits mode. And we need to set up the segment register. The value is the byte offset of the segment info entry in GDT. After this step, the memory address will be translated by segmentation, which is called linear address.

```
# Jump to next instruction, but in 32-bit code segment.
# Switches processor into 32-bit mode.
ljmp    $PROT_MODE_CSEG, $protcse
  
.code32                     # Assemble for 32-bit mode
protcseg:
# Set up the protected-mode data segment registers
movw    $PROT_MODE_DSEG, %ax    # Our data segment selector
movw    %ax, %ds                # -> DS: Data Segment
movw    %ax, %es                # -> ES: Extra Segment
movw    %ax, %fs                # -> FS
movw    %ax, %gs                # -> GS
movw    %ax, %ss                # -> SS: Stack Segment

# Set up the stack pointer and call into C.
movl    $start, %esp
call bootmain
```

* In "boot/main.c", we read the kernel into our memory, our kernel is in ELF format and is stored on the disk starting from the 2nd sector.  
The following code read 'count' bytes at 'offset' from kernel into physical address 'pa'. Why do we need to round down physical address to sector boundary?

```
// Read 'count' bytes at 'offset' from kernel into physical address 'pa'.
// Might copy more than asked
void
readseg(uint32_t pa, uint32_t count, uint32_t offset)
{       
        uint32_t end_pa;
        
        end_pa = pa + count;
        
        // round down to sector boundary
        pa &= ~(SECTSIZE - 1);
        
        // translate from bytes to sectors, and kernel starts at sector 1
        offset = (offset / SECTSIZE) + 1;
        
        // If this is too slow, we could read lots of sectors at a time.
        // We'd write more to memory than asked, but it doesn't matter --
        // we load in increasing order.
        while (pa < end_pa) {
                // Since we haven't enabled paging yet and we're using
                // an identity segment mapping (see boot.S), we can
                // use physical addresses directly.  This won't be the
                // case once JOS enables the MMU.
                readsect((uint8_t*) pa, offset);
                pa += SECTSIZE;
                offset++;
        }
}
```
That is because when we read data from the disk, we read the whole sector into our memory, we need to round down both the offset and the pysical address, for example if offset is 0x0a, and the pysical address is 0x10000, after round down, the offset equals 0 and the pa equals 0xffff5. After reading the whole sector into memory, the real data still locates at 0x100000.

* How does the boot loader decide how many sectors it must read in order to fetch the entire kernel from disk? Where does it find this information?  

```
struct Proghdr *ph, *eph;
        
// read 1st page off disk
readseg((uint32_t) ELFHDR, SECTSIZE*8, 0);
    
// is this a valid ELF?
if (ELFHDR->e_magic != ELF_MAGIC)
        goto bad;
    
// load each program segment (ignores ph flags)
ph = (struct Proghdr *) ((uint8_t *) ELFHDR + ELFHDR->e_phoff);
eph = ph + ELFHDR->e_phnum;
for (; ph < eph; ph++)
        // p_pa is the load address of this segment (as well
        // as the physical address)
        readseg(ph->p_pa, ph->p_memsz, ph->p_offset);
    
// call the entry point from the ELF header
// note: does not return!
((void (*)(void)) (ELFHDR->e_entry))();
```
We will firstly read the ELF header including the Program Table into memory, which can not exceed 8 sectors. From to the Program Table, we get the pa, count and offset information, ensuring us fetching them correctly.

* ELF format: VMA and LMA meaning? Why different?

<img src="http://www.runqitian.com/content/jos_lab1/p2.png" style="width: 80%; display: block; margin-left: auto; margin-right: auto;">

VMA is the link address. The linker will modify the address in our assembly code based on this link address. For example, their is a command 
"mov 0x1002 %eax" and the .text VMA is 0xf0000000, it will be interpretted as "mov 0xf0001002 %eax".  
LMA is the load address, this is the virtual address where our program will be loaded.(note that both LMA and VMA are virtual address, in our progarm, we do not enable paging yet, now we load it to the linear address which is the same as physical address). This the the virtual address where we will load our content into memory.   
Normally, VMA is the same as LMA, because we load the program to where we execute them. It is a different situation here, we do not enable paging yet. We need to load the program to some specified pysical address and link it to our expected virtual address, later, we will enbale paging and we will map the VMA to LMA, so that we can execute the program correctly. In this case we map virtual address oxf0100000 to pysical address 0x00100000.

## Part3: The Kernel
* We firstly enable paging in "kern/entry.S".

```
.globl          _start
_start = RELOC(entry)

.globl entry
entry:
        movw    $0x1234,0x472                   # warm boot

        # We haven't set up virtual memory yet, so we're running from
        # the physical address the boot loader loaded the kernel at: 1MB
        # (plus a few bytes).  However, the C code is linked to run at
        # KERNBASE+1MB.  Hence, we set up a trivial page directory that
        # translates virtual addresses [KERNBASE, KERNBASE+4MB) to
        # physical addresses [0, 4MB).  This 4MB region will be
        # sufficient until we set up our real page table in mem_init
        # in lab 2.

        # Load the physical address of entry_pgdir into cr3.  entry_pgdir
        # is defined in entrypgdir.c.
        movl    $(RELOC(entry_pgdir)), %eax
        movl    %eax, %cr3
        # Turn on paging.
        movl    %cr0, %eax
        orl     $(CR0_PE|CR0_PG|CR0_WP), %eax
        movl    %eax, %cr0

        # Now paging is enabled, but we're still running at a low EIP
        # (why is this okay?).  Jump up above KERNBASE before entering
        # C code.
        mov     $relocated, %eax
        jmp     *%eax
relocated:

        # Clear the frame pointer register (EBP)
        # so that once we get into debugging C code,
        # stack backtraces will be terminated properly.
        movl    $0x0,%ebp                       # nuke frame pointer

        # Set the stack pointer
        movl    $(bootstacktop),%esp

        # now to C code
        call    i386_init
```
Before we enable paging, we should still use physical address, RELOC will change the link address to pysical address by substracting KERNBASE which is 0xf0000000. After enble paging, we need to jump to above KERNBASE to run the C code program. (relocated label address is based on link address)

* questions for exercise 8
	* Explain the interface between printf.c and console.c. Specifically, what function does console.c export? How is this function used by printf.c?   
	
	They all serve in init.c. Fistly, cons_init() initialize the console, then we are able to cprintf().
	
	* Explain the following from console.c:

	```
if (crt_pos >= CRT_SIZE) {
    int i;

    memmove(crt_buf, crt_buf + CRT_COLS, (CRT_SIZE - CRT_COLS) * sizeof(uint16_t));
    for (i = CRT_SIZE - CRT_COLS; i < CRT_SIZE; i++)
            crt_buf[i] = 0x0700 | ' ';
    crt_pos -= CRT_COLS;
}
	```

	In console.h defines "#define CRT_SIZE       (CRT_ROWS * CRT_COLS)", so here the logic is, when the screen is full, it moves 1 line up.

	
* Exercise 9:  Determine where the kernel initializes its stack, and exactly where in memory its stack is located. How does the kernel reserve space for its stack? And at which "end" of this reserved area is the stack pointer initialized to point to?   
In "kern/entry.S":

```
relocated:

# Clear the frame pointer register (EBP)
# so that once we get into debugging C code,
# stack backtraces will be terminated properly.
movl    $0x0,%ebp                       # nuke frame pointer

# Set the stack pointer
movl    $(bootstacktop),%esp

# now to C code
call    i386_init
```

This part is after setting up paging, it sets %ebp to 0x0, because now we are not in any function. it sets %esp to $(bootstacktop), note that $(boostacktop) meaning the address not the value at the address. Here is how it is defined.

```
bootstack:
        .space          KSTKSIZE
        .globl          bootstacktop
bootstacktop:
```
The stack size is "#define KSTKSIZE      (8*PGSIZE)", and stack pointer decrease so it is set to the top address.

### x86 calling convention
Before we go further, let's take a look at x86 calling convention. Here provides some sample code:  

```
// caller:
// func(a);
sub 0xc, %esp
push a
call func
add 0x10 %esp


// callee: 
// func(int a){
//  	int c = a + 5;
//  	return;
// 	}
func:
push %ebp
mov %esp %ebp
sub 0x10, %esp
execution...
leave
ret
```
First look at the caller:  

* sub 0xc, %esp

>  Called stack alignment, here we follow i386 System V ABI conventio, which requires 16 bytes stack alignment. We pass one int, which is 4 bytes. So we need reserve the stack for 0xc bytes just for alignment.(The reserved space is useless, just for alignment)  
> If we pass 6 int, what would happen?  
> 6 int use 24 bytes, we need to "sub 0x8, %esp", for 2*16 bytes alignment.

* push a

> push in the parameter

* call func

> call function

* add 0x10, %esp

> We have reserved 0xc bytes for alignment and 0x4 bytes for parameter in stack, in total is 0x10 bytes. Now we need to clean up the stack by increasing the %esp.

Now look at the callee:  

* What happens implicitly?  

> The call will automatically push return eip into the stack.

* push %ebp

> We need to push the old %ebp into stack for preservation.

* mov %esp %ebp

> Set up the new %ebp, the same as %esp.

* sub 0x10, %esp

> If we have some local variables in func, reserve them on stack. Remember to follow the stack alignment convension, which means even if you just need 4 bytes, you still need to reserve 16 bytes for stack alignment.

* leave

> leave will implicitly execute:  
> mov %ebp, %esp  
> pop %ebp

* ret

> pop the return address and set %eip to the return address.

GCC behavior:  

> gcc -m32 will defaultly do 16 bytes stack alignment, like what we talk about above.  
> We can set it by -mpreferred-stack-boundary=n, to align 2^n bytes, n default value is 4.

Direct look:
<img src="http://www.runqitian.com/content/jos_lab1/p3.jpg" style="width: 60%; display: block; margin: auto">
reference:
[link](https://stackoverflow.com/questions/41971481/what-are-the-following-instructions-after-this-call-assembly), [link](http://blog.opensecurityresearch.com/2013/06/reversing-basics-part-2-understanding.html), [link](https://stackoverflow.com/questions/3638075/explanation-about-push-ebp-and-pop-ebp-instruction-in-assembly)


## Exercise 10 & 11
After familiarize ourselves with the calling convention, let's finish the calling stack part.

```
int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
        // the ebp addr is 2 * 4 bytes top from the first parameter.
        uint32_t* ebp = ((uint32_t*)&argc) - 2;
        cprintf("Stack backtrace:\n");
        while (ebp) {
                cprintf("ebp %08x  eip %08x  args %08.x %08.x %08.x %08.x %08.x\n", ebp, ebp[1], ebp[2], ebp[3], ebp[4], ebp[5], ebp[6]);
                // the previous stack frame ebp pointer is saved as value on current ebp pointer.
                ebp = (uint32_t*) *ebp;
        }
        return 0;
}
``` 
* According to the convention, we know that the ebp pointer is 2\*4 bytes above the first parameter address.
* The %ebp saves the value of old %ebp pointer, we can backtrace simply by \*ebp. 
* Notice that in entry.S, the top %ebp value is set to 0, which means when we quit the i386_init(), we will find ebp equals to 0, that is where we stop backtracing.

## Exercise 12

* In debuginfo_eip, where do \_\_STAB\_\* come from?

> 


