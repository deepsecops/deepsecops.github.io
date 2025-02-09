---
title: ud2a and ud2 assembly instruction
description: >-
  In this we will see that how ud2a and ud2 instruction effect the static analysis and how can we handle or bypass them in tool like Ghidra to continue disassembling the binary, identify program flow, and properly analyze the program's behavior beyond these instructions and how Malware authors could use this to conintue execution even after the signal exception is raised to mislead the automated analysis.   
author: deepsecops
date: 2025-02-09T12:00:00+0530
categories: [Research]
tags: [Research]
toc: true
---

My Linkedin Profile: [https://www.linkedin.com/in/deepak-bhardwaj-aa8543143/](https://www.linkedin.com/in/deepak-bhardwaj-aa8543143/) 

If we search on internet we might get information like this about the "ud2" and "ud2a" instruction: The UD2 instruction in x86-64 assembly is an instruction that generates an invalid opcode exception. It’s part of the x86 architecture and is specifically designed to trigger an exception (typically a #UD or "Invalid Opcode Exception") when executed.

In simple words: The UD2 and UD2A instruction is a valid but **intentionally** invalid opcode in x86-64 architecture, meaning it is designed to trigger a SIGILL (illegal instruction) exception when executed. And both UD2 and UD2A are 2-byte instruction (we will see why this is important to know). 

If we use the "ud2" and "ud2a" instruction in our program, this would result in an "illegal instruction" exception and program will exit from the execution. Let's take an example created code (save it in file named: test.c): 

```c
#include<stdio.h> 
void test()
{
	int a = 0;
	printf("inside the function test\n");
	__asm__("ud2a");
	printf("returning from function test after execution of the ud2a instruction\n");
	return;
}
int main()
{
    printf("inside main function\n");
	int a = 4;
	int b = 5;
	int c = a + b;
	__asm__("ud2");
    test();
    printf("In main function executing after the ud2a or ud2 instruction\n");
    int c = a+b; 
    printf("The add result is: %d\n", c);
	return 0;

}
```

![res-001](assets/img/Research/ud2-ud2a-instruction/img-1.png)


This is expected, as the system got the SIGILL signal and this signal is handled by the system then program execution is stopped but what if we want to keep executing the program even after the illegal instruction exception is raised to the OS. 

We can manually handle this signal using the signal handlers. For that we need to register our handler for the specific singal, we can do this using the signal() function. 

```signal(SIGILL, handle_sigill);```

where SIGILL is the signal constant for Illegal Instruction and "handle_sigill" is the name of the signal handler function we will define. So, lets define the signal handler and lets print something and return from that signal handler, and observe that is it continuing the execution after the "ud2" or "ud2a" instruction. 

Saved in a file named: custom-signal-handler.c
```c
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
 
void handle_sigill(int sig) {     // Signal handler for SIGILL

    printf("in the signal handler\n");
    return;
}
void test()
{
	int a = 0;
	//printf("test");
	printf("inside the function test\n");
	__asm__("ud2a");
	printf("returning from function test after execution of the ud2a instruction\n");
	return;
}
int main() {
    signal(SIGILL, handle_sigill);    // registering my handler using "signal" function. 

    printf("inside main function\n");
    int a = 4;
    int b = 5;
    __asm__("ud2");
    test();
    printf("In main function executing after the ud2a or ud2 instruction\n");
    int c = a+b; 
    printf("The add result is: %d\n", c);
    return 0;
}
```
After running the above code it can be observed that it is calling infinitely the singal handler (that we have defined) after it enters into the main function.

![res-002](assets/img/Research/ud2-ud2a-instruction/img-2.png)

Lets find the root cause of it using "gdb" debugger.

Disassembly of the main function:
![res-003](assets/img/Research/ud2-ud2a-instruction/img-3.png)


Execution stopped at the breakpoint to handle_sigill function:
![res-004](assets/img/Research/ud2-ud2a-instruction/img-4.png)


Execution reaches back to the main function, observe the "rip" register:
![res-005](assets/img/Research/ud2-ud2a-instruction/img-5.png)


Observe that when the execution reaches back to the main function the "RIP" register still points to the "ud2" instruction as the register values were restored by the "__restore_rt()" function, and when that will execute again it will invoke our singal handler and it keeps going and to understand why this happens we need to understand what happens when a interrupt occurs (this signal exception causes a software interrupt to occur). 

This interrupt triggers a singal to the kernal or CPU which handles the execution from that point to resolve the interrupt, the "rip" register value is also saved in this step of ISR (Interrupt Service Routine): 
 
 - The Kernel/CPU saves the state (or context) of the current process, including registers, program counter (PC), and other relevant processor states. This
   ensures that the Kernel/CPU can return to the interrupted task once the ISR completes. This is critical to ensure that the normal execution flow can continue smoothly after the interrupt is serviced. The CPU pushes the current execution state (e.g., program counter, flags, registers) onto the stack, which allows it to return to the same point after handling the interrupt.


In above image we would see and wonder what is this function "__restor_rt()" doing in the call stack, well it is the Linux kernel implemented function used for restoring the state of a process after handling a signal or an interrupt, specifically when dealing with context switching in certain systems. It is part of the internals of the Linux kernel's signal handling mechanism and is not typically exposed to user-space applications. This function is used to restore the "real-time" state of a process, specifically restoring registers and state information that might have been modified during the signal handling process or other interrupt handling.


Now if we want this to continue execution after the next instruction of "ud2" in our main function, there might be other ways, I tried this one:
 - using assembly we can make sure to update the location which is pointing to the instruction "ud2", update it with 2 bytes (as we know ud2 and ud2a are 2-bytes instruction) to make sure it now points to the next instruction. So when resuming from where it was interrupted now it executes from next instruction, not from "ud2" again. 

#### # Code Plan: 
We need to know the address which points to the "ud2" instruction from where the interrupt is generated and then calculate the relative address of it from the "rbp" register inside our signal handler frame. Once we have relative address then using assembly in our singal handler we could increment it by 2 bytes so that it will point to the next instruction to be executed and the execution will resume from the next instruction not again from the "ud2" or "ud2a" instruction.

> **Note**: This change will be valid everytime we use the "ud2" or "ud2a" instruction in our program now, as we have calculated relative position of address pointing to "ud2" instruction from "rbp" register which is pointing to current frame address which is our signal handler function. So, after our change once the "ud2" instruction is encountered it will be handled in our signal handler function and then it will return to the function from where the signal was invoked and continue execution from the next instruction. Checked on two different machines relative location from "rbp" register was same. 
{: .prompt-info }

We need to first find where the address which points to the "ud2" is getting stored in the stack and once the call reaches to our signal handler from the main function. 

We know from above screenshot that in main function this is the address which points to "ud2" instruction: ```0x000055555555521d```

Let's observe the stack after our signal handler is invoked and when the "rbp" is pointing into current frame.

Observe that "rbp" is pointing to the current frame: 
![res-006](assets/img/Research/ud2-ud2a-instruction/img-6.png)

Observe the stack when signal handler is invoked: 
![res-007](assets/img/Research/ud2-ud2a-instruction/img-7.png)

Observe that the address which is pointing to the "ud2" its upper 4 bytes (which is sufficient) are stored in the stack on address: ```0x7fffffffd868```
And the "rbp" is pointing to : ```0x00007fffffffd7b0```

By doing hex math we would get to know that the difference between the two is 184 which is 0xb8 in hex. 
We can confirm that our calculation is correct by using: 

```x/x $rbp+0xb8```

![res-008](assets/img/Research/ud2-ud2a-instruction/img-8.png)


Now lets write assembly code which would update this address by 2 bytes and that will make it point to next instruction. We can use "\__asm__()" function in C to include inline assembly in our C program. These instructions will basically update the value stored at location "$rbp+0xb8" and add 0x2 into it: 

```
mov rax,QWORD PTR [rbp-0x8]     --> saving rax
mov rax, QWORD PTR [rbp+0xb8]   --> moving the value stored at location $rbp+0xb8 to rax
lea rdx, [rax+0x2]              --> moving the calculated value where in rax we are adding 0x2 and result will be stored in rdx
mov rax,QWORD PTR [rbp-0x8]     --> restoring rax
mov QWORD PTR [rbp+0xb8],rdx    --> moving the value of calculated rdx value which is updated value of instruction which was pointing to ud2 now after adding 0x2 it is pointing to next instruction 
```

I have written above assembly in Intel Syntax as I am familiar with that but as we are executing our program in linux, we need to convert this into the AT&T Syntax: 

```
movq -0x8(%rbp), %rax      // Move QWORD from [rbp-0x8] to rax
movq 0xb8(%rbp), %rax      // Move QWORD from [rbp+0xb8] to rax
leaq 0x2(%rax), %rdx       // Load effective address of rax+0x2 into rdx
movq -0x8(%rbp), %rax      // Move QWORD from [rbp-0x8] to rax
movq %rdx, 0xb8(%rbp)      // Move QWORD from rdx to [rbp+0xb8]
```

Let's update our above program "custom-signal-handler.c": 
```c
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
 
void handle_sigill(int sig) {     // Signal handler for SIGILL

    printf("in the signal handler\n");
    __asm__(
	"movq -0x8(%rbp), %rax;"
	"movq 0xb8(%rbp), %rax;"
	"leaq 0x2(%rax), %rdx;"
	"movq -0x8(%rbp), %rax;"
	"movq %rdx, 0xb8(%rbp);"	
    );
    return;
}
void test()
{
	int a = 0;
	//printf("test");
	printf("inside the function test\n");
	__asm__("ud2a");
	printf("returning from function test after execution of the ud2a instruction\n");
	return;
}
int main() {
    signal(SIGILL, handle_sigill);    // registering my handler using "signal" function. 

    printf("inside main function\n");
    int a = 4;
    int b = 5;
    __asm__("ud2");
    test();
    printf("In main function executing after the ud2a or ud2 instruction\n");
    int c = a+b; 
    printf("The add result is: %d\n", c);
    return 0;
}
```

If we compile and run above code, we would observe that after the call returns from the handler function it is executing from the next instruction of "ud2" or "ud2a" instruction which is not causing the infinite loop calls to signal handler and execution is successful. 

![res-009](assets/img/Research/ud2-ud2a-instruction/img-9.png)


Let's provide this binary to ghidra and observe that how the disassembly will look: 

![res-010](assets/img/Research/ud2-ud2a-instruction/img-10.png)

Observe ghidra by default didn't disassembled the binary after encountering the "ud2" or "ud2a" instruction, we can manually disassemble by selecting the hex bytes after the "ud2" instructions till the end then right click and select disassemble --> Observe that now we got the disassembly of the code after the "ud2" and "ud2a" instruction. 

![res-011](assets/img/Research/ud2-ud2a-instruction/img-11.png)


![res-012](assets/img/Research/ud2-ud2a-instruction/img-12.png)


If we use objdump tool it will show us the disassembly of the binary after the "ud2" or "ud2a" instruction, there are several other ways we can path the binary by replacing "ud2" or "ud2a" instructions with "nop" instruction.



> Similarly a Malware Author could use these instructions to confuse static analysis tools, or to divert the analysis, there are many other such instructions which require careful look while performing analysis to find the program's intent. 
{: .prompt-info }

One such example I found of malware using the "ud2" instruction to mislead the analysis: 
 - [https://analysisofmalware.wordpress.com/2015/05/20/analysis-of-the-finfisher-malware-part-2-the-dropped-file/](https://analysisofmalware.wordpress.com/2015/05/20/analysis-of-the-finfisher-malware-part-2-the-dropped-file/)




