---
title: Branchless Branching
description: >-
  This challenge is Easy-Medium level where the user has to idenitfy the logic, and the binary is stripped but the decompiled version of the binary doesn't makes any sense as the jump to the instructions are defined on the runtime based on the user's input, so the static analyzers were not able to properly define the decompiled version of the code, we need to step through assembly to understand behavior. 
author: deepsecops
date: 2025-08-31T12:00:00+0530
categories: [Reverse Engineering Challanges, crackme]
tags: [crackme]
toc: true
---

Link to the Challenge: [https://crackmes.one/crackme/68692679aadb6eeafb398fdf](https://crackmes.one/crackme/68692679aadb6eeafb398fdf)

My Linkedin Profile: [https://www.linkedin.com/in/deepak-bhardwaj-aa8543143/](https://www.linkedin.com/in/deepak-bhardwaj-aa8543143/)

My crackme's profile: [https://crackmes.one/user/anon786](https://crackmes.one/user/anon786)


In this reverse engineering challenge see that indrect jumps are used which are predicted at the run-time based on the calculation and the user-input, in this case the static analyzers will not be able to properly de-compile the program and may fail to reconstruct the correct control flow, we have to manually step through the assembly and dynamically understand the behavior of the program, and reverse the assembly code to get the working pseudo-code program and then we will move forward with writing a key-gen which would help in solving this challenge. 

Observe that language used by the author is mentioned as "Assembler", the program might be written in raw assembly.

![crackme-001](/assets/img/Challenges/branchless-branching/img-1.png)



So, what are the difference between Indirect Jumps vs. Normal "if/else":

- **Indirect Jumps (jmp rax, call rax, cmove/cmovne followed by jmp):** 
    - The target address is not known at compile time. 
    - Depends on calculations, function pointers, jump tables, or even user input. 
    - Static analyzers struggle because the jump target could vary every run (will show the decompiled behavior of the Ghidra).

- **Normal if/else branches**:
    - Compilers generate direct conditional jumps (e.g: je, jne, jg).
    - The targets of these jumps are known at compile time.
    - Static analyzers can usually decompile these correctly, because the control flow graph is fully known.


Observe that it is an ELF executable, with the symbols stripped and it prompts for "username" and "password":

![crackme-002](/assets/img/Challenges/branchless-branching/img-2.png)

Let's see if we could get anything from the "strings" utility, observe that as the binary is stripped, we just get the sections names and some pre-defined strings in the output:

![crackme-003](/assets/img/Challenges/branchless-branching/img-3.png)

Let's throw this binary into ghidra, and see if we could get any useful information, observe below that we could see no function other than the "entry" function and also observe that when clicked on the disassembly the de-compiled code doesn't makes much sense, we could see keywords like: "UNRECOVERED_JUMPTABLE", lets jump to dynamic analysis as there are no functions seems in function section. 

![crackme-004](/assets/img/Challenges/branchless-branching/img-4.png)

![crackme-005](/assets/img/Challenges/branchless-branching/img-5.png)

Let's use the "start" command in gdb to have a break point at the "entry point address" of the binary, and see if we could get the disassembly in current context or if we could find information of any functions: 


![crackme-006](/assets/img/Challenges/branchless-branching/img-5-1.png)

Observe in above image we are not getting any functions information related to binary, and also we are not able to see complete disassembly, as the binary is stripped the gdb might not knowing the function boundaries, so it doesn't knows which function disassembly I am referrring to, but we could use gdb memory referencing command to get any number of instructions we want after an address.

Disassembly of the program could be seen from instructions shown above and below of current executing instruction and seems like it is invoking a system call number 1, and from the above decompiled code from Ghidra we observed that it is invoking 4 system calls at the start:

Let's disassemble this system call, as from the previous posts also we know that in linux x86-64 system ABI:

- rax holding the syscall number: "1" in our case which is "write".
- rdi is the 1st argument which is file descriptor "stdout" in our case. 
- rsi is the buffer from where it would write which is "0x402000".
- rdx is the third argument which is the count of bytes which would be written from buffer, which is 10.

So, the disassembled version of the below syscall is: 

```write(1, 0x402000, 10);   // above instructions are calling "sys_write"```


![crackme-007](/assets/img/Challenges/branchless-branching/img-6.png)

If we look into the memory address: "0x42000" we would obesrve that it is printing "username" from the first 10 bytes of "0x42000":

![crackme-008](/assets/img/Challenges/branchless-branching/img-7.png)

Similarly if we keep stepping into assembly, we would see that it is asking for the username input through standard input from syscall, the resulting call is:

```read(0, 0x402078, 8);   -->username stored "testing\n"```

```
0x40101b   mov    eax, 0x0
0x401020   mov    edi, 0x0
0x401025   movabs rsi, 0x402078
0x40102f   mov    edx, 0x8
0x401034   syscall 
```
> Observe that the entered username is stored in the location "0x402078", this would be useful later on
{: .prompt-info }

Again, next set of instructions are for the password prompt printing in console: 

```write(1, 0x40200a, 10);```

```
0x401036  mov    eax, 0x1
0x40103b  mov    edi, 0x1
0x401040  movabs rsi, 0x40200a
0x40104a  mov    edx, 0xa
0x40104f  syscall 
```

Next system call is to get the password from the user and it will be stored at the particular location in memory based on how the program is written. 

```read(0, 0x402080, 17);  --> Password stored "password\n"```

```
0x401051  mov    eax, 0x0
0x401056  mov    edi, 0x0
0x40105b  movabs rsi, 0x402080
0x401065  mov    edx, 0x11
0x40106a  syscall 
```
> Observe that the entered password is stored in the location "0x402080", this would be useful later on
{: .prompt-info }


### Disassembling raw instructions: 
Some function prologue starts from "0x40106c" after the 4 system calls, and I have printed the upcoming 20-30 instructions that would get executed after "0x40106c":

> From here the raw reading and disassembling of the assembly instructions starts, Let the fun begins..., we will see the instructions first have a general idea of it, then we will create the behavior in pseudo-code and later-on in high level language:
{: .prompt-info }

![crackme-009](/assets/img/Challenges/branchless-branching/img-8.png)


So, function prologue and some of the local pointers which points to the memory location where instructions are stored, lets step through assembly: 
```
=> 0x40106c:	push   rbp
   0x40106d:	mov    rbp,rsp
   0x401070:	sub    rsp,0x20
   0x401074:	mov    QWORD PTR [rbp-0x8],0x4010e8
   0x40107c:	mov    QWORD PTR [rbp-0x10],0x40109e
   0x401084:	mov    QWORD PTR [rbp-0x18],0x401000
```

Below are some of my comments after assembly for understanding, Below are some of my observations:
- So initially it is zeroing out rax,rbx,rcx,rdx register and at r10 "0x8" is getting stored. 
- We know that at location "0x402078" the entered username is stored so it is doing some operation on the characters of the username (it might be the loop which interprets the characters of the username provided).

```
0x40108c  xor    rax, rax    --> rax = 0
0x40108f  xor    rbx, rbx    --> rbx = 0
0x401092  xor    rcx, rcx    --> rcx = 0
0x401095  xor    rdx, rdx    --> rdx = 0
0x401098  mov    r10d, 0x8   --> r10d = 0x8 
0x40109e  mov    rax, rdx    --> rax = 0

0x4010a1  imul   rax, rax, 0x7 --> rax = 0x0
0x4010a5  mov    bl, BYTE PTR [rdx+0x402078] --> $rbx   : 0x74 (which is first character, moving 1 byte from 0x402078 to lowest byte of rbx, so first character of username)
0x4010ab  add    rax, rbx    --> rax = 0x74
0x4010ae  and    rax, 0x1f   --> rax = 0x14  ( "&" of 0x1f with the first character of username)  : Added 0x1f with the first character of username which was in rbx
```


Below are my observations for further instructions:
- The address "0x402055" used below points to the first character of the string: ```"!@$defghijklmn9pqrstuvwxyz012345"```

![crackme-010](/assets/img/Challenges/branchless-branching/img-9.png)

- As "$rax" value is "0x14", so when the 0x402055 will get added with $rax which is "0x14" the result is : 0x402069, where the first 8 bytes is "u" character, which is getting stored in the lowest byte of the rcx register.  

- Observe that the address "0x402091" is pointing to empty string, but after some calculation it is getting populated (below it is getting populated). 

![crackme-011](/assets/img/Challenges/branchless-branching/img-10.png)

- This address is getting referenced ```rbx+0x402055``` which resolves to ```0x402059``` which basically points to "e" character in the string ```"!@$defghijklmn9pqrstuvwxyz012345"```


```
0x4010b2  mov    cl, BYTE PTR [rax+0x402055] --> $rcx = 0x75  (u)    : (which is first character of memory location, moving 1 byte from 0x402078 to lowest segment of rcx)
0x4010b8  mov    BYTE PTR [rdx+0x402091], cl  --> 0x00+0x402091 = "u"
0x4010be  imul   rbx, rcx  --> $rbx = 0x74*0x75 = "t"*"u" = 0x3504 

0x4010c2  and    rbx, 0x1f    -->  0x3504 & 0x1f : $rbx = 0x4
0x4010c6  mov    cl, BYTE PTR [rbx+0x402055]  -->  0x402059 : $rcx = 0x65 
```

Right now the value of "$r10" is "0x8", so r10+0x402091 becomes "0x402099" in that 0x65 will get stored by below instruction, here also observe that the string pointing at location "0x402091" is getting populated:

```0x4010cc                  mov    BYTE PTR [r10+0x402091], cl  ```

"$rdx" value is currently 0, but in the next instruction it is getting incremented, and the incremented value is getting compared with the 0x8, so its like condition if(rdx == 0x8):
  
``` 
0x4010d3  inc    rdx    --> rdx becomes 1
0x4010d6  inc    r10    --> r10 becomes 0x9
0x4010d9  cmp    rdx, 0x8  --> Zero flag doesn't sets to 0 as it is not equal to 0x8
```

As, we know from previous stepping of assembly that some code pointers (which points to instructions) were saved in current context at the start after function prologue, based on the previous conditional check "cmp" it is taking place, it is conditional move which would check if the zero flag is set or not: 

```
0x4010dd  mov    rax, QWORD PTR [rbp-0x10]
0x4010e1  cmove  rax, QWORD PTR [rbp-0x8]
0x4010e6  jmp    rax
```

So, above 3 instructions could be written as: 

```c
if(rdx == 0x8)
{
	execute from "rbp-0x8" :  which is : 0x00000000004010e8
}
else
{ 
	execute from "rbp-0x10" : which is : 0x000000000040109e
   0x40109e:	mov    rax,rdx
   0x4010a1:	imul   rax,rax,0x7
   0x4010a5:	mov    bl,BYTE PTR [rdx+0x402078]
   0x4010ab:	add    rax,rbx
   0x4010ae:	and    rax,0x1f
   0x4010b2:	mov    cl,BYTE PTR [rax+0x402055]
   0x4010b8:	mov    BYTE PTR [rdx+0x402091],cl
   0x4010be:	imul   rbx,rcx
   0x4010c2:	and    rbx,0x1f 
   0x4010c6:	mov    cl,BYTE PTR [rbx+0x402055]
   0x4010cc:	mov    BYTE PTR [r10+0x402091],cl
   0x4010d3:	inc    rdx
   0x4010d6:	inc    r10

}
```
So, "$rdx" will get incremented and continue from "0x40109e", it seems like a loop to me lets create a pseudo-code of the above instructions observe and include them in a loop which is observed, we need to make some assumptions about names to visualize correctly: 
- Lets consider "$rdx" as "i" variable (As that is the one which is getting compared with the 0x8 (which looks to be username length as operations are performed on characters)).
- Consider "$rax" as "var1", "$rbx" as "ch" and "$rcx" as "ch2".
- As the username is stored at location "0x402078", so operations related to this address, I am using it as "username" array below.
- As in the location "0x402055" we observed that it is pointing to some characters, lets say this is "keyArr".
- We also observed that in location "0x402091" the characters are getting populated, it seems some output generation, lets call it "output".

**Note:** After carefully analyzing the raw assembly, I came up with the below "for" loop with the operations being performed on the username, lets save the below code for now, we will use this later on: 

#### # Pseudo-code for populating the "output" array from the provided "username":

```c
r10 = 0x8;
for(int i=0; i<8;i++)
{	
	var1 = i;
	var1 = var1*0x7;
	ch = username[i];
	var1 = var1+ch;
	var1 = var1 & 0x1f;
	
	ch2 = keyArr[var1];
	output[i] = ch2;

	ch = ch*ch2;
	ch = ch & 0x1f; --> This makes sure that the result is between 0 to 31 as we are doing & with 0x1f, so that we could correctly reference the "keyArr" characters array that we have.

	ch2 = keyArr[ch];
	output[r10] = ch2;
	r10++;
}
```

As we need to understand the behavior of program/function, if we keep on stepping assembly at one point it would reach at comparison where "$rdx" is equal to "0x8" then it will start execution from "0x00000000004010e8" as per the above if condition that we had: 

```
if(rdx == 0x8)
{
	execute from "rbp-0x8" :  which is : 0x00000000004010e8
}
```

Below are the instructions from where the execution will jump after "if" condition:

![crackme-012](/assets/img/Challenges/branchless-branching/img-11.png)
  

Below are some of comments based on the observations, and below instructions are sequential just splitted on part to understand in this blog:

```
=> 0x4010e8:	mov    QWORD PTR [rbp-0x8],0x401150
   0x4010f0:	mov    QWORD PTR [rbp-0x10],0x40110e
   0x4010f8:	mov    QWORD PTR [rbp-0x18],0x40112a
   0x401100:	mov    QWORD PTR [rbp-0x20],0x401141
   0x401108:	xor    rdx,rdx    --> rdx = 0
   0x40110b:	xor    r12,r12    --> r12 = 0
   0x40110e:	mov    al,BYTE PTR [rdx+0x402091] --> (moving first character of 0x402091 to rax smaller byte) this 0x402091 is the output array created from username and keyArr
   0x401114:	inc    al			  --> (incrementing the character stored in previous instruction by 1)
```

Below instructions comparing the password[i] == rax (lower bytes of "$rax"):

**Assembly:**
```
  0x401116:	cmp    al,BYTE PTR [rdx+0x402080]  --> (Comparing the first character of password with the output array)
  0x40111c:	mov    rax,QWORD PTR [rbp-0x18]
  0x401120:	cmove  rax,QWORD PTR [rbp-0x20]
  0x401125:	inc    rdx
  0x401128:	jmp    rax
```
**Pseudo-code:**
```
if(password[i] == rax(lower 8 bits))
{
	goto rbp-0x20: 0x401141
	i++
}
else
{
	goto rbp-0x18: 0x40112a
  i++;  (rdx)

  0x40112a                  or     r12, rdx    : 0x0 or 0x1 = 0x1
  0x40112d                  test   r12, r12	  : (& of same register, the value is 0x1 so answer is non zero)
  0x401130                  movabs rax, 0x40110e   --> back to above 
  0x40113a                  cmovne rax, QWORD PTR [rbp-0x20]--> conditional move if not equal: as the above check from "test" instruction doesn't sets the zero flag, so the move will happen  
  0x40113f                  jmp    rax     --> jmp to rbp-0x20 
  ....
```

It was observed that the below instructions after above instructions creates another condition, and it was observed that this is also the loop where it might be checking the password with the created output array from username: 

**assembly:**
```
  0x401141:	cmp    rdx,0x10			 --> as we know rdx is not equal to 16 yet, so it would again jump to the above instruction at "0x40110e"
  0x401145:	mov    rax,QWORD PTR [rbp-0x10]
  0x401149:	cmove  rax,QWORD PTR [rbp-0x8]
  0x40114e:	jmp    rax
  0x401150:	mov    QWORD PTR [rbp-0x8],0x401176
  0x401158:	movabs rbx,0x40119f
  0x401162:	test   r12,r12
  0x401165:	cmove  rbx,QWORD PTR [rbp-0x8]
  0x40116a:	mov    eax,0x1
  0x40116f:	mov    edi,0x1
  0x401174:	jmp    rbx
  0x401176:	movabs rsi,0x402014
  0x401180:	mov    edx,0xd
  0x401185:	syscall
```

What I observed after writing the pseudo-code from above assembly is that the based on the success condition, the syscall is taking place:

**pseudo-code:**
```
if(rdx or "i" == 16)
{
	rbp-0x8: 0x401150
	0x401150:	mov    QWORD PTR [rbp-0x8],0x401176
  0x401158:	movabs rbx,0x40119f
  0x401162:	test   r12,r12
  0x401165:	cmove  rbx,QWORD PTR [rbp-0x8]
  0x40116a:	mov    eax,0x1
  0x40116f:	mov    edi,0x1
  0x401174:	jmp    rbx
  0x401176:	movabs rsi,0x402014
  0x401180:	mov    edx,0xd
  0x401185:	syscall        ==> write(1, 0x402014, 13) --> Prints in screen as : "Logged in as"
  0x401187:	mov    eax,0x1
  0x40118c:	movabs rsi,0x402078
  0x401196:	mov    edx,0x8
  0x40119b:	syscall        ==> write(1, 0x402078, 8)  --> Prints in console as: username of 8 length which was passed as input
  0x40119d:	jmp    0x4011b2
  0x40119f:	movabs rsi,0x402021
  0x4011a9:	mov    edx,0x33
  0x4011b2:	mov    eax,0x3c
  0x4011b7:	mov    edi,0x0
  0x4011bc:	syscall       ==> _exit(0); --> exit system call with status code as 0. 

}
else
{
	goto rbp-0x10: 0x40110e

}
```

Observation from the assembly and pseudo-code together: 

- It was observed that the provided password is being compared with the output array which was created when the "username" was getting interpret.
- Also, there are indirect jumps involved in that and the loop is running, password seems to be expected of 16 characters as it is getting compared with "0x10".
- It was alos observed that in the "username" parsing loop the "r10" value was 0x8 and it is writing into ```output[r10] = ch2;``` and also loop runs 8 times, so it is writing from 8th place to 15th place, if we count from 0 to 15 the "output" is having 16 characters in total. 
- Below is the pseudo-code created for the password interpreting, so from pseudo-code it is observed that "password" is expected to be "output+1" for every character that is stored in the "output" array or at the location "0x402091".

#### # Pseudo-code for comparing the "password" with the populated "output" array:
```c
r12 = 0;

for(int i=0; ;i++)
{   
  if(password[i] == output[i]+1)
  {   
      if(i == 16)
      {
	 if(r12 == 0)
      	 {
	     Success Condition!!!
         }
         else
         {
	    go to: 0x40119f
         }
      }
      else
      {
         continue;
      }		
   }
   else
   {
        r12 = r12 | i;
	if(r12 != 0)
	{
	     if(i != 16)
	     {
		if(r12 == 0)
		{
		     Success Condition!!!
		}	
		else
		{	
		     go to: 0x40119f
		}
	     }
	     else
	     {
		continue;
	     }
	}
	else
	{
	     continue;
	}	
    }
}
```

## Logic for obtaining the password for any "username" entered:
Let's go and create a keygen to generate a password for any username we want:
- In the below code, I have used the same logic, that we reversed. 
- And generating password which would be "output+1" character. 

```c
#include<stdio.h>

int main()
{
	char ch;
	char ch2;
	int var1;
	char username[8];
	printf("Enter Username: ");
	fgets(username, sizeof(username), stdin);
	
	int r10 = 0x8;   //pre-defined from assembly
	char keyArr[] = "!@$defghijklmn9pqrstuvwxyz012345";
	int i=0;
	char output[50];
	for(i=0;i<8;i++)
	{
		var1 = i;
		var1 = var1*0x7;
		ch = username[i];
		var1 = var1+ch;
		var1 = var1 & 0x1f;

		ch2 = keyArr[var1];
		output[i] = ch2;

		ch = ch * ch2;
		ch = ch & 0x1f;
		
		ch2 = keyArr[ch];
		output[r10] = ch2;
		r10++;		

	}

	printf("For the entered username, the password is: ");
	for(i=0;i<16;i++)
	{
		printf("%c",output[i]+1);
	}
	printf("\n");

}
```

Let's run this code and see what is the behavior of the binary output, if we provide the username, and enter the generated password from keygen: 

I have saved the above "c" code with name as "test.c", after compiling the code, observe that we are getting logged in response: 


![crackme-013](/assets/img/Challenges/branchless-branching/img-12.png)

Wooooooooooooo Hoooooooooooooooo this challenge is solved...
I hope you enjoyed reading this!!!!!!!!!! 

Will get back soon.
