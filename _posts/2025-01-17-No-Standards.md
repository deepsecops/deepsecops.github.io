---
title: 
author: deepsecops
date: 2025-01-17T12:00:00+0530
categories: [Reverse Engineering Challanges, No-Standards]
tags: [crackmes]
toc: true
---



## No-Standards

Link to the challenge: [**https://crackmes.one/crackme/6736b3a09b533b4c22bd2b9f**](https://crackmes.one/crackme/6736b3a09b533b4c22bd2b9f)

My Linkedin profile: [**https://www.linkedin.com/in/deepak-bhardwaj-aa8543143/**](https://www.linkedin.com/in/deepak-bhardwaj-aa8543143/)

This challenge was easy but it adds up little bit of **anti-debugging methods** which confuses our analysis but if we observe carefully we would get to know the inner workings of it by analyzing the decompiled binary code and looking into the flow of the code and for some function decompiled version of the code is not making any sense so need to look into assembly of those functions. 

**Anti-debugging methods used by the binary:**
* **Adding un-necessary code to divert the analysis.**
* **Using obfuscation (no meaningful information in ".symtab" section of ELF).**
* **Checks if "ptrace" is attached to the running program.**

Observe that the binary is ELF executable, and when it runs it prompts for the user input and it only accepts 8 characters from the user input and discards other characters. 

![crackme-001](/assets/img/Challenges/no-standards/img-1.png)

It shows the symbols are not stripped, but we would observe that obfuscation is applied. Let's see which functions does it has, we can use gdb to identify those, by using the : info functions command: 

![crackme-002](/assets/img/Challenges/no-standards/img-1-1.png)

Observe that the function names are obfuscated, and if we look at the ".strtab" section of the binary we would observed that no meaningful data is stored in it, it means the binary is obfuscated. 

Let's statically analyze the binary using "Ghidra", we would observe that once binary is analyzed by the tool we could see the disassembly and de-compilation of the binary. 

This is the decompiled version of the entry() function by ghidra, lets observe this function carefully: 

```

/* WARNING: Control flow encountered bad instruction data */

void processEntry entry(void)
{
  char cVar1;
  byte bVar2;
  int iVar3;
  undefined *puVar4;
  undefined8 uVar5;
  long lVar6;
  byte *pbVar7;
  int iVar8;
  float fVar9;
  byte local_19 [8];
  undefined local_11 [9];
  undefined local_8 [8];
  
  puVar4 = local_11;
  do {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  } while (puVar4 != local_8);
  uVar5 = FUN_00101280(&DAT_00102000);
  FUN_0010123f(&DAT_00102000,uVar5);
  FUN_00101203(local_11,8);
  lVar6 = FUN_00101280("hmmh... let me think...\n");
  FUN_0010123f("hmmh... let me think...\n");
  cVar1 = FUN_00101475();
  if (cVar1 == '\0') {
    if ((long)(~(int)DAT_00104000 + DAT_00104000 * 8) != 0x10203222121) {
      if ((long)(~(int)DAT_00104000 + DAT_00104000 * 8) == 0x10221503000) {
        *(undefined *)(lVar6 + -0x185cdca1) = *(undefined *)(lVar6 + -0x185cdca1);
        iVar8 = 0x41;
        fVar9 = 0.0;
        bVar2 = DAT_ffffffffe7b34413;
        do {
          DAT_ffffffffe7b34413 = bVar2;
          iVar3 = (int)fVar9;
          pbVar7 = (byte *)(long)iVar3;
          local_19[(long)pbVar7] = pbVar7[0x1020b4];
          bVar2 = (byte)((uint)iVar8 >> 8);
          *pbVar7 = *pbVar7 ^ bVar2;
          *pbVar7 = *pbVar7 ^ bVar2;
          *pbVar7 = *pbVar7 ^ bVar2;
          fVar9 = fVar9 + 1.0;
          iVar8 = iVar8 + -1;
          bVar2 = DAT_ffffffffe7b34413 ^ (byte)iVar3;
        } while (iVar8 != 0);
        FUN_00101360(local_11,8);
        cVar1 = FUN_001012ff(local_11,local_19,8);
      }
      else {
        FUN_00101360(local_19,8);
        cVar1 = FUN_001012ff(local_11,local_19,8);
      }
      if (cVar1 == '\0') {
        lVar6 = FUN_00101280("unfortunately that isn\'t the correct passphrase\n");
        FUN_0010123f("unfortunately that isn\'t the correct passphrase\n");
      }
      else {
        lVar6 = FUN_00101280("congratulations! you managed to escape\n");
        FUN_0010123f("congratulations! you managed to escape\n");
      }
      bVar2 = FUN_00101000();
      *(byte *)(lVar6 + -0x185cdca1) = *(byte *)(lVar6 + -0x185cdca1) ^ bVar2;
      return;
    }
    *(byte *)(lVar6 + -0x185cdca1) = *(byte *)(lVar6 + -0x185cdca1) ^ 0x21;
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  FUN_0010123f("loading",7);
  do {
    FUN_0010123f(&DAT_001020b2,1);
  } while( true );
}

```

Observe that at the start of the function local variables and the local arrays are defined, it can also be observed that the array "local_11" is assigned with all the zeros:
```
void processEntry entry(void)
{
  char cVar1;
  byte bVar2;
  int iVar3;
  undefined *puVar4;
  undefined8 uVar5;
  long lVar6;
  byte *pbVar7;
  int iVar8;
  float fVar9;
  byte local_19 [8];
  undefined local_11 [9];
  undefined local_8 [8];
  
  puVar4 = local_11;
  do {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  } while (puVar4 != local_8);

	// Will analyze the below code later, that is why removed for now..
}
```

First three function calls is done in this order, lets analyze these 3 functions one by one: 

```
uVar5 = FUN_00101280(&DAT_00102000);
FUN_0010123f(&DAT_00102000,uVar5);
FUN_00101203(local_11,8);
```

### # Analysis of FUN_00101280(): 

This function taking character array reference as input, if we observe this function carefully, we would observe that it is simply calculating the characters till it encounters the null character "\0" and returning the length of the array. 

![crackme-003](/assets/img/Challenges/no-standards/img-2.png)

### # Analysis of FUN_0010123f(): 

This function takes two arguments, first argument seems to be the reference of the array and the second parameter seems to be the size of the provided array as input. 

![crackme-004](/assets/img/Challenges/no-standards/img-3.png)

Observe that the decompiled version of this version is not making sense so lets just dive into the assembly of this function: 

```
0010123f f3 0f 1e fa     ENDBR64
00101243 53              PUSH       RBX
00101244 48 89 7c        MOV        qword ptr [RSP + local_10],RDI
         24 f8
00101249 48 89 74        MOV        qword ptr [RSP + local_18],RSI
         24 f0
0010124e 48 c7 c0        MOV        RAX,0x1
         01 00 00 00
00101255 48 c7 c7        MOV        RDI,0x1
         01 00 00 00
0010125c 48 8b 74        MOV        RSI,qword ptr [RSP + local_10]
         24 f8
00101261 48 8b 54        MOV        RDX,qword ptr [RSP + local_18]
         24 f0
00101266 0f 05           SYSCALL
00101268 5b              POP        RBX
00101269 c3              RET
```

From the above assembly instructions it can be observed that "syscall" instruction is being used, which basically invokes the system function, where:
* the "rax" holds the syscall number to be called which is 1 (sys_write) which means write() system function would be invoked.
* "rdi" holds the file descriptor to which it would write which is 1 (standard output).
* "rsi" would store the pointer to the string which would be written by syscall.
* "rdx" holds the length of the string to write to the file descriptor. 

For more information about the syscall number, please refer: 
* https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/

So, this function is basically writing the provided string according to the provided length to the standard output. 

So, by calling this function it is printing the data stored at &DAT_00102000: 
```
FUN_0010123f(&DAT_00102000,uVar5);
```

If we look out what data is stored at location: DAT_00102000, we can find that this string is being printed in the standard output that we see when the program runs: 
![crackme-005](/assets/img/Challenges/no-standards/img-4.png)

### # Analysis of FUN_00101203(): 

In the above de-compiled version of "entry" function, we can observe that next function is call is: 
```
FUN_00101203(local_11,8);
```

If we observe the disassembly of the function, its like above function its also using the syscall instruction to call some system function, just the difference is in this case:
* "rax" holds 0x0 which means the "sys_read" or read() system function would be invoked.
* "rdi" holds 0x0 as well which means the file descriptor in this case is standard input (from where the input will be read).
* "rsi" holds the array in which the read data will be stored.
* "rdx" stores the number of bytes to be read from the file descriptor. 

**Note: So, this function is reading the input (just 8 characters) provided by the user from the standard input, and saving it in the array "local_11". 

So, till now we have analyzed till here (read the comments after function calls): 
```
void processEntry entry(void)

{
     // stripped the part where local variables were defined.....
  
  puVar4 = local_11;
  do {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  } while (puVar4 != local_8);   // Unncessary loop 
  uVar5 = FUN_00101280(&DAT_00102000); // Counts the provided string length
  FUN_0010123f(&DAT_00102000,uVar5);  // Prints it into the stdout
  FUN_00101203(local_11,8);   // Takes the user input in the stdin
  lVar6 = FUN_00101280("hmmh... let me think...\n"); // counting length of str
  FUN_0010123f("hmmh... let me think...\n"); // prints the str into stdout
  cVar1 = FUN_00101475();  // Lets analyze this function
```

So, lets further analyze the function: FUN_00101475().

### # Analysis of FUN_00101475(): 

In the above de-compiled version of "entry" function, we can observe that the next function call is: 
```
 cVar1 = FUN_00101475(); 
```

If we observe the disassembly of the function, we would observe that it is again making a system function call by using the "syscall" instruction, its interesting lets analyze assembly: 

```
00101482 6a 32           PUSH       0x32
00101484 48 c7 c0        MOV        RAX,0x2
         02 00 00 00
0010148b 5b              POP        RBX
0010148c 48 f7 e3        MUL        RBX
0010148f 48 ff c0        INC        RAX
00101492 48 c7 c7        MOV        RDI,0x0
         00 00 00 00
00101499 48 c7 c6        MOV        RSI,0x0
         00 00 00 00
001014a0 48 c7 c2        MOV        RDX,0x1
         01 00 00 00
001014a7 49 c7 c2        MOV        R10,0x0
         00 00 00 00
001014ae 0f 05           SYSCALL
001014b0 c3              RET
```

As, we saw it doesn't takes any argument, so lets understand assembly: 
* First it is pushing 0x32 into the stack so RSP will contain 0x32 (which is 50 in decimal).
* Moving 0x2 to RAX. 
* Popping the value at top of stack to RBX, so RBX will now hold 0x32. 
* Multiplying RBX with RAX, so 0x32 * 0x2 ( 50 * 2 in decimal) = 100 (in decimal), so RAX will store 100 (in decimal).
* Incrementing the value of RAX, so now the RAX will have 101 (in decimal). 
* Then it is doing system call, where the system call number is 101, which is "sys_ptrace". 

The "ptrace" system call would look something like this: 
```
long ptrace(int request, pid_t pid, void *addr, void *data);
```

* "rdi" holds the "request" parameter which is 0x0 it corresponds to PTRACE_TRACEME, which is the request that tells the system to trace the current process.

* "rsi" also holds "0x0" it typically refers to the current process when using "PTRACE_TRACEME", next two arguments in "rdx" and "r10" are just placeholders for the "PTRACE_TRACEME" call. 

So, this function is trying to attach the "ptrace" to itself, and when the "ptrace" system call successfully gets attached to the provided process, it returns 0 and for other conditions if it fails to attach to the process it will return a non-zero value. 

**Note: For one running particular program/process, we can attach only one "ptrace", the OS doesn't allows us to attach more than one "ptrace" to a running process. 

So, this is another **anti-debugging** technique used by the creator of this binary, that if we tries to attach the ptrace to this running program, it will detect it and according to the de-compiled version of "entry" function if we see that it goes into the "else" condition of the program if it is not able to attach itself to the "ptrace" as a non-zero value will be received in "cVar1" which is not equal to 0 or ascii value '\0' (null).

Observe that once user attaches a debugger like "gdb" or another as implicitly it uses "ptrace" system call, it will end up in the infinite loop and will not be able to debug the code. 

**Note:** There is also an option to escape from this, which is binary patching, but that won't help much as obfuscation is also in place, which makes it hard to understand which functions or variable is being used. 

```
void processEntry entry(void)
{
  // removed the code where local variables were declared
  
  puVar4 = local_11;
  do {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  } while (puVar4 != local_8);
  uVar5 = FUN_00101280(&DAT_00102000);
  FUN_0010123f(&DAT_00102000,uVar5);
  FUN_00101203(local_11,8);
  lVar6 = FUN_00101280("hmmh... let me think...\n");
  FUN_0010123f("hmmh... let me think...\n");
  cVar1 = FUN_00101475();  // trying to attach its own process to ptrace. 
  if (cVar1 == '\0') {

			some logic - but if we attach this program while running to ptrace,                this won't be executed that is why removed for readability purpose.
  }
  FUN_0010123f("loading",7);
  do {
    FUN_0010123f(&DAT_001020b2,1);
  } while( true );
}
```

Lets try this in action, observe that it goes into infinite loop, and we will not be able to debug it: 
![crackme-006](/assets/img/Challenges/no-standards/img-6.png)

### # Analysis of condition where it successfully attaches "ptrace" to itself: 
So, we need to now see the condition, where it can successfully attach the "ptrace" to itself and returns 0. This is the condition which would get executed when it successfully attaches the "ptrace" to itself. 

```
  cVar1 = FUN_00101475();
  if (cVar1 == '\0') {
    if ((long)(~(int)DAT_00104000 + DAT_00104000 * 8) != 0x10203222121) {
      if ((long)(~(int)DAT_00104000 + DAT_00104000 * 8) == 0x10221503000) {
        *(undefined *)(lVar6 + -0x185cdca1) = *(undefined *)(lVar6 + -0x185cdca1);
        iVar8 = 0x41;
        fVar9 = 0.0;
        bVar2 = DAT_ffffffffe7b34413;
        do {
          DAT_ffffffffe7b34413 = bVar2;
          iVar3 = (int)fVar9;
          pbVar7 = (byte *)(long)iVar3;
          local_19[(long)pbVar7] = pbVar7[0x1020b4];
          bVar2 = (byte)((uint)iVar8 >> 8);
          *pbVar7 = *pbVar7 ^ bVar2;
          *pbVar7 = *pbVar7 ^ bVar2;
          *pbVar7 = *pbVar7 ^ bVar2;
          fVar9 = fVar9 + 1.0;
          iVar8 = iVar8 + -1;
          bVar2 = DAT_ffffffffe7b34413 ^ (byte)iVar3;
        } while (iVar8 != 0);
        FUN_00101360(local_11,8);
        cVar1 = FUN_001012ff(local_11,local_19,8);
      }
      else {
        FUN_00101360(local_19,8);
        cVar1 = FUN_001012ff(local_11,local_19,8);
      }
      if (cVar1 == '\0') {
        lVar6 = FUN_00101280("unfortunately that isn\'t the correct passphrase\n");
        FUN_0010123f("unfortunately that isn\'t the correct passphrase\n");
      }
      else {
        lVar6 = FUN_00101280("congratulations! you managed to escape\n");
        FUN_0010123f("congratulations! you managed to escape\n");
      }
      bVar2 = FUN_00101000();
      *(byte *)(lVar6 + -0x185cdca1) = *(byte *)(lVar6 + -0x185cdca1) ^ bVar2;
      return;
    }
    *(byte *)(lVar6 + -0x185cdca1) = *(byte *)(lVar6 + -0x185cdca1) ^ 0x21;
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
```

There are two conditions we need to look at : 
```
if ((long)(~(int)DAT_00104000 + DAT_00104000 * 8) != 0x10203222121) {
      if ((long)(~(int)DAT_00104000 + DAT_00104000 * 8) == 0x10221503000) {
```

If we would see what data is stored at the location "DAT_00104000", hex 2a is stored in the location mentioned:
![crackme-007](/assets/img/Challenges/no-standards/img-7.png)

If we do the calculation we would observe that these code is junk code added to confuse the first condition result is true as the calculation will not be equal to 0x10203222121 and the second condition result will be false as the calculation will not be equal to 0x10221503000, so it will jump to else condition of second "if" statement that we have which is: 

```
cVar1 = FUN_00101475();
  if (cVar1 == '\0') {
    if ((long)(~(int)DAT_00104000 + DAT_00104000 * 8) != 0x10203222121) {
      if ((long)(~(int)DAT_00104000 + DAT_00104000 * 8) == 0x10221503000) {

			// removed the code as this condition is not taken.
      }
      else {
        FUN_00101360(local_19,8);
        cVar1 = FUN_001012ff(local_11,local_19,8);
      }
      if (cVar1 == '\0') {
        lVar6 = FUN_00101280("unfortunately that isn\'t the correct passphrase\n");
        FUN_0010123f("unfortunately that isn\'t the correct passphrase\n");
      }
      else {
        lVar6 = FUN_00101280("congratulations! you managed to escape\n");
        FUN_0010123f("congratulations! you managed to escape\n");
      }
      bVar2 = FUN_00101000();
      *(byte *)(lVar6 + -0x185cdca1) = *(byte *)(lVar6 + -0x185cdca1) ^ bVar2;
      return;
    }
      // removed some code as we are inside the first "if" condition
  }
```

So, we need to now focus on this part of the code, where the key might be getting compared: 

```
      else {
        FUN_00101360(local_19,8);
        cVar1 = FUN_001012ff(local_11,local_19,8);
      }
      if (cVar1 == '\0') {
        lVar6 = FUN_00101280("unfortunately that isn\'t the correct passphrase\n");
        FUN_0010123f("unfortunately that isn\'t the correct passphrase\n");
      }
      else {
        lVar6 = FUN_00101280("congratulations! you managed to escape\n");
        FUN_0010123f("congratulations! you managed to escape\n");
      }
```

We can observe from above code that call to function FUN_00101360() is being made with input "local_19" array as input, with second parameter as integer 8, and from the analysis of function FUN_00101203 we know that the user input is getting stored in "local_11" array. 

From looking into the decompiled version of function "FUN_001012ff" we can observe that it is comparing the two arrays till the provided third parameter "length", it is self understandable. 

![crackme-008](/assets/img/Challenges/no-standards/img-8.png)

Now, we need to analyze the function call being made before this function, which is ```
```
FUN_00101360(local_19,8);
```


### # Analysis of FUN_00101360():

Let's analyze this function, first argument to this function is "local_19" array and second parameter is 8 (integer), it can be observed that: 
* It can be seen that first index of array "local_19" is set as : 0x3a (":" character)
* Next using the previously analyzed function "FUN_00101280" length of the string stored in location "DAT_00104010" is getting calculated and getting returned in variable "bVar1".

![crackme-009](/assets/img/Challenges/no-standards/img-9.png)

Let's see what data is stored in the location: "DAT_00104010" , we can see that these characters are stored in the location, so the function "FUN_00101280" will calculate length of this till it encounters null characters, so the collection of characters are stored is: "KHINOLMBC@AFGDEZ\[XY^_\\]RSP" , so this function will return 26.

![crackme-010](/assets/img/Challenges/no-standards/img-10.png)

So, "bVar1" is equal to 25. Next it is doing XOR operation with the defined characters in the location "DAT_00104010", so XOR operation will be performed with all these characters : "KHINOLMBC@AFGDEZ\[XY^_\\]RSP" stored in  "DAT_00104010".

```
  if (bVar1 != 0) {
    lVar2 = 0;
    do {
      (&DAT_00104010)[lVar2] = (&DAT_00104010)[lVar2] ^ 0x2a;
      lVar2 = lVar2 + 1;
    } while ((byte)lVar2 < bVar1);
  }
```

We would observe that if we do XOR of the stored data with 0x2a, we can write a small program: 
```
#include<stdio.h>

int main()
{
	char* str = "KHINOLMBC@AFGDEZ[XY^_\\]RSP";
	char val;
	int i = 0;
	for(; i<=25;i++)
	{
		val = str[i] ^ 0x2a;
		printf("index: %d, character: %c \n", i, val);
	}

	return 0;
}

```

![crackme-011](/assets/img/Challenges/no-standards/img-10-1.png)

Next the "if" condition will not be executed as "bVar1" is greater than 10.  Next code instructions are: 

```
param_1[1] = (&DAT_00104010)[(int)(0x2a % (ulong)(long)(int)(uint)bVar1) + 6];
param_1[2] = (&DAT_00104010)[(int)(0x2a % (ulong)(long)(int)(uint)bVar1)];
param_1[3] = 10;
param_1[4] = 0x2a < bVar1;
param_1[5] = bVar1 % 0x1a;
```

So, if we evaluate these we will get to know that: 

```
param_1[1] = DAT_00104010[22];
param_1[2] = DAT_00104010[16];
param_1[3] = 10;
param_1[4] = 0;
param_1[5] = 0;
```

So, the array "local_19" which was passed with reference as input to this function becomes: 
```
param_1[0] = ":";
param_1[1] = "w";
param_1[2] = "q";
param_1[3] = 10;    // character "\n" in ascii
param_1[4] = 0;
param_1[5] = 0;
```

Now, we know that what are the contents in the array "local_19", next it compares both the arrays "local_19" and where the user input is stored "local_11" array till the length 8.  But observe that "param_1\[3\] = 10 (which is "\n" character, this will be considered as the input when user will press the enter keyword while providing the user input)". 

So, what if we provide the user input as ":wq", lets see what happens: 

![crackme-012](/assets/img/Challenges/no-standards/img-11.png)

Yeah!!! we have escaped...................


**Note:** You might be thinking what happened to the characters at index 6th and 7th as we know that "local_11" array was initialized with 0 before and based on the memory layout array "local_19" also contained 0, so 6th and 7th index matched. I created a program for checking that as well: 

```
#include<stdio.h>

int check(char* str1, char* str2, int len)
{
	long lVar1;
	if(len == 0){
		return 1;
	}
	lVar1 = 0;
	do{
		if(str1[lVar1] != str2[lVar1]){
			return 0;
		}
		lVar1 = lVar1 + 1;
	}while(len != lVar1);
	return 1;
}

int main()
{
	char *ptr;
	char str1[8];
	char str2[8];
	char str3[8];
	ptr = str2;
	do{
		*ptr = 0;
		 ptr = ptr+1;
	}while(ptr != str3);

	str1[0] = ':';
	str1[1] = 'a';
	str1[2] = 'b';
	str1[3] = 10;
	str1[4] = 0;
	str1[5] = 0;

	int i = 0;
	for(; i<8; i++){
		printf("%d ", str1[i]);
	}
	str2[0] = ':';
    str2[1] = 'a';
    str2[2] = 'b';
    str2[3] = 10;
	
	printf("\n");
	i = 0;
	for(; i<8; i++){
		printf("%d ", str2[i]);
	}
	printf("\n");
	int val = check(str1, str2, 8);
	printf("Val : %d", val);
	
}
```

We can observe that if we run this above programs, both the arrays are equal, that is why we are able to achieve and successfully complete the challenge. 

![crackme-013](/assets/img/Challenges/no-standards/img-12.png)

Lets' get back with another cool challenge...

