---
title: Follow the asm
description: >-
   In this reverse engineering challenge we would see that static analysis doesn't provides us that much of info. to solve, so we need to dynamically understand the behaviour of the program, and understand what input exactly it requires, so that we can make our input which is expected and try to solve the challenge. 
author: deepsecops
date: 2025-03-05T12:00:00+0530
categories: [Reverse Engineering Challanges, crackme]
tags: [crackme]
toc: true
---

In this reverse engineering challenge we would see that static analysis doesn't provides us that much information to solve or move further, so we need to dynamically understand the behavior of the program, and understand what input exactly it requires, so that we can make our input which is expected and try to solve the challenge.

It makes use of the "ebp" register as base and writes the instructions in the stack, later on it makes the execution jump to the stack by making a call to stack address where instructions were stored and from there it would process and compare the user input bytes with the XOR encrypted bytes. I have explained all the details in my writeup. 


Link to the Challenge: [https://crackmes.one/crackme/66fd63059b533b4c22bd0b91](https://crackmes.one/crackme/66fd63059b533b4c22bd0b91)

My Linkedin Profile: [https://www.linkedin.com/in/deepak-bhardwaj-aa8543143/](https://www.linkedin.com/in/deepak-bhardwaj-aa8543143/)

My crackme's profile: [https://crackmes.one/user/anon786](https://crackmes.one/user/anon786) 


![crackme-001](/assets/img/Challenges/follow-asm-call/img-1.png)

This challenge is written in assembly using the NASM and with C, our goal is to find the correct input which will print the success message in the standard output. 

Observe that it is an ELF executable.

![crackme-002](/assets/img/Challenges/follow-asm-call/img-2.png)

Let's run this executable and see, observe that "wrong key" message is getting received in stdout. 

![crackme-01-1](/assets/img/Challenges/follow-asm-call/img-1-1.png)

Observe that no interesting information could be seen from the "strings" utility. 

![crackme-003](/assets/img/Challenges/follow-asm-call/img-3.png)

Observe that if we do "info functions" only 2 functions we could see: 

![crackme-004](/assets/img/Challenges/follow-asm-call/img-4.png)

If we will disassemble/de-compile this binary using the ghidra tool, we would observe that it is hard to analyze statically, contains many repeated instructions and after approx. 1000 lines of code, observe that the function pointer is getting assigned with some value and then the function is getting invoked by dereferencing the function pointer and calling the function. 

![crackme-005](/assets/img/Challenges/follow-asm-call/img-5.png)

According to me from here (where function pointer is called) the assembly instructions which is written originally by the programmer is getting invoked, where after here it will be all pure assembly instructions which is executing instructions defined in assembly, as the address to the "call" instruction is getting calculated at the run-time.So, while static analysis we will not be able to follow up with the code flow, as the executable code is being referenced in some other locations in the memory. 


## # Dynamic Analysis: 

Lets use "gdb" to analyze what actually is happening, and set the breakpoint at "_start" function: 

![crackme-006](/assets/img/Challenges/follow-asm-call/img-6.png)

**Note:** If we carefully observe the disassembly it can be observed that the using the "ebp" as the base pointer of the current frame of the "_start" function many information is getting written into the stack space. 

![crackme-007](/assets/img/Challenges/follow-asm-call/img-7.png) 

Let's see if the "stack" is executable for this program, observe that stack space is "executable" for this binary. 

![crackme-008](/assets/img/Challenges/follow-asm-call/img-8.png)

After looking into assembly found the last conditional after the operations were performed in the stack memory region, let's analyze the last conditional instruction (as before that writing/reading operation is performed in the stack using the "ebx" as the base register), if this condition will be "true" then it will jump in the location which is relative to the "_start" function. And this condition is after the "13579" lines of instructions in the disassembly of "_start" function. Let's add a breakpoint
at that particular instruction: 

```b *0x5655950b```

![crackme-08-1](/assets/img/Challenges/follow-asm-call/img-8-1.png)

Observe that once the execution reaches after continuing, observe that the "operand" to the "call" instruction is getting calculated, so the address of the function to call is getting calculated and stored in the "eax" register, initial value of "eax" is 0. 

![crackme-009](/assets/img/Challenges/follow-asm-call/img-9.png)

As, we could observe that call is to address in the stack region: ```0xffffcd39```

![crackme-010](/assets/img/Challenges/follow-asm-call/img-10.png)

And this address in the stack region is pointing to the assembly instructions ```0x6853db31```, if we decode this ```0x6853db31``` we would observe that it is assembly instructions for the x86 architecture.
If we step into the assembly instructions, after pushing some values into the stack, we would observe that it is making a system call number 3 (which is system call number for read()), lets analyze the values of stack at this point, when it is in the instruction to make system call. 

![crackme-011](/assets/img/Challenges/follow-asm-call/img-11.png)

Observe that: 
   - "eax" value is 3 (which means system call to read()).
   - "ebx" value is 0 (which means standard input from which input would be taken).
   - "ecx" is holding some location address ```0xffffccf8``` which will store the user input obtained from read() function. 
   - "edx" value is "0x28" (which means 40 max. bytes to be read from stdin).


I have provided input as 30 characters:  ```AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA```


Once the user provides the input using "stdin", then we would observe that the number of bytes read by the system call was returned in the "eax" register and if we observe the assembly in "code" section "eax" getting XORed with "edx" register
and then added with "0x11f2", then some of address is getting stored in the "ebx" register by referring to an address in the data segment (ds) with the offset 0x1223. And then further the value of "eax" and "ebx" is getting compared, based on 
the comparison if both "eax" and "ebx" will not be equal then execution jumps to the address "0xffffce34", lets step into the assembly and further observe what is going on. What is the value that is getting stored in "eax", "ebx". What is in the address "0xffffce34".

Register values: 
```
$eax   : 0x1e      (30 in decimal)    
$ebx   : 0x0       
$ecx   : 0xffffccf8  →  0x41414141 ("AAAA"?)
$edx   : 0x28      (40 in decimal)
$esp   : 0xffffccf8  →  0x41414141 ("AAAA"?)
$ebp   : 0xffffcecc  →  0x00000000
$esi   : 0xffffcd39  →  0x6853db31
$edi   : 0x16b     
```

Code section: 
```
   0xffffcd8d                  int    0x80
 → 0xffffcd8f                  xor    eax, edx
   0xffffcd91                  add    eax, 0x11f2
   0xffffcd96                  lea    ebx, ds:0x1223
   0xffffcd9c                  cmp    eax, ebx
   0xffffcd9e                  jne    0xffffce34
   0xffffcda4                  mov    ebx, 0x0
```

It can be observed that in below image, that the "eax" is holding 0x1228 and "ebx" is holding 0x1223 and as both the values were not same after the comparison jump is taken to the address "0xffffce34", that is pushing 
some values in the stack, lets step into assembly again and observe where we reaches. 

![crackme-012](/assets/img/Challenges/follow-asm-call/img-12.png)


Observe that if we step into assembly and observe that it is the "wrong key exit" condition of the program. Lets save this address ```0xffffce34``` and whenever we encounter it again we would understand that this is the "wrong key exit" condition.

![crackme-013](/assets/img/Challenges/follow-asm-call/img-13.png)

So, to make sure we don't hit the "wrong key exit" condition again, we need to make sure that after the input where the "eax" and "ebx" registers were getting compared, they both hold the same value, we can control the value of "eax" register and "ebx" value is obtained from data section. 
By Observation we could tell that we need to make the value of "eax" same as "ebx" which is ```0x1223```, so we need to add some value in ```0x11f2``` to make it equal to ```0x1223```, if we do math we would know that we need to add ```0x31``` with ```0x11f2``` to make it ```0x1223```
So, we need to make the result of the instruction ```xor eax, edx``` as ```0x31```, as we know that "edx" is holding the value ```0x28``` and we know result should be ```0x31```, so by doing XOR of ```0x28 ^ 0x31``` we would get ```0x19```, 
thus now we know that we need to provide ```0x19``` bytes as input, it means the input length limit on this program is 25 characters. Let's now provide exactly 25 characters (24 characters and one new line character when we press enter).

```
 → 0xffffcd8f                  xor    eax, edx
   0xffffcd91                  add    eax, 0x11f2
```

Let's again start the program with the debugger and reach to the execution point where we would provide the input that has length of 24 characters (another character would automatically be included when we press enter): ```AAAAAAAAAAAAAAAAAAAAAAAAA``` 
Observe that "eax" contains ```0x19``` that is what we wanted, lets continue and see what happens at the comparsion. 

![crackme-014](/assets/img/Challenges/follow-asm-call/img-14.png)

Observe that at this time the jump is not taken as both "eax" and "ebx" were equal, and observe that the user input is at the top of the stack "esp": 

![crackme-015](/assets/img/Challenges/follow-asm-call/img-15.png)


Let's see the current value of registers: 
```
$eax   : 0x1223    
$ebx   : 0xa455    
$ecx   : 0xffffccf8  →  "AAAAAAAAAAAAAAAAAAAAAAAA\n"
$edx   : 0x28      
$esp   : 0xffffccf8  →  "AAAAAAAAAAAAAAAAAAAAAAAA\n"
$ebp   : 0xffffcecc  →  0x00000000
$esi   : 0xffffcd39  →  0x6853db31
$edi   : 0x16b     
$eip   : 0xffffcdb5  →  0xf3812574
```

Let's see the next assemnly instructions and for refernce I have added the values of registers after these instructions gets executed with comment explained below: 
```
cmp    eax, ebx
jne    0xffffceb4  --> Not taken as this time we make "eax" and "ebx" equal
mov    ebx, 0x0
xor    ebx, 0xa455   // No use instruction
cmp    ebx, 0xa453   // No use instruction
je     0xffffce5c  --> Not taken obviously as "ebx" was not equal to "0xa453"
xor    ebx, 0xa455 --> ebx: 0
lea    eax, [esp+ebx*4]    --> pointing to tos (user input string)
mov    eax, DWORD PTR [eax] --> $eax   : 0x41414141 ("AAAA"?)  // This would move the 4-bytes from address (by dereferncing it) in eax to itself
mov    ecx, 0x4c2c4c2c   --> $ecx   : 0x4c2c4c2c (",L,L"?)
xor    ecx, 0x11111111   --> $ecx   : 0x5d3d5d3d ("=]=]"?)
xor    eax, ecx          --> $eax   : 0x1c7c1c7c
lea    ecx, [esp+ebx*4+0x1c]   --> $ecx   : 0xffffcd94  →  0x0f7e186e
mov    ecx, DWORD PTR [ecx]   --> $ecx   : 0xf7e186e
cmp    ecx, eax               --> Comparison of "ecx" and "eax"
jne    0xffffceb4    --> wrong key exit condition
```

Observe that the "eax" holds the first four bytes of the user input, and "ecx" value after the xor with ```0x11111111``` becomes ```0x5d3d5d3d```

![crackme-016](/assets/img/Challenges/follow-asm-call/img-16.png)


### # The core logic to extract the correct key

So, from the above assembly instructions, it could be seen that first four characters of the user input is stored in the "eax" register
Then ```0x4c2c4c2c``` value is getting moved to "ecx" register, then "ecx" is getting XORed with ```0x11111111``` which would result in "ecx" to become ```0x5d3d5d3d```
Then further "eax" and "ecx" is getting XORed and result will be stored in "eax", we know that user input first 4 characters were stored in "eax". 
 
Then if we observe that some value is getting loaded in the "ecx" register using these instructions: 
```
   0xffffcdcf                  lea    ecx, [esp+ebx*4+0x1c]
   0xffffcdd3                  mov    ecx, DWORD PTR [ecx]
```

Then this "ecx" value is getting compared with the "eax" value and if they both matches the execution will continue, else if we observe that if "ecx" and "ebx" will not be equal
we would jump into the "wrong key" condition and execution will stop. 

**Note:** To extract the correct key, we need to make sure that "ecx" and "eax" match, lets see what value does "ecx" holds which is getting compared with "eax". 

![crackme-017](/assets/img/Challenges/follow-asm-call/img-17.png)

Observe that "ecx" holds the value ```0xf7e186e``` which is getting compared with the "eax" register, but we want these two registers having same value, so how can we make "eax" same as "ecx" 
This is crucial step that we need to know with which value of "eax" XOR of "ecx" would be done so that the result comes out to ```0xf7e186e```

```
mov    ecx, 0x4c2c4c2c   --> $ecx   : 0x4c2c4c2c (",L,L"?)
xor    ecx, 0x11111111   --> $ecx   : 0x5d3d5d3d ("=]=]"?)  --> We will use this value of "ecx" to XOR with "x0f7e186e"

xor    eax, ecx          --> $eax   : This "eax" value we need to know with what value we need to do XOR so that the result comes out to 0xf7e186e

lea    ecx, [esp+ebx*4+0x1c]   --> $ecx   : 0xffffcd94  →  0x0f7e186e
mov    ecx, DWORD PTR [ecx]   --> $ecx   : 0xf7e186e
cmp    ecx, eax               --> Comparison of the "eax" and "ecx"
```

Like previously we could do XOR operation of value stored in "ecx" before XOR with the "eax", the "ecx" value before was ```0x5d3d5d3d``` and the result ```0xf7e186e```, so that we can make "eax" equal to ```0xf7e186e``` 
If we do these 4 hex values "0x0f7e186e" xor with the "0x5d3d5d3d" we get "52434553" which is these 4 characters: ```RCES```

**Note:** As we know that in x86 architecture data is stored in little endian format, so if we reverse the 4 characters "RCES" we would get "SECR". 

Currently as we have passed the wrong first four characters, we would enter into the jump condition which is the "wrong key" condition. Observe that like previosuly "wrong key" message is getting pushed into stack and execution will stop. 

![crackme-018](/assets/img/Challenges/follow-asm-call/img-18.png)


Now as we have our first four characters of the correct key, lets again run this program with providing first four characters as "SECR" and remember that the string needs to be 24 characters, so we will pass: ```SECRAAAAAAAAAAAAAAAAAAAA```
Observe that this time comparison is successfull both "eax" and "ecx" value was same and we didn't went into "wrong key" condition. 

![crackme-019](/assets/img/Challenges/follow-asm-call/img-19.png)

Let's further step into assembly and further try to find the next correct characters for the key. 
The instructions after stepping into assembly after the successful comparison are (added comments for reference explained below): 
```
→  0xffffce29                  xor    ebx, 0xa455   -->   $ebx   : 0xa454
   0xffffce2f                  cmp    ebx, 0xa453
   0xffffce35                  je     0xffffce5c    -->   Not taken 
   0xffffce37                  xor    ebx, 0xa455   -->   $ebx   : 0x1
   0xffffce3d                  lea    eax, [esp+ebx*4]   --> eax pointing to string starting from 5th character
   0xffffce40                  mov    eax, DWORD PTR [eax] --> This would move the 4-bytes from address (by dereferncing it) in eax to itself
   0xffffce42                  mov    ecx, 0x4c2c4c2c   
   0xffffce47                  xor    ecx, 0x11111111
   0xffffce4d                  xor    eax, ecx
   0xffffce4f                  lea    ecx, [esp+ebx*4+0x1c]
   0xffffce50                  mov    ecx, DWORD PTR [ecx]
 → 0xffffce55                  cmp    ecx, eax
   0xffffce57                  jne    0xffffceb4    --> wrong key exit condition
   0xffffce59                  inc    ebx
```

Again if we observe these instructions are similar just difference is that now "eax" holds the next 4 bytes from the 5th byte of user input, so in "eax" we have "5,6,7,8" characters/byte of user input. 
Again after below operations we would get the value as ```0x5d3d5d3d```: 
```   
0xffffce42                  mov    ecx, 0x4c2c4c2c   
0xffffce47                  xor    ecx, 0x11111111
```

One more thing is that now the value which is getting stored in "ecx" while execution of below instructions is also getting loaded from different place as now "ebx" is "0x1", so this time the value would be different:
```
0xffffce4f                  lea    ecx, [esp+ebx*4+0x1c]
0xffffce50                  mov    ecx, DWORD PTR [ecx]
```   
Let's see what is the value which is getting stored in "ecx" which is finally again getting compared with "eax". 

![crackme-020](/assets/img/Challenges/follow-asm-call/img-20.png)

Observe that the value ```0x19460978``` is getting stored in the "ecx" that will get compared with the value in "eax", so like previously we need to do XOR of "ecx" register when the "ecx" register value is calculated using below instructions:
```
0xffffce42                  mov    ecx, 0x4c2c4c2c   
0xffffce47                  xor    ecx, 0x11111111
```

As the calculated "ecx" value is getting XORed with "eax" which is then getting compared with ```0x19460978```, so to calculate the "eax" value which would make the XOR of "eax" and "ecx" equal to ```0x19460978```
So, lets perform XOR of "0x19460978" and "0x5d3d5d3d" which comes out as "0x52434553" which is these 4 characters: is ```D{TE```

If we reverse these 4 characters, we get next 4 correct characters of the key: ```ET{D```
So, our key now becomes: ```SECRET{DAAAAAAAAAAAAAAAA```

If we keep on continuing the same we would observe that we are able to get the full correct key required by the program:
```
SECRET{D0n_wAAAAAAAAAAAA --> next 4 correct characters
SECRET{D0n_wtf_dAAAAAAAA --> next 4 correct characters
SECRET{D0n_wtf_did_uAAAA --> next 4 correct characters
SECRET{D0n_wtf_did_u_do} --> Full correct key of length 24
```

Let's pass this correct key to our program and observe if we are getting any success message: 

![crackme-021](/assets/img/Challenges/follow-asm-call/img-21.png)



This Challenge was amazing..... See you with next one if you are reading.






















