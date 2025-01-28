---
title: Simple CTF
description: >-
  This challenge is easy just by looking into the decompiled version one can obtain the logic and using simple math operation this challenge can be solved. 
author: deepsecops
date: 2025-01-17T12:00:00+0530
categories: [Reverse Engineering Challanges, Simple CTF]
tags: [crackme]
toc: true
---


## Simple CTF

Link to the challange: https://crackmes.one/crackme/66ee30341070323296555610 

This challenge was simple as by looking at the decompiled version of the code we could figure out the inner workings and do reversing of the interesting functions, we didn't have to dig in into the disassembly. 

Observe that we have ELF binary, in which the user input is being prompt and it requires a special string to get to the right condition, we would be using "Ghidra" to analyze the disassembled and decompiled code. 

![[Pasted image 20241030153152.png]]

This is the decompiled version of the main() function, provided by the ghidra, observe that lots of local variables in the decompiled code, 

```

undefined8 main(void)

{
  int iVar1;
  void *pvVar2;
  long in_FS_OFFSET;
  size_t local_e8;
  size_t local_e0;
  undefined4 local_c8;
  undefined4 local_c4;
  undefined4 local_c0;
  undefined4 local_bc;
  undefined4 local_b8;
  undefined4 local_b4;
  undefined4 local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined local_88 [65];
  char local_47 [15];
  char local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_c8 = 0x1a22;
  local_c4 = 0x20c7;
  local_c0 = 0x1b50;
  local_bc = 0x2515;
  local_b8 = 0x29c6;
  local_b4 = 0x28ff;
  local_b0 = 0x2d4c;
  local_ac = 0x2d4d;
  local_a8 = 0x2646;
  local_a4 = 0x2f43;
  local_a0 = 0x2f44;
  local_9c = 0x2f45;
  local_98 = 0xc82;
  local_94 = 0x16ab;
  local_90 = 0x1a94;
  puts("D0 50M3 H4CK3r r3V");
  read(0,local_47,0xf);
  iVar1 = strncmp(local_47,valid_ctf,0xf);
  if (iVar1 == 0) {
    local_38[0] = -0x30;
    local_38[1] = -0x2f;
    local_38[2] = -0x36;
    local_38[3] = -0x3b;
    local_38[4] = -0x2d;
    local_38[5] = -0x7c;
    local_38[6] = -0x33;
    local_38[7] = -0x28;
    local_38[8] = -0x7c;
    local_38[9] = -0x33;
    local_38[10] = -0x29;
    local_38[0xb] = -0x2e;
    local_38[0xc] = -0x28;
    local_38[0xd] = -0x7c;
    local_38[0xe] = -0x28;
    local_38[0xf] = -0x34;
    local_38[0x10] = -0x3b;
    local_38[0x11] = -0x28;
    local_38[0x12] = -0x7c;
    local_38[0x13] = -0x29;
    local_38[0x14] = -0x33;
    local_38[0x15] = -0x2f;
    local_38[0x16] = -0x2c;
    local_38[0x17] = -0x30;
    local_38[0x18] = -0x37;
    local_38[0x19] = 'n';
    local_38[0x1a] = '\0';
    for (local_e8 = 1; local_38[local_e8] != '\0'; local_e8 = local_e8 + 1) {
    }
    pvVar2 = malloc(local_e8);
    for (local_e0 = 0; local_e0 != local_e8; local_e0 = local_e0 + 1) {
      *(char *)(local_e0 + (long)pvVar2) = local_38[local_e0] + -100;
    }
    *(undefined *)((long)pvVar2 + local_e8 + 1) = 0;
    printf("%s",pvVar2);
  }
  ctfhash(local_47,local_88,0xf);
  iVar1 = compare_hashes(&local_c8,local_88,0xf);
  if (iVar1 == 0) {
    puts("7rY 4641N");
  }
  else {
    puts("Y4Y U D1D 17");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}


```

Observe that after the string input received from the user input, the string is compared with the defined constant string "valid_ctf", and according to the return type received from the strcmp() function it would take the next "if" condition, however if we observe a bit, it could be seen that final comparison is taking place after the "if" condition, and that code part will be executed every time no matter what is the output from the string comparison above. 

We would observe that there are two function calls, one is "ctfhash()" and other is "compare_hashes", we would analyze the working of these two functions. 

We could also see after the call to "ctfhash()" function there is another function getting called "compare_hashes" and from the return value received from the function call "compare_hashes()", there are two ways to reach to the condition where we would get "Y4Y U D1D 17":
- First is the runtime debugging using "gdb" debugger, where we could enter any random string and when the function call would return from the function "compare_hashes", we would simply change the return value of the "eax"/"rax" register to 0, to make sure the success condition would be executed. 
- We would follow this second approach where we would reverse engineer the functions "ctfhash()" and "compare_hashes()", to understand what is the exact string it requires to reach to the succeeding else condition. 


From the above code we have some points to note:
- the user input is getting stored in the "local_47" character array:
		- ```read(0,local_47,0xf);```

- the function "ctfhash()" takes 3 parameters, the first is the user input array of 15 characters and second is the local_88 array and the size as 0xf or 15 in decimal: 
		- ```ctfhash(local_47,local_88,0xf);```

- the function "compare_hashes" takes 3 parameters, the first is the reference to the local variable defined as "local_c8" and the second is the local_88 array which was passed and processed in the "ctfhash" function, third is the size as 15:
		- ```compare_hashes(&local_c8,local_88,0xf);```


#### Analysis of "compare_hashes" function:
Now, observe that in the function "compare_hashes", the reference to the local variable is passed, so lets check this function decompiled version:

![[Pasted image 20241030153215.png]]


From the above code understanding this part is crucial:
if (*(int *)(param_1 + local_10 * 4) != *(int *)(param_2 + local_10 * 4)) break;

Lets understand this part and the working of loop: 

When the loop starts running initially in the "param_1" we have the reference of the local variable "local_c8", look into the decompiled version of "main" function, observe that its value is "0x1a22", and the value of "local_10" would be 0 initially, so the result of the statement below would be: 

```*(int *)(param_1 + local_10 * 4)```

On 1st Iteration:
```*(int *)(param_1) --> (int*)0x1a22 --> 0x20c7 // here it is just typecasting it to the size of the pointer which is 8 bytes in 64 bits, so the final value contains the variable value of local_c8```

On 2nd Iteration: 
Now the reference "param_1+4" would point to next variable defined because by adding 4 to the reference value stored in "param_1", we are moving 4 bytes forward in reference now the effective reference would point to next variable which would be "local_c4" and "local_10" value would be 1 now.

```*(int*)(param_1+4) --> (int*)0x20c7 --> 0x20c7```

So, in the function "compare_hashes" function its just compares the value stored in the variables from "local_c8" till variable "local_90" with each index from 0-14th index of the "local_88" array passed.

#### Analysis of the "ctfhash" function:
So, now we need to understand how the "local_88" array values were created in the function "ctfhash" using the user input which is stored in the "local_47" character array:

![[Pasted image 20241030153239.png]]

If we observe the function and analyze the processing of it, we could make a simplified version of the above code as: 

```
ctfhash(local_47,local_88,0xf):

	for (i = 0; i < 0xf ; i++) 
	{
		local_88[i] = (local_47[i] * 100);
		local_88[i] = i + local_88[i] + (-10);	
	}

```

And now we could understand that how the "local_88" array elements are being created. 

*Note: If the user would pass the correct key or the string when this binary would run, the index value that would be stored in array local_88 would be same as the value stored in the local variables from local_c8 to local_90, something like this:*

```
```local_88[0] = 0x1a22;
local_88[1] = 0x20c7;
local_88[2] = 0x1b50;	
local_88[3] = 0x2515;
local_88[4] = 0x29c6;
local_88[5] = 0x28ff;
local_88[6] = 0x2d4c;
local_88[7] = 0x2d4d;
local_88[8] = 0x2646;
local_88[9] = 0x2f43;
local_88[10] = 0x2f44;
local_88[11] = 0x2f45;
local_88[12] = 0xc82;
local_88[13] = 0x16ab;
local_88[14] = 0x1a94;
```

So, by doing some math we could easily identify the local_47 array as we already know local_88 array from 0 to 14th index: 

```local_47[i] = ((local_88[i] + 10) - i) / 100```

So, the final program to generate the key or string to successfully run this program would be: 

```
#include<stdio.h>
#include<stdlib.h>

void main()
{

	int local_88[65];

	local_88[0] = 0x1a22;
	local_88[1] = 0x20c7;
	local_88[2] = 0x1b50;	
	local_88[3] = 0x2515;
	local_88[4] = 0x29c6;
	local_88[5] = 0x28ff;
	local_88[6] = 0x2d4c;
	local_88[7] = 0x2d4d;
	local_88[8] = 0x2646;
	local_88[9] = 0x2f43;
	local_88[10] = 0x2f44;
	local_88[11] = 0x2f45;
	local_88[12] = 0xc82;
	local_88[13] = 0x16ab;
	local_88[14] = 0x1a94;

	char flag[15];
	int i = 0;
	for( i=0; i<0xf ; i++)
	{
		flag[i] = ((local_88[i] + 10) - i) / 100; 

	}

	i = 0;
	for(; i< 0xf; i++)
	{
		printf("%c",flag[i]);
	}

}
```

When this program would be run, a string would be printed in console, which is the final string that is expected by this binary. 

I hope this was fun.. I enjoyed solving this. 