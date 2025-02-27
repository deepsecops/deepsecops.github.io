---
title: Baby's First Crackme
description: >-
  This challenge make use of disassembly and creating the pseudo-code for the function, analysis of the decompiled function to solve the challenge.
author: deepsecops
date: 2025-01-17T12:00:00+0530
categories: [Reverse Engineering Challanges, crackme]
tags: [crackme]
toc: true
---


## Baby's First Crackme:

Link to the Challenge: [https://crackmes.one/crackme/66736380e7b35c09bb266f92](https://crackmes.one/crackme/66736380e7b35c09bb266f92)

My Linkedin Profile: [https://www.linkedin.com/in/deepak-bhardwaj-aa8543143/](https://www.linkedin.com/in/deepak-bhardwaj-aa8543143/)

My crackme's profile: [https://crackmes.one/user/anon786](https://crackmes.one/user/anon786)

This challenge was of easy difficulty as well, where we just have to understand the code logic, and reverse some functions, we need to analyze assembly instructions to get to know the proper argument values. Solving this challenge from disassembly + de-compiled code, so even if the symbols were stripped for this binary, we can get the logic easily. Lets dive into the challenge.

Observe that it is an ELF executable, with the symbols not stripped and the usage is provided, it accepts : key and a number

![crackme-001](/assets/img/Challenges/baby-first-crackme/img-1.png)


Let's analyze the binary using "Ghidra" or "gdb", we would observe that once binary is analyzed by the tool we could see the disassembly and de-compilation of the binary. 

Here the calling convention would be according to the System-V ABI (Unix-like systems) which is running in the x86 architecture as this binary is compiled for x86-64 systems: 

### # Analysis of the main function:

```
001013bc 55              PUSH       RBP
001013bd 48 89 e5        MOV        RBP,RSP
001013c0 48 83 ec 20     SUB        RSP,0x20
001013c4 89 7d ec        MOV        dword ptr [RBP + local_1c],EDI
001013c7 48 89 75 e0     MOV        qword ptr [RBP + local_28],RSI
001013cb 83 7d ec 02     CMP        dword ptr [RBP + local_1c],0x2
001013cf 7f 19           JG         LAB_001013ea
001013d1 48 8d 05        LEA        RAX,[s_usage:_./rust-1_<key>_<number>_00102028]  = "usage: ./rust-1 <key> <number>"
50 0c 00 00
001013d8 48 89 c7        MOV        RDI=>s_usage:_./rust-1_<key>_<number>_00102028   = "usage: ./rust-1 <key> <number>"
001013db e8 b0 fc        CALL       <EXTERNAL>::puts                                 int puts(char * __s)
         ff ff
001013e0 b8 ff ff        MOV        EAX,0xffffffff
         ff ff
001013e5 e9 a7 00        JMP        LAB_00101491
         00 00
```


The disassembly of the code, where the first argument would be stored in the "EDI" register and second argument would be in "RSI", according to the analysis the first argument is the number of arguments to the main() function, and the second argument is the array holding the arguments to the main function. Something that we do in typical C program: 

```int main(int argc, char \*argv\[\])```

So, the count of number of arguments are stored in  : ```dword ptr [RBP + local_1c]```
and the array holding the passed arguments are stored in :  ```qword ptr [RBP + local_28]```

In this line it is checking if the number of argument passed is greater than 2 : 
```001013cb 83 7d ec 02     CMP        dword ptr [RBP + local_1c],0x2```

If the number of argument is greater than 2, it will proceed with the execution and does a jump to this branch "LAB_001013ea" else it will display the message of the "usage" using the method puts() as we could see in assembly. 

This is the second part of assembly code of the main() function, where the jump is taken to the branch "LAB_001013ea" as the arguments passed by user are greater than 2. 


   ```
         LAB_001013ea                                    XREF[1]:     001013cf(j)  
01013ea 48 8b 45 e0      MOV        RAX,qword ptr [RBP + local_28]
001013ee 48 8b 40 08     MOV        RAX,qword ptr [RAX + 0x8]
001013f2 48 89 45 f8     MOV        qword ptr [RBP + local_10],RAX
001013f6 48 8b 45 e0     MOV        RAX,qword ptr [RBP + local_28]
001013fa 48 83 c0 10     ADD        RAX,0x10
001013fe 48 8b 00        MOV        RAX,qword ptr [RAX]
00101401 48 89 c7        MOV        RDI,RAX
00101404 b8 00 00        MOV        EAX,0x0
         00 00
00101409 e8 c2 fc        CALL       <EXTERNAL>::atoi                                 int atoi(char * __nptr)
                 ff ff
0010140e 89 45 f4        MOV        dword ptr [RBP + local_14],EAX
00101411 48 8b 45 f8     MOV        RAX,qword ptr [RBP + local_10]
00101415 48 89 c7        MOV        RDI,RAX
00101418 e8 83 fc        CALL       <EXTERNAL>::strlen                               size_t strlen(char * __s)
         ff ff
0010141d 48 83 f8 0c     CMP        RAX,0xc
00101421 74 16           JZ         LAB_00101439d
00101423 48 8d 05        LEA        RAX,[s_Access_denied!_00102018]                  = "Access denied!"
         ee 0b 00 00
0010142a 48 89 c7        MOV        RDI=>s_Access_denied!_00102018,RAX               = "Access denied!"
0010142d e8 5e fc        CALL       <EXTERNAL>::puts                                 int puts(char * __s)
         ff ff
00101432 b8 ff ff        MOV        EAX,0xffffffff
         ff ff
00101437 eb 58           JMP        LAB_00101491
```

 Observe that the parameter values were getting extracted and stored. It did added 0x8 before to the base address \[RBP + local_28\] due to the reason that first argument is always the name of the program itself  (shown in below images), so that is why this is being done: 
```
01013ea 48 8b 45 e0      MOV        RAX,qword ptr [RBP + local_28]
001013ee 48 8b 40 08     MOV        RAX,qword ptr [RAX + 0x8]
```

Observe in the image, "rsi" register holding the second argument to function which is the arguments array : 
![crackme-002](/assets/img/Challenges/baby-first-crackme/img-2.png)

Observe that first three arguments to the function is printed in "gdb", while the program is running, i have set the breakpoint in the main function. 
![crackme-003](/assets/img/Challenges/baby-first-crackme/img-3.png)


The "key" which is second parameter, its value is getting stored in location :  ```qword ptr [RBP + local_10]``` 

The base address of argument array again gets stored into RAX register and referring the third value from the arguments array and passing it as an argument to the atoi() function, which would convert it to the integer value (as the third argument is expected to be a number). 

The third parameter converted integer value "number", that got (returned from the function atoi()) gets stored in the location : ```dword ptr [RBP + local_14]```

Now the strlen() function gets called with the "key" string as the argument to this function, and the length of the string returned from the function "strlen()" is getting compared with 0xc which is 12 in decimal, means it is checking whether the length of the "key" passed by user is equal to 12 or not: 
```
0010141d 48 83 f8 0c     CMP        RAX,0xc
00101421 74 16           JZ         LAB_00101439d
```

If the "key" provided by the user while running program is of 12 characters in length then  it is jumping to the branch location "LAB_00101439d" , else access denied would be printed to the user, using the puts() function as can be observed and large integer value would be returned from main function. 

This is the third and last part of the assembly code of main() function, where the jump has taken place to branch location "LAB_00101439d" as the length of the string passed from user as first argument is equal to 12: 

 ```
	                LAB_00101439                                    XREF[1]:     00101421(j)  
00101439 83 7d f4 00     CMP        dword ptr [RBP + local_14],0x0
0010143d 78 06           JS         LAB_00101445
0010143f 83 7d f4 32     CMP        dword ptr [RBP + local_14],0x32
00101443 7e 16           JLE        LAB_0010145b
                    LAB_00101445                                    XREF[1]: 0010143d(j)  
00101445 48 8d 05        LEA        RAX,[s_Access_denied!_00102018]                  = "Access denied!"
         cc 0b 00 00
0010144c 48 89 c7        MOV        RDI=>s_Access_denied!_00102018,RAX               = "Access denied!"
0010144f e8 3c fc        CALL       <EXTERNAL>::puts                                 int puts(char * __s)
         ff ff
00101454 b8 ff ff        MOV        EAX,0xffffffff
         ff ff
00101459 eb 36           JMP        LAB_00101491
                    LAB_0010145b                                    XREF[1]:   00101443(j)  
0010145b 48 8b 45 f8     MOV        RAX,qword ptr [RBP + local_10]
0010145f 48 8d 15        LEA        RDX,[DAT_00102047]      = 0Ah
         e1 0b 00 00
00101466 48 89 d6        MOV        RSI=>DAT_00102047,RDX   = 0Ah
00101469 48 89 c7        MOV        RDI,RAX
0010146c e8 4f fc        CALL       <EXTERNAL>::strcspn                              size_t strcspn(char * __s, char 
         ff ff
00101471 48 8b 55 f8     MOV        RDX,qword ptr [RBP + local_10]
00101475 48 01 d0        ADD        RAX,RDX
00101478 c6 00 00        MOV        byte ptr [RAX],0x0
0010147b 8b 55 f4        MOV        EDX,dword ptr [RBP + local_14]
0010147e 48 8b 45 f8     MOV        RAX,qword ptr [RBP + local_10]
00101482 89 d6           MOV        ESI,EDX
00101484 48 89 c7        MOV        RDI,RAX
00101487 e8 76 fe        CALL       check_key                                        undefined check_key()
         ff ff
0010148c b8 00 00        MOV        EAX,0x0
         00 00
                    LAB_00101491                                    XREF[3]:     001013e5(j), 00101437(j), 00101459(j)  
00101491 c9              LEAVE
00101492 c3              RET

```

In the branch "LAB_00101439" location, it is just checking if the third parameter "number" passed by user to the program which is a number is not smaller than 0 or not greater than 0x32 which is 50 in decimal.  If one of the conditions were not met the "access denied" message would be printed to the user and large value is getting returned from the main function. 

If the provided third parameter "number" value is more than 0 and less than 50, then the branch location "LAB_0010145b" is taken,  in this we are calling the function strcspn() by passing the first argument as the user provided second argument which is "key" getting passed in "RDI" and the second argument which is "0Ah" in "RSI", here one thing to note is "0Ah" corresponds to the new line characters in the ASCII format. So the call to the function strcspn() would look something like: 
``` strcspn(key , "\n") ```

strcspn() is used to find the length of the initial segment of a string that does **not** contain any characters from a specified set of characters. So, above call would return the length of the string segment till it encounters first occurrence of the "\n" character.  If no character was found that contains the new line character it will return the length of the string as it has traversed all characters in the string. 

In these instructions, after the function call strcspn(), it is taking the value of second argument to program which is "key" add storing it in "RDX", and adding it with the RAX which contains the return value from the function strcspn() (here basically it is going to the index of the character array "key", here index will be the return_value obtained from strcspn() function), and after that it is moving the null value to the updated value of RAX, which is the "\[RBP + local_10\] + return_value", 
something like this is happening:  
```key\[return_value\] = '\0';```

```
00101471 48 8b 55 f8     MOV        RDX,qword ptr [RBP + local_10]
00101475 48 01 d0        ADD        RAX,RDX
00101478 c6 00 00        MOV        byte ptr [RAX],0x0
```

Then after it is calling the function check_key() function with the "key" and integer value of "number" as the argument to the function that user has passed to the program while running, so the call would look something like:  ```check_key(key,num)```

So, after reversing the assembly code, we get the main() function look something like below code:

```

int main(int argc, char *argv[])
{
	int num = atoi(argv[2])     // (second argument - number)
	int key_len = strlen(argv[1])         // (first argument - key)
	const char *key = argv[1];

	if ( key_len == 12 )
	{
		if (num > 0 || num <= 50)
		{
			int val3 = strcspn(key, '\n'); --> it will return 12 (explained below)
			key[val3] = '\0';      ---> 12th index will have null, so string length would be 11 when we do strlen(key) now. 

			check_key(key,num);
		}
		else
		{
			printf("%s","Access Denied!!!");
		}
	
	}
	else 
	{
		printf("%s","Access Denied!!!");
		return 
	} 
	return;
}

```

From the above code, we can observe that function "strcspn" is getting called, lets see what it returns, so we need to make sure that the "key" value should always be 12, then only we would enter inside the condition and after that number value should be greater than 0 and less than 50, if we pass any 12 character key and as it will not contain any "\n" character in it, this function would always return 12 as the user would pass a normal string of 12 characters. 

Next it is trying to place null into the index (which is return value from previous function call) of the "key" string which would be :  key\[12\] = "\0"

So, it is just placing the null character at the end of the "key" string as "key" string is from 0th to 11th index which is 12 characters. And then it calls the "check_key(key, num)" function. 


Now, in the next part of the explanation i am using the de-compiled version of the functions provided by ghidra, as the document will become very large if we keep reversing from assembly, provided decompiled version from ghidra saves our time, however we should not fully dependent on the decompiled version of the function, as for accuracy we have to look and analyze the assembly code. 


### # Analysis of the check_key() function: 

Here is the screenshot of the de-compiled version of "check_key" function by ghidra.

![crackme-004](/assets/img/Challenges/baby-first-crackme/img-4.png)

If we observe the function and analyze the processing of it, we could make a simplified version of the above code as: 

```
check_key(key,num):
	
	char local_58[56];
	encode_input(key,num,local_58)
	
	int val; 
	int j = 0;
	while(true)
	{
		strval = strlen(local_58);
		if (strval <= j)break;
		val = local_58[j];
		j = j + 1;

	}

	if ( val == 124 )
		print("Access granted!!")
	else:
		print("Access Denied!!")

```

Observe that "local_58" character array is defined, and the "encode_input" function is being called, the function must be doing some processing on the "local_58" array as it is getting passed to the "encode_input" function. 

It can also be observed from above code that the while loop is running till variable "j" is less than or equal to "strval", which is the length of the "local_58" array, so the "val" at the end of the loop would have the value as : val = local_58\[strlen(local_58) - 1\]

**Observation:** And if the "local_58\[strlen(local_58) - 1\]" is equal to 124 , it prints the "Access granted!!!" in the console, else "Access Denied" is printed. 

Now, we need to understand what are the contents in the "local_58" array, so for that we need to analyze the "encode_input" function:  


### # Analysis of the encode_input() function: 

Here is the screenshot of the de-compiled version of "encode_input" function by ghidra.

![crackme-005](/assets/img/Challenges/baby-first-crackme/img-5.png)

If we observe the function and analyze the processing of it, we could make a simplified version of the above code as: 

```
encode_input(char* key, int num, char* local_58):
	 
	int i;

	for ( i = 0; key[i] != '\0'; i++)
	{
		if( i & 1 == 0)
		{
			if( (key[i] & 1) == 0)
			{
				local_58[i] = key[i] - num;
			}
			else
			{
				local_58[i] = key[i] + num;
			}
		}
		else if((key[i] & 1) == 0)	
		{
			local_58[i] = key[i] + num * '\x02'; 
		}
		else
		{
			local_58[i] = key[i] + num * -2; // result will be odd (odd-even=odd)
		}
	}

	local_58[i] = '\0';
	return;

}
```

Observe that this function is writing into the "local_58" array till the length of the "key" array that we have passed as an argument to this function, so length of the "local_58" would also be equal to the "key" length which is 12. 


So, from above analysis we know that if the "local_58\[strlen(local_58) - 1\]" is equal to 124 , it prints the "Access granted!!!" in the console, else "Access Denied" is printed.  The local_58\[11\] value should be equal to 124  (the resulting character in local_58\[11\] should contain "|" ) when comparison would happen it will automatically gets type-casted to its decimal value according to ASCII table. 

So, according to function "encode_input" lets see in which condition inside loop local_58 array's 11th index is getting populated as we now know what should be the resulting value at that index. 

**Note:** ***We only need to know what is the value at key\[11\]  as initial 11 characters could be anything as check is placed at the value of the 11th index which is 12th character of the key, that we need to pass from the input so that the local_58\[11\] becomes 124. 

In above function's for loop, we need to consider only case when i=11, As (11 & 1 != 0 ), so the conditions that it might getting populated should be between these two: 

```
		else if((key[i] & 1) == 0)	
		{
			local_58[i] = key[i] + num * '\x02';  ----> 
		}
		else
		{
			local_58[i] = key[i] + num * -2;   ---> result will always be odd ( as odd-even = odd) 
		}
	}
```

However, the resulting answer is an even number 124 and if we do some math, if we wanted to find the value of key in index 11, we have two cases: 

***When the key\[11\] value is even then: ***
- local_58\[11\] = key\[11\] + val1 * '\x02'; 
***When the key\[11\] is not even, nor i is even as i here is 11:***
- local_58\[11\] = key\[11\] + val1 * -2;

In the second case key\[11\] is odd, but we know when we will will simplify: 
```local_58[11] = key[11] + num * -2;```  it will become  ```local_58[11] = num[11] - 2*(val1);``` which is a condition **odd - even = odd** , so the local_58\[11\] comes odd in this case, but we already know that local_58\[11\] value should be even "124" to reach to "Access granted" condition, so this condition will also not give us which character should be in key\[11\]

In case when key\[11\] is even in the "else if(((key\[11\] & 1) == 0))" condition of above loop in this the value of local_58\[11\] will get populated when program would run,  in this case we can get the key when we simplify: ```local_58[11] = key[11] + num * '\x02';```  to:
```key[11] = local_58[11] - num * '\0x2' ``` 
```key[11] = 124 - num * '\0x2'```

Now we already know that "num" value could be greater than 0 and less than or equal to 50, so for every value of number user passes let's get the character that should present in our key at index 11, to make this program reach to "Access granted!!!" condition. By doing it we would have all possible solution for this challenge. 

```
#include<stdio.h>

int main()
{
	char value;
	int num = 0;
	char *key = "AAAAAAAAAAA";
	for (num=0 ; num<= 50; num++)
	{
		value = 124 - (num * '\x02');
		printf("key : %s%c , number : %d\n", key, value, num);
	    
	}

} 

```

If we would run the solution and take the value of key and number and use it in the challenge it can be observed that we have solved the challenge. 

Observe that all possible keys and numbers are generated
![crackme-006](/assets/img/Challenges/baby-first-crackme/img-6.png)

Observed that "Access granted!!!" is received, keys and numbers combination is correct
![crackme-007](/assets/img/Challenges/baby-first-crackme/img-7.png)


**Note:** In the decompiled version of the code from "ghidra" at the end after the loop it says: 
```*(undefined *)(param_3 + (int)local_c) = 0;```  // it seems it is adding 0 value where null was present, so when in the "check_key", function strlen(local_58) would be done it might give any random value till it encounters null character, however this is not the case, as "local_58" is character array the 0 value would automatically would be type-casted to its respective ASCII value in character which is null character. 


It was fun solving the challenge!!. I hope you enjoyed as well follow for more challenges.

