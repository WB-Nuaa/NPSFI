# How Bit Flips Disrupt Networking: Revealing Vulnerability in the Linux Kernel Network Protocol Stack (NPSFI)

## Overview
Each folder is a function and contains the error information, instruction information, and logs.
The most important files in each folder are as follows:
- error.log: the error information after each bit of each instruction in the function is flipped.
- received_data.log: the packet received by the client.
- result: contains detailed error information.
- addr_instruction.json: the information and addresses of each instruction in the function.
- analyse.py or analyse-origin.py: a program for analyzing functions.
  
## Setup

To run the code, you need the following dependencies:
- [numpy 1.18.5](https://numpy.org/)
- 

It is noteworthy that we have modified the HGTConv source code to return the attention coefficient
  
## DataSet
Our current experiments are conducted on data obtained by LLVM and LLFI.
- `Ins_g.dot` : The text and structure information of instructions.
- `F_B_I.dot` : The position number of the instruction in the program.
- `cycle_result.txt, result_other.txt` : The result of fault injection.

## Usage
Execute the following scripts to train on node classification task:

```bash
python main.py
```
