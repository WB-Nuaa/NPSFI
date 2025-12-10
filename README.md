# How Bit Flips Disrupt Networking: Revealing Vulnerability in the Linux Kernel Network Protocol Stack (NPSFI)

## Overview
Each folder is a function and contains the error information, instruction information, and logs.
The most important files in each folder are as follows:
- error.log: the error information after each bit of each instruction in the function is flipped.
- received_data.log: the packet received by the client.
- main.py: Data division, model building, and training module.
  - `def train_model` : Building the graphs. Model building and training.
  - `G` : Semantic enhanced Graph of instrcution layer.
  - `BB_G` : Graph of basic block layer. 
  
## Setup

To run the code, you need the following dependencies:
- [Pytorch 1.10.2](https://pytorch.org/)
- [DGL 0.9.0](https://www.dgl.ai/pages/start.html)
- [sklearn](https://github.com/scikit-learn/scikit-learn)
- [numpy 1.18.5](https://numpy.org/)

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
