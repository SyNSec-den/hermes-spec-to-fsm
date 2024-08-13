# Hermes

This is the official repository of the paper titled "[Hermes: Unlocking Security Analysis of Cellular Network Protocols by Synthesizing Finite State Machines from Natural Language Specifications](https://www.usenix.org/conference/usenixsecurity24/presentation/al-ishtiaq)" (USENIX Security '24). 


## System 
- OS: Ubuntu 22.04.3 LTS
- GPU: NVIDIA RTX A6000
- CUDA Version: 12.2
- NVIDIA Driver version: 535.86.05


## Components

### Annotated data 

`data` contains the annotated data for 4G NAS, 5G NAS and 5G RRC specifications.


### NEUTREX

`neutrex` contains the implementation of NEUTREX. It also provides instructions to run it.  


### Keyword Extractor

`keyword_extraction` contains the implementation of Keyword Extractor from Hermes. 
It also contains the instructions on how to use the tool.  


### Synthesizers

`synthesizers` contains the implementation of IRSynthesizer and FSMSynthesizer.
It also provides instructions to use the tool.  


## Citation

```bibtex
@inproceedings{ishtiaq2023hermes,
  title={Hermes: Unlocking Security Analysis of Cellular Network Protocols by Synthesizing Finite State Machines from Natural Language Specifications},
  author={Ishtiaq, Abdullah Al and Das, Sarkar Snigdha Sarathi and Rashid, Syed Md Mukit and Ranjbar, Ali and Tu, Kai and Wu, Tianwei and Song, Zhezheng and Wang, Weixuan and Akon, Mujtahid Al-Islam and Zhang, Rui and Hussain, Syed Rafiul},
  booktitle={Proceedings of USENIX Security Symposium (USENIX Security)},
  year={2024}
}
```



