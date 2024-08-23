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
@inproceedings {ishtiaq2023hermes,
author = {Abdullah Al Ishtiaq and Sarkar Snigdha Sarathi Das and Syed Md Mukit Rashid and Ali Ranjbar and Kai Tu and Tianwei Wu and Zhezheng Song and Weixuan Wang and Mujtahid Akon and Rui Zhang and Syed Rafiul Hussain},
title = {Hermes: Unlocking Security Analysis of Cellular Network Protocols by Synthesizing Finite State Machines from Natural Language Specifications},
booktitle = {33rd USENIX Security Symposium (USENIX Security 24)},
year = {2024},
isbn = {978-1-939133-44-1},
address = {Philadelphia, PA},
pages = {4445--4462},
url = {https://www.usenix.org/conference/usenixsecurity24/presentation/al-ishtiaq},
publisher = {USENIX Association},
month = aug
}
```



