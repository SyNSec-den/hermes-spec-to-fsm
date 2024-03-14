# NEUTREX

## Setup

Download the following files to `neutrex` folder:  
- model_4g_nas: https://drive.google.com/file/d/11-4ujqtQAwDf8p_7j_leG_hECiAaxw2t/view?usp=sharing
- model_5g_nas: https://drive.google.com/file/d/1xHqhadH3mgjK9v_0eV7MWSRQAx6ZycJE/view?usp=sharing

Download and unzip the following file to `neutrex` folder:  
- saved_model.zip: https://drive.google.com/file/d/1R3A5zfM9z6aQzILrfh7aPkSzlQebu5iX/view?usp=sharing

Download the following file to `neutrex/data` folder:  
- glove.6B.100d.txt: https://drive.google.com/file/d/1qot1XbmuN6R7bwDmT7CwSZBV1Sh1X1VD/view?usp=sharing

### Requirements

- python=3.7
- dill==0.3.6
- nltk==3.8.1
- stanza==1.5.0
- tokenizers==0.13.3
- torch==1.13.1
- transformers==4.30.1

## Preprocess

Preprocess text document with `neutrex/xml_to_tree/conversion.py`. 
It takes inputs from a `input.txt` file and 
will generate `out_full.pid` file with preprocessed trees to be given as input to NEUTREX.  


## Commands

train: 
```sh
python3 -u -m supar.cmds.crf_con train -b -d 0 -c crf-con-roberta-en -p model_4g_nas \
    --train data/4g-nas.pid \
    --dev data/5g-nas.pid \
    --test data/5g-nas.pid \
    --encoder=bert \
    --bert=saved_model/ \
    --lr=5e-5 \
    --lr-rate=20 \
    --epochs=200 \
    --update-steps=4 
```

predict:
```sh
python3 -u -m supar.cmds.crf_con predict -d 0 -c crf-con-roberta-en -p model_4g_nas \
    --data data/5g-nas.pid \
    --pred pred_out.pid \
    --encoder=bert \
    --bert=saved_model/
```

evaluate:
```sh
python3 -u -m supar.cmds.crf_con evaluate -d 0 -c crf-con-roberta-en -p model_4g_nas \
    --data data/5g-nas.pid \
    --encoder=bert \
    --bert=saved_model/
```

## Tree to XML

The output trees from NEUTREX can be translated to XML formats with `neutrex/tree_to_xml/tree_to_xml.py`. 
It takes inputs from a `input.pid` file and will generate outputs to `output.txt`.  

## Acknowledgement

We acknowledge [SuPar](https://github.com/yzhangcs/parser) as the baseline implementation of NEUTREX. 