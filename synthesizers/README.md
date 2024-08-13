# IRSynthesizer and FSMSynthesizer

## Requirements

- python=3.7
- stanza==1.4.2
- nltk==3.8.1
- tokenizers==0.13.3
- torch==1.13.1
- sympy==1.10.1
- python-levenshtein==0.20.9


## Config

- Update `./script_config.py` to select appropriate configuration.


## Input

- Put input Hermes annotated document into `./input.txt`
- Put extracted keywords into `./defs-saved.json`


## CoreNLP Server

- Run `./CoreNLP_server.py` to start CoreNLP server and keep it running.


## Keyword Preprocess

- Run `./run-keyword-db-builder.py` to create database for keywords.


## Synthesizers

- Run `./run-synthesizers.py` to run IRSynthesizer and FSMSynthesizer.


## Output

- `./transitions.txt` outputs the transitions.
- `./ir-out.xml` outputs the FSM in IR format.
- `./smv-out.smv` FSM transpiled to nuXmv.



