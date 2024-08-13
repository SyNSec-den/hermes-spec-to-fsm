# Keyword Extraction

The folder shows keyword extraction for 5G RRC Release 17. It can be adapted for other specification documents.


## Required packages

```bash
pip3 install stanza transformers nltk
pip3 install PyEnchant
pip3 install PyPDF2
pip3 install tabula-py

python3 -m nltk.downloader all-nltk
```


## How to generate files in `assets` folder:

```bash
# substitute '. ' and '; ' with '.\n' and ';\n'
cat assets/5g-rrc.txt | sed 's/\. /\.\n/g' | sed 's/; /;\n/g' > assets/5g-rrc_small_lines.txt
python3 constituency_parser.py -f assets/5g-rrc_small_lines.txt --label NP > assets/5g-rrc_small_lines.np.txt
cat assets/5g-rrc_small_lines.np.txt | awk '{print tolower($0)}' | sort | uniq -c | sort -nr > assets/5g-rrc_small_lines.np.count.0.txt
cat assets/5g-rrc_small_lines.np.txt | awk '{print tolower($0)}' | sed 's/^the \|^a \|^an //' | sed '/[],:;\(\){}[]/d' | grep -Evw '(and|or|but)' | sort | uniq -c | sort -nr > assets/5g-rrc_small_lines.np.count.1.txt
cat assets/5g-rrc_small_lines.np.txt | awk '{print tolower($0)}' | sed 's/^the \|^a \|^an //' | sed '/[],:;\(\){}[]/d' | grep -Evw '(and|or|but)' > temp
cat temp | grep 's$' | sed 's/.$//' | sort -u | grep -xFf temp | sed -e 's/$/s/' > temp.remove
cat temp | grep -vxFf temp.remove > out.1
cat temp | grep -xFf temp.remove | sed 's/.$//' > out.2
cat out.1 out.2 | sort | uniq -c | sort -nr > assets/5g-rrc_small_lines.np.count.2.txt
rm temp temp.remove out.1 out.2
```


## Update the following files manually

- `assets/abbreviations.txt`
- `assets/definitions.txt`
- `assets/cause.txt`
- `assets/manual_recategorization.txt`
- `gather_keyword_pdf.py: gather_messages_and_procedures, gather_state, gather_vars`
- `ie_from_pdf.py: get_IE_toc`


## Run the following commands

```bash
python3 noun_phrase_cleanup.py
python3 merge_keywords_np.py
python3 create_combined_dictionary.py
python3 post_refinement_combined_keywords.py
```

Output: `combined.json`


## Note

The output of automated keyword extraction and categorization may still contain some uncategorized keywords. 
In Hermes, we manually check and categorize them.


