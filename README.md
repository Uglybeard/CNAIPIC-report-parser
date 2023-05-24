# CNAIPIC IoC Report Parser

### ENGLISH:

**WARNING**
Once the reports have been parsed, the script deletes all \*.zip, \*.misp-json and *.csv-ids files within the working directory.

**Script's purpose:**

- Unzip all *.zip files with the password specified in the code
- Parse the report to summarize all IoCs (MD5, SHA256, SHA1,...)
- Create a file containing the summary of the IoCs excluding the Indicators contained in whitelist (Whitelist/*.txt files)
- Delete useless files (\*.zip, \*.misp-json, well formed *.csv-ids)
- Do a Backup of all the Hashes/Domains contained in the file for malware analysis/threat hunting purpose

**Requirements:**

- Create a directory named "Backup_IoC" in the same directory as the script (Do this only the first time).
- Create a directory named "Whitelist" in the same directory as the script (Do this only the first time).
	- OPTIONAL: insert one or more *.txt file in the Whitelist directory to filter the IoCs

**How to use the script (CMD):**

1. Move the *.zip files you want to parse to the same directory as the script.
2. Move to the directory that contains the script and the zip files
3. Run the following command: ``python3 CNAIPIC_Parser.py``

**How to use the script (IDE):**

1. Move the \*.zip files you want to parse to the same directory as the script.
2. Open the script.
3. If necessary, choose the folder to open from the IDE, for example:
   - On Visual Studio press Ctrl + Shift + E to open the Explorer and, after clicking the button "Open Folder", choose the folder containing the script and the *.zip reports
4. Run the script

**Script Output:**

- "IoC_Summary.txt" contains the summary of the IoCs contained in the reports
- Problematic (not well formed, missing IoCs) \*.csv-ids files unzipped from the *.zip files
- Backup files contained in the /Backup_IoC directory

**Warnings:**

- _[ID:1]_ "The file contains also the following IoCs" means that the script wasn't able to parse some IoCs.
      The files containing the unparsable IoCs will be listed under the warning.
      If you get this warning please contact me to update the script and add the unparsable IoCs to the script.
- _[ID:2]_ "The following files weren't well formed so they couldn't be fully parsed" means that the scirpt wan't able to parse a partition of a CSV file.
      The not well formed files and the not well formed lines will be listed under the warning.
      You can manually analyze the not well formed lines and then remove them to resolve this problem.

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

### ITALIANO:

**AVVERTENZA**
Una volta analizzati i rapporti, lo script elimina tutti i file \*.zip, \*.misp-json, *.csv-ids presenti nella cartella corrente.

**Scopo dello script:**

- Unzippare tutti i file *.zip con la password specificata nel codice
- Analizzare il report per riassumere tutti gli IoC (MD5, SHA256, SHA1,...)
- Creare un file contenente il riepilogo degli IoC escludendo gli indicatori contenuti nella whitelist (file Whitelit/*.txt)
- Eliminare i file inutili (\*.zip, \*.misp-json, *csv-ids ben formati)
- Fare un backup degli hash/domini contenuti nei file per scopi di Malware Analysis/Threat Hunting

**Requisiti:**

- Creare una cartella chiamata "Backup_IoC" nella stessa directory dello script (da fare solamente la prima volta).
- Creare una cartella chiamata "Whitelist" nella stessa directory dello script (da fare solamente la prima volta).
  - FACOLTATIVO: inserire uno o più file *.txt nella directory Whitelist per filtrare gli IoC.

**Come utilizzare lo script (CMD):**

1. Spostare i file *.zip che si desidera analizzare nella stessa cartella dello script.
2. Spostarsi nella cartella che contiene lo script ed i file zip
3. Eseguire il seguente comando: ``python3 CNAIPIC_Parser.py``

**Come utilizzare lo script (IDE):**

1. Spostare i file *.zip che si desidera analizzare nella stessa directory dello script.
2. Aprire lo script.
3. Se necessario, scegliere la cartella da aprire dall'IDE, ad esempio:
   - In Visual Studio premere Ctrl + Shift + E per aprire l'Explorer e, dopo aver fatto clic sul pulsante "Apri cartella", scegliere la cartella contenente lo script e i rapporti *.zip.
4. Eseguire lo script.

**Output dello script:**

- "IoC_Summary.txt" contiene il riepilogo degli IoC contenuti nei report
- File \*.csv-ids problematici (non ben formati, IoC mancanti) decompressi dai file *.zip
- File di backup contenuti nella cartella /Backup_IoC

**Avvertenze:**

- _[ID:1]_ "The file contains also the following IoCs" significa che lo script non è stato in grado di analizzare alcuni IoC.
      I file contenenti gli IoC non parsabili saranno elencati sotto l'avviso.
      Se si riceve questo avviso, contattatemi per aggiornare lo script e aggiungere gli IoC non parsabili allo script.
- _[ID:2]_ "The following files weren't well formed so they couldn't be fully parsed" significa che lo script non è in grado di analizzare una parte di un file CSV.
      I file non ben formati e le righe non ben formate saranno elencati sotto l'avviso.
      È possibile analizzare manualmente le righe non ben formate e rimuoverle per risolvere il problema.
