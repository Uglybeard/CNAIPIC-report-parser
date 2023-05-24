import csv
import glob
import os
from zipfile import ZipFile;
from urllib.parse import urlparse;

ZIP_PASSWORD=b"<YOUR_PASSWORD>" #Replace <YOUR_PASSWORD> with the *.zip(s) actual password

#Compares the IoC to the whitelist and, if it's not whitelisted, adds it to the IoC array (i.e. url=[])
def append_array(elem,array):
  if(elem not in array and elem not in whitelist):
    array.append(elem)

#Checks whether the list is not empty and, if so, writes its contents to the IoC file.
def write_fun(text,list):
  if len(list):
      f.write(text)
      f.write("\n".join(list))
      f.write("\n\n")

#Checks wether the list is not empty and, if so, replaces special characters and writes its contents into the IoC file.
def write_fun_and_replace(text,list):
  if len(list):
      for i,s in enumerate(list):
        list[i]=list[i].replace('|','\n') 
      f.write(text)
      f.write("\n".join(list))
      f.write("\n\n")

#Checks whether the list is not empty and, if so, writes its contents to the Backup file.
def write_backup(list):
  if len(list)>0:
      f.write("\n".join(list))
      f.write("\n")

#Removes duplicates from files
def remove_duplicates(file):
  lines_seen = set()
  with open(file, "r+") as f:
    d = f.readlines()
    f.seek(0)
    for i in d:
      if i not in lines_seen:
        f.write(i)
        if i!="\n": lines_seen.add(i)
    f.truncate()

#Extracts the contents of all .zip files in the current directory using the password provided 
filename=glob.glob('*.zip')
for a in filename:
  with ZipFile(a) as zf:
    zf.extractall(pwd=ZIP_PASSWORD)

#Add .csv-ids and whitelist (.txt) file names to file arrays.
filename=glob.glob('*.csv-ids')
whitelistfilename=glob.glob('Whitelist/*.txt')

#Definition of variables
line_count=0
url=[]
md5=[]
sha256=[]
sha1=[]
mal=[]
warning=[]
domain=[]
ip_dst=[]
ip_src=[]
url_parsed=[]
hostname=[]
emailsrc=[]
ip_dst_port=[]
email_dst=[]
domain_ip=[]
filename_sha1=[]
exceptions=[]
file=[]
filename_md5=[]
filename_sha256=[]
problematic_files=[]
whitelist=[]

#Reads the contents of the whitelist files and adds them to the whitelist array.
for a in whitelistfilename:
  with open(a) as txt_file:
    lines=txt_file.readlines()
    for elem in lines:
      elem=elem.replace("\n","")
      append_array(elem,whitelist)

#Reads the contents of the .csv-ids files and interprets them as csv files, using "," as a delimiter
for a in filename:
  with open(a) as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    row=""

    #Adds IoCs contained in rows to IoCs arrays, based on their type
    try:
      for row in csv_reader:
        if line_count == 0: line_count+=1
        else:
          if row[3]=="sha256": append_array(row[4],sha256)
          elif row[3]=="malware-sample": append_array(row[4],mal)
          elif row[3]=="md5": append_array(row[4],md5)
          elif row[3]=="sha1": append_array(row[4],sha1)    
          elif row[3]=="domain": append_array(row[4],domain)
          elif row[3]=="ip-dst": append_array(row[4],ip_dst)
          elif row[3]=="ip-src": append_array(row[4],ip_src)
          elif row[3]=="hostname": append_array(row[4],hostname)
          elif row[3]=="email-src": append_array(row[4],emailsrc)
          elif row[3]=="ip-dst|port": append_array(row[4],ip_dst_port)
          elif row[3]=="domain|ip": append_array(row[4],domain_ip)
          elif row[3]=="email-dst": append_array(row[4],email_dst)
          elif row[3]=="filename|sha1": append_array(row[4],filename_sha1)
          elif row[3]=="filename": append_array(row[4],file)
          elif row[3]=="filename|md5": append_array(row[4],filename_md5)
          elif row[3]=="filename|sha256": append_array(row[4],filename_sha256)

          #Adds the URL to the IoC array url=[] and parses it by extracting the domain, adding the result to url_parsed=[]
          elif row[3]=="url":
              if(row[4] not in url):
                url.append(row[4])
                temp=urlparse(row[4]).netloc
                if(temp not in url_parsed and temp not in whitelist):
                  url_parsed.append(temp)
          
          #If the IoC type is not known, it is added to the warning list and the file is flagged as problematic
          elif row[3] not in warning and row[3]!="type":
              warning.append("FILE: " + a + "\nProblem in parsing the following IoC:\n" + row[3] + "\n")
              problematic_files.append(a)

    #Captures exceptions, saving the lines that caused them and flagging files containing them as problematic          
    except Exception as e:
      if(row!=""):
        exceptions.append("FILE: " + a + "\nProblem in parsing after the following line:\n" + ",".join(row) + "\n")
        problematic_files.append(a)
      else:
        exceptions.append("FILE: " + a + "\nProblem in parsing the first row of the file\n")
        problematic_files.append(a)

  #Call functions
  with open("IoC_Summary.txt", "w") as f:
    write_fun(">>>WARNING(ID:1): The file contains also the following IoCs\n\n",warning)
    write_fun(">>>WARNING(ID:2): The following files weren't well formed so they couldn't be fully parsed\n\n",exceptions)
    write_fun("MD5:\n",md5)
    write_fun("SHA256:\n",sha256)
    write_fun("SHA1:\n",sha1)
    write_fun("URL:\n",url)
    write_fun("URL PARSED: !!DO A DOUBLE CHECK IF THE URL IS PARSED WELL!!\n",url_parsed)
    write_fun("IP-DST:\n",ip_dst)
    write_fun("IP-SRC:\n",ip_src)
    write_fun("Domain:\n",domain)
    write_fun("Hostname:\n",hostname)
    write_fun("Email Source:\n",emailsrc)
    write_fun("Email Destination:\n",email_dst)
    write_fun("Filename:\n",file)
    write_fun_and_replace("Malware Samples:\n",mal)
    write_fun_and_replace("Domain | Ip:\n",domain_ip)
    write_fun_and_replace("IP DST | Port:\n",ip_dst_port)
    write_fun_and_replace("Filename | SHA1:\n",filename_sha1)
    write_fun_and_replace("Filename | MD5:\n",filename_md5)
    write_fun_and_replace("Filename | SHA256:\n",filename_sha256)
    
  with open("Backup_IoC/md5.txt", "a") as f: write_backup(md5)
  with open("Backup_IoC/sha256.txt", "a") as f: write_backup(sha256)
  with open("Backup_IoC/sha1.txt", "a") as f: write_backup(sha1)
  with open("Backup_IoC/url_parsed.txt", "a") as f: write_backup(url_parsed)
  with open("Backup_IoC/url.txt", "a") as f: write_backup(url)
  with open("Backup_IoC/ip_dst.txt", "a") as f: write_backup(ip_dst)
  with open("Backup_IoC/ip_src.txt", "a") as f: write_backup(ip_src)
  with open("Backup_IoC/hostname.txt", "a") as f: write_backup(hostname)
  with open("Backup_IoC/emailsrc.txt", "a") as f: write_backup(emailsrc)
  with open("Backup_IoC/ip_dst_port.txt", "a") as f: write_backup(ip_dst_port)
  with open("Backup_IoC/email_dst.txt", "a") as f: write_backup(email_dst)
  with open("Backup_IoC/domain_ip.txt", "a") as f: write_backup(domain_ip)
  with open("Backup_IoC/domain.txt", "a") as f: write_backup(domain)
  with open("Backup_IoC/filename_sha1.txt", "a") as f: write_backup(filename_sha1)
  with open("Backup_IoC/malware_samples.txt", "a") as f: write_backup(mal)
  with open("Backup_IoC/filename.txt", "a") as f: write_backup(file)
  with open("Backup_IoC/filename_md5.txt", "a") as f: write_backup(filename_md5)
  with open("Backup_IoC/filename_sha256.txt", "a") as f: write_backup(filename_sha256)

  remove_duplicates("Backup_IoC/md5.txt")
  remove_duplicates("Backup_IoC/sha256.txt")
  remove_duplicates("Backup_IoC/sha1.txt")
  remove_duplicates("Backup_IoC/url_parsed.txt")
  remove_duplicates("Backup_IoC/url.txt")
  remove_duplicates("Backup_IoC/ip_dst.txt")
  remove_duplicates("Backup_IoC/ip_src.txt")
  remove_duplicates("Backup_IoC/hostname.txt")
  remove_duplicates("Backup_IoC/emailsrc.txt")
  remove_duplicates("Backup_IoC/ip_dst_port.txt")
  remove_duplicates("Backup_IoC/email_dst.txt")
  remove_duplicates("Backup_IoC/domain_ip.txt")
  remove_duplicates("Backup_IoC/domain.txt")
  remove_duplicates("Backup_IoC/malware_samples.txt")
  remove_duplicates("Backup_IoC/md5.txt")
  remove_duplicates("Backup_IoC/filename_sha1.txt")
  remove_duplicates("Backup_IoC/filename.txt")
  remove_duplicates("Backup_IoC/filename_md5.txt")
  remove_duplicates("Backup_IoC/filename_sha256.txt")
  remove_duplicates("IoC_Summary.txt")

#Removes all .zip, .misp-json, and cvs-ids files not flagged as problematic from the current directory.
filename=glob.glob('*.zip')
for a in filename:
  os.remove(a)

filename=glob.glob('*.misp-json')
for a in filename:
  os.remove(a)

filename=glob.glob('*.csv-ids')
for a in filename:
  if a not in problematic_files:
    os.remove(a)

    
      
      
    
       
