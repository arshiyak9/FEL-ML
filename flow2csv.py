import binascii
from csv import writer
import subprocess as sp
import os, json
import numpy as np
import pandas as pd

#from pcap_splitter.splitter import PcapSplitter
#
#ps = PcapSplitter("network_traffic.pcap")
#print(ps.split_by_session("dest_pcaps_folder"))
#

def colFill(fileName):
    df=pd.read_csv(fileName)
    lcol=len(df.columns)
    if df.columns[0]=='Label':
        print("with label")
        cols=['Label', 'Type', 'f_0']
        for i in range(1, lcol-2):
            cols.append('f_' +str(i))
    else:
        print("without label")
        cols=['Label', 'Type', 'f_0']
        #df['Label']= 'Malicious'
        #df['Type']= type
        for i in range(1, lcol):
            cols.append('f_' +str(i))
    df.columns=cols
    df.to_csv(fileName)

colFill("zeroAll_malicious_1-1.csv")

#i=1
#for each in df.columns:
#    if each.find('Unnamed') != -1:
#        df.rename(columns={each: 'f_'+str(i)}, inplace=True)
#        i=i+1
df=pd.read_csv("pcap_benign_7-1.csv")
df.columns
lcol=len(df.columns)
cols=['Label', 'Type', 'f_0']
for i in range(1, lcol-2):
    cols.append('f_' +str(i))

df.columns=cols
df.to_csv("pcap_benign_7-1.csv")

df1 = pd.read_csv("remip_malicious_1-1.csv")
df2 = pd.read_csv("remip_malicious_3-1.csv")
df3 = pd.read_csv("remip_malicious_9-1.csv")
df4 = pd.read_csv("remip_malicious_36-1.csv")
df5 = pd.read_csv("remip_malicious_49-1.csv")


df1 = pd.read_csv("showAll_benign_4-1.csv")
df2 = pd.read_csv("showAll_benign_5-1.csv")
df3 = pd.read_csv("showAll_benign_7-1.csv")

df1 = pd.read_csv("remip_benign_training.csv")
df2 = pd.read_csv("remip_malicious_training.csv")

ds=[df1.shape[1], df2.shape[1], df3.shape[1], df4.shape[1], df5.shape[1]]

df1.shape
df2.shape
df3.shape
df4.shape
df5.shape

df4=df4.iloc[0:16000,:]

for each in ds:
    print("before: ")
    each.shape
    each=each.iloc[:,0:ncol]
    print("after: ")
    each.shape

nrow=min(df1.shape[0], df2.shape[0], df3.shape[0], df6.shape[0], df5.shape[0])
ncol=min(df1.shape[1], df2.shape[1], df3.shape[1], df6.shape[1], df5.shape[1])

df1=df1.iloc[0:nrow,0:ncol]
df2=df2.iloc[0:nrow,0:ncol]
df3=df3.iloc[0:nrow,0:ncol]
df4=df4.iloc[0:nrow,0:ncol]
df5=df5.iloc[0:nrow,0:ncol]

df1['Label']='Benign'
df1['Type']= 'Phillips Hue'
df2['Label']='Benign'
df2['Type']= 'Echo'
df3['Label']='Benign'
df3['Type']= 'Doorlock'

df1=df1.drop(columns=['Unnamed: 0'])
df2=df2.drop(columns=['Unnamed: 0'])
df3=df3.drop(columns=['Unnamed: 0'])
df4=df4.drop(columns=['Unnamed: 0'])
df5=df5.drop(columns=['Unnamed: 0'])
dfa=pd.concat([df1,df2,df3,df6,df5], ignore_index=True, axis=0, sort=False)
dfa.to_csv("showAll_pcap_training.csv")

for i in range(34):
    dfb=dfb.drop(columns=['f_'+str(i)])
############

def get_tshark_hexstreams(capture_path: str) -> list:
    """Get the frames in a capture as a list of hex strings."""
    cmds = ["tshark", "-x", "-r", capture_path, "-c", "14000", "-T", "json"]
    frames_text = sp.check_output(cmds, text=True)
    frames_json = json.loads(frames_text)
    hexstreams = [frame["_source"]["layers"]["frame_raw"][0] for frame in frames_json]
    return hexstreams

def append_list_as_row(file_name, list_of_elem):
    # Open file in append mode
    with open(file_name, 'a+', newline='') as write_obj:
        # Create a writer object from csv module
        csv_writer = writer(write_obj)
        # Add contents of list as last row in the csv file
        csv_writer.writerow(list_of_elem)

def showAllHeaders(file):
#all headers are included in this function
    raw_row=[]
    output = get_tshark_hexstreams(file)
    for each in output:
        encoded_str=str.encode(each)
#        r=np.random.randint(0, 255, size=(20))
        for i in range(len(encoded_str)):
            raw_row.append(encoded_str[i])
    append_list_as_row("showAll_ben1.csv", raw_row)

def remEthHeader(file):
#remove ethernet headers only from each pcap
    raw_row=[]
    output = get_tshark_hexstreams(file)
    for each in output:
        encoded_str=str.encode(each)
#            r=np.random.randint(0, 255, size=(20))
        for i in range(14,len(encoded_str)):
#                print(i)
            raw_row.append(encoded_str[i])
    append_list_as_row("remeth_ben.csv", raw_row)

def zeroEthHeader(file):
#replace ethernet headers with zero from each pcap
    raw_row=[]
    output = get_tshark_hexstreams(file)
    for each in output:
        encoded_str=str.encode(each)
#            r=np.random.randint(0, 255, size=(20))
        for i in range(14):
#                print(i)
            raw_row.append(0)
#            print(",\n")
        for i in range(14,len(encoded_str)):
#                print(i)
            raw_row.append(encoded_str[i])
    append_list_as_row("zeroeth_ben.csv", raw_row)

def remIpHeader(file):
#remove IP headers only from each pcap
    raw_row=[]
    output = get_tshark_hexstreams(file)
    for each in output:
        encoded_str=str.encode(each)
#            r=np.random.randint(0, 255, size=(20))
        for i in range(14):
#                print(i)
            raw_row.append(encoded_str[i])
#            print(",\n")
        for i in range(34,len(encoded_str)):
#                print(i)
            raw_row.append(encoded_str[i])
    append_list_as_row("remip_ben.csv", raw_row)

def zeroIpHeader(file):
#replace IP headers with zero from each pcap
    raw_row=[]
    output = get_tshark_hexstreams(file)
    for each in output:
        encoded_str=str.encode(each)
#            r=np.random.randint(0, 255, size=(20))
        for i in range(14):
#                print(i)
            raw_row.append(encoded_str[i])
#            print(",\n")
        for i in range(20):
#               print(r[i])
            raw_row.append(0)
#            print(",\n")
        for i in range(34,len(encoded_str)):
#                print(i)
            raw_row.append(encoded_str[i])
    append_list_as_row("zeroip_ben.csv", raw_row)

def remAllHeaders(file):
#remove all(ethernet + IP) headers only from each pcap
    raw_row=[]
    output = get_tshark_hexstreams(file)
    for each in output:
        encoded_str=str.encode(each)
#            r=np.random.randint(0, 255, size=(20))
        for i in range(34,len(encoded_str)):
#                print(i)
            raw_row.append(encoded_str[i])
    append_list_as_row("remAll_ben.csv", raw_row)

def zeroAllHeaders(file):
#replace all(ethernet + IP) headers with zero from each pcap
    raw_row=[]
    output = get_tshark_hexstreams(file)
    for each in output:
        encoded_str=str.encode(each)
        for i in range(34):
#               print(r[i])
            raw_row.append(0)
#            print(",\n")
        for i in range(34,len(encoded_str)):
#                print(i)
            raw_row.append(encoded_str[i])
    append_list_as_row("zeroAll_ben.csv", raw_row)

def recordPcap(file):
#pcap representations are recorded in this function
    output = get_tshark_hexstreams(file)
    for each in output:
        raw_row=[]
        encoded_str=str.encode(each)
        for i in range(len(encoded_str)):
            raw_row.append(encoded_str[i])
        print(",")
        append_list_as_row("showAll_ben1_pcap.csv", raw_row)

for i in range(42):
    recordPcap(pcaplist[i])


if __name__=="__main__":
    thisdir=os.getcwd()
    pcaplist = [f for f in os.listdir(thisdir) if f.endswith('.pcap')]
    
if len(pcaplist)<=16000:
    for apcap in pcaplist:
        showAllHeaders(apcap)
else:
    for apcap in pcaplist[0:16000]:
#        all headers are included
        showAllHeaders(apcap)
#
#        all headers are replaced by 0
#        zeroAllHeaders(apcap)
#        all headers are removed (NO headers are included)
#        remAllHeaders(apcap)
#
#        ethernet headers are replaced by 0
#        zeroEthHeader(apcap)
#        ethernet headers are removed
#        remEthHeader(apcap)
#
#        ip headers are replaced by 0
#        zeroIpHeader(apcap)
#        ip headers are removed
#        remIpHeader(apcap)
#
#    pcap representation
    recordPcap(pcaplist[0])
#    all headers are included
for apcap in pcaplist:
    showAllHeaders(apcap)
for apcap in pcaplist:
#        all headers are replaced by 0
    zeroAllHeaders(apcap)
for apcap in pcaplist:
#        all headers are removed (NO headers are included)
    remAllHeaders(apcap)
#        ethernet headers are replaced by 0
for apcap in pcaplist:
    zeroEthHeader(apcap)
#        ethernet headers are removed
    remEthHeader(apcap)
#        ip headers are replaced by 0
    zeroIpHeader(apcap)
#        ip headers are removed
    remIpHeader(apcap)

thisdir=os.getcwd()
csvlist = [f for f in os.listdir(thisdir) if f.endswith('.csv')]
for f in csvlist:
    df=pd.read_csv(f)
    print("without label")
    lcol=len(df.columns)
    cols=[]
    for i in range(lcol):
        cols.append('f_' +str(i))
    df.columns=cols
    df2['Label']= 'Malicious'
    df2['Type']= 'SNOOPY'
    df.to_csv(f)


thisdir=os.getcwd()
flist = [f for f in os.listdir(thisdir) if f.startswith('showAll')]
flist

df1 = pd.read_csv(flist[0])
df2 = pd.read_csv(flist[1])
df3 = pd.read_csv(flist[2])
df4 = pd.read_csv(flist[3])
df5 = pd.read_csv(flist[4])
df6 = pd.read_csv(flist[5])

df1.columns
df2.columns
df3.columns
df4.columns
df5.columns
lcol=len(df6.columns)
cols=['Label', 'Type', 'f_0']
for i in range(1, lcol-2):
    cols.append('f_' +str(i))

df6.columns=cols
df6.columns

df6['Type'].value_counts()

df4['Label']= 'Benign'
df4['Type']= 'Benign'

for i in range(34):
    d1['f_'+str(i)]=0
 
for i in range(14, 2400):
    cols.append('f_' +str(i))

for i in range(lcol):
    cols.append('f_' +str(i))
