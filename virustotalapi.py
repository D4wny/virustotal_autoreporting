#-*- coding: utf-8 -*-
import requests
import json
import os
from time import sleep


def scan(file_name, path, api_key):
	url = 'https://www.virustotal.com/vtapi/v2/file/scan'
	params = {'apikey': api_key}
	files = {'file': (file_name, open(path, 'rb'))}
	response = requests.post(url, files=files, params=params)
	data = response.json()
	sending = data["response_code"]
	if(str(sending) == "1"):
		print("upload complete ..")
		return(1)	

def report(name, api_key, log_path):
	try : 
		url = 'https://www.virustotal.com/vtapi/v2/file/report'
		params = {'apikey': api_key, 'resource': name}
		response = requests.get(url, params=params)
		data = response.json()
		report_chk = data["response_code"]
		if(str(report_chk == "1")):
			detect = data["positives"]
			resource = data["resource"]
			log = "file_name : " + str(resource) + " detect : " + str(detect) + "\n"
			f = open(log_path , 'a')
			f.write(log)
			print("logging and reporting complete ...")
			return(1)
		else:
			print("fail")
			return(0)
	except:
		print("fail")
		return(0)

def file_list(path):
	fl = os.listdir(path)
	return(fl)
	#for each_list in fl:
		

if __name__ == "__main__":
	api_key = ''
	ransom_path = '/home/dawn/Desktop/samples-training-set/'
	lansom_path = '/home/dawn/Desktop/samples-training-set/'
	log_file = '/home/dawn/Desktop/source/detect_list'
	#scan(lansom_path , api_key)
	#report(resource, api_key, log_file)
	#file_list('/home/dawn/Desktop/samples-testset/')
	fl = file_list(lansom_path)
	for each_list in fl:
		lansome_file_path = lansom_path + str(each_list)
		scan_chk = scan(lansome_file_path, api_key)
		if (scan_chk == 1):
			sleep(20)
			report_chk = report(str(each_list), api_key, log_file)
			while(report_chk == 0):
				report_chk = report(str(each_list), api_key, log_file)
				sleep(10)
		
