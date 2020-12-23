from django.shortcuts import render
import sys, os, datetime, optparse, collections 
import pefile
import struct
import datetime
from django.views.decorators.csrf import csrf_exempt



def home(request):
    return render(request,'home.html')

@csrf_exempt
def result(request):
    path = request.POST.get("path")
    pe = pefile.PE(path)  
    a =[5]
    i=0
    print("Name".ljust(20), "Virtual Address".ljust(20), "SizeOfRawData".ljust(20),
        "PointerToRawData".ljust(20), "Characteristics".ljust(20))
    for section in pe.sections :     
        inform = [section.Name.decode('utf8').ljust(20), hex(section.VirtualAddress).ljust(20),hex(section.SizeOfRawData).ljust(20), hex(section.PointerToRawData).ljust(20), hex(section.Characteristics)]
        a.insert(i,inform)
        i+=1
            
    print(a)       
    print("-" * 30,"\n") 
    
    return render(request,'result.html',{'path' : path , 'lists' : a , 'inform' : inform})

