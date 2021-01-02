# from django.shortcuts import render
# import sys, os, datetime, optparse, collections 
# import pefile
# import struct
# import datetime
# from django.views.decorators.csrf import csrf_exempt



# def home(request):
#     return render(request,'home.html')

# @csrf_exempt
# def result(request):
#     path = request.POST.get("path")
#     pe = pefile.PE(path)  
#     a =[5]
#     i=0
#     print("Name".ljust(20), "Virtual Address".ljust(20), "SizeOfRawData".ljust(20),
#         "PointerToRawData".ljust(20), "Characteristics".ljust(20))
#     for section in pe.sections :     
#         inform = [section.Name.decode('utf8').ljust(20), hex(section.VirtualAddress).ljust(20),hex(section.SizeOfRawData).ljust(20), hex(section.PointerToRawData).ljust(20), hex(section.Characteristics)]
#         a.insert(i,inform)
#         i+=1
            
#     print(a)       
#     print("-" * 30,"\n") 
    
#     return render(request,'result.html',{'path' : path , 'lists' : a , 'inform' : inform})

from django.shortcuts import render
import sys, os, datetime, optparse, collections 
import pefile
import struct
import datetime
from django.views.decorators.csrf import csrf_exempt
from myapp import IMAGE_DOS_HEADER 
from myapp import PEView


def home(request):
    return render(request,'home.html')



@csrf_exempt
def result(request):
    path = request.POST.get("path")
    pe = pefile.PE(path)  

    
    pFile_start = pe.DOS_HEADER.e_lfanew
    pFile = format(pFile_start, '#010x') #pFile 출력형식지정

    image_dos_header_list =  IMAGE_DOS_HEADER.image_dos_header_list

    f = open(path, 'rb')
    t = 0x0
    data = f.read()
    DosHeaderInfo = IMAGE_DOS_HEADER.DosHeader(t)
    DosHeaderInfo.print()
    NTHeaderAddressSt = struct.unpack('<HH', DosHeaderInfo.e_lfanew) #e_lfanew에 NTHeaderAddress의 주소가 있다
    NTHeaderAddress = IMAGE_DOS_HEADER.intTupletoInt(NTHeaderAddressSt) 
    DosStubInfo = IMAGE_DOS_HEADER.DosStub(DosHeaderInfo.getT(), NTHeaderAddress)
    
    DosStub_list = PEView.DosStub_list
    DosStubInfo.print()


    signature_header_list = []
    file_header_list = []
    optional_header_list = []

    print("-" *60)
    print('IMAGE_NT_HEADERS'.rjust(35))
    print("-" *60)


    signature_header_list.append(["pFile", "Data", "Description"])
    # Signature
    signature_header_list.append([pFile, hex(pe.NT_HEADERS.Signature), "Signature"])

  # IMAGE_FILE_HEADER
    file_header_list.append(["pFile", "Data", "Description"])
    file_header_list.append([pFile, hex(pe.FILE_HEADER.Machine), "Machine"])
    file_header_list.append([pFile, hex(pe.FILE_HEADER.NumberOfSections), "NumberOfSections"])
    file_header_list.append([pFile, hex(pe.FILE_HEADER.TimeDateStamp), "TimeDaeStamp"])
    file_header_list.append([pFile, hex(pe.FILE_HEADER.PointerToSymbolTable), "PointerToSymbolTable"])
    file_header_list.append([pFile, hex(pe.FILE_HEADER.NumberOfSymbols), "NumberOfSymbols"])
    file_header_list.append([pFile, hex(pe.FILE_HEADER.SizeOfOptionalHeader), "SizeOfOptionalHeader"])
    file_header_list.append([pFile, hex(pe.FILE_HEADER.Characteristics), "Characteristics"])
   
    # IMAGE_OPTINAL_HEADER
    optional_header_list.append(["pFile", "Data", "Description"])
    optional_header_list.append([pFile, hex(pe.OPTIONAL_HEADER.Magic), "Magic"])
    optional_header_list.append([pFile, hex(pe.OPTIONAL_HEADER.MajorLinkerVersion), "MajorLinkerVersion"])
    optional_header_list.append([pFile, hex(pe.OPTIONAL_HEADER.MinorLinkerVersion), "MinorLinkerVersion"])
    optional_header_list.append([pFile, hex(pe.OPTIONAL_HEADER.SizeOfCode), "SizeOfCode"])
    optional_header_list.append([pFile, hex(pe.OPTIONAL_HEADER.SizeOfInitializedData), "SizeOfInitializedData"])
    optional_header_list.append([pFile, hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint), "AddressOfEntryPoint"])
    optional_header_list.append([pFile, hex(pe.OPTIONAL_HEADER.BaseOfCode), "BaseOfCode"])
    optional_header_list.append([pFile, hex(pe.OPTIONAL_HEADER.BaseOfData), "BaseOfData"])
    optional_header_list.append([pFile, hex(pe.OPTIONAL_HEADER.ImageBase), "ImageBase"])
    optional_header_list.append([pFile, hex(pe.OPTIONAL_HEADER.SectionAlignment), "SectionAlignment"])

    print("-" *60)
    print('Signature')
    print("-" *60)
    for data in signature_header_list:
        print(data[0].ljust(20), data[1].ljust(20), data[2].ljust(20))


    print("-" *60)
    print('IMAGE_FILE_HEADERS')
    print("-" *60)
    for data in file_header_list:
        print(data[0].ljust(20), data[1].ljust(20), data[2].ljust(20))


    print("-" *60)
    print('IMAGE_OPTIONAL_HEADERS')
    print("-" *60)
    for data in optional_header_list:
        print(data[0].ljust(20), data[1].ljust(20), data[2].ljust(20))
    
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
    
    return render(request,'result.html',{'path' : path , 'lists' : a , 'inform' : inform,'image_dos_header_list':image_dos_header_list,'DosStub_list':DosStub_list, 'signature_header_list' : signature_header_list, 'file_header_list': file_header_list, 'optional_header_list' : optional_header_list})
