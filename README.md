# PE-Viewer
리버싱
#### PE뷰어가 제공하는 기능을 직접 구현

경로 : C:/reversing/notepad.exe

- IMAGE_DOS_HEADER
- MS-DOS Stub Program
- IMAGE_NT_HEADERS
  - Signature
  - IMAGE_FILE_HEADER
  - IMAGE_OPTIONAL_HEADER
- IMAGE_SECTION_HEADER .text
- IMAGE_SECTION_HEADER .data
- IMAGE_SECTION_HEADER .rsrc
- BOUND IMPORT Directory Table
- BOUND IMPORT DLL Names
- SECTION .text
  - IMPORT Address Table
  - IMAGE_DEBUG_DIRECTORY
  - IMPORT Directory Table
  - IMPORT Name Table
  - IMPORT Hints/Names & DLL Names
- SECTION .rsrc
