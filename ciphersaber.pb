; ==============================================================
; Created on:         24.10.2015
; App/Lib-Name:       ciphersaber
; Author:             Niklas Hennigs
; Version:            0.3
; Compiler:           PureBasic 5.40 (MacOS X - x64)
; ==============================================================

CompilerSelect #PB_Compiler_OS
  CompilerCase #PB_OS_MacOS
  ImportC ""
    readpassphrase(prompt.p-UTF8, *buf, bufsize.i, flags.i)
  EndImport
  CompilerCase #PB_OS_Linux
  ;    CAVE: getpass() is limited to 128 bytes! Use readpassphrase() instead.
  ImportC ""
    getpass(prompt.p-UTF8)
  EndImport
  ;     ImportC "-lbsd"
  ;       readpassphrase(prompt.p-UTF8, *buf, bufsize.i, flags.i)
  ;     EndImport
CompilerEndSelect


Macro ciphersaber
  GetFilePart(ProgramFilename())
EndMacro


Procedure usage()
  PrintN("Usage:")
  PrintN("  " + ciphersaber + " [-d] [-r rounds] [< infile] [> outfile]")
  PrintN("")
  PrintN("Options:")
  PrintN("  -d         Decrypt [Default: Encrypt].")
  PrintN("  -r rounds  Repetitons of state array mixing loop [Default: 20].")
  PrintN("  -h         Show this help text.")
  PrintN("")
  PrintN("See:")
  PrintN("  http://ciphersaber.gurus.org/faq.html")
  PrintN("  http://diceware.com")
EndProcedure


Procedure encrypt(*input.Ascii, inputLen, *output.Ascii, *key.Ascii, keyLen, rounds = 20)

  ; max key length of 246 bytes
  If keyLen > 246
    keyLen = 246
  EndIf

  ; define state array and key array (S2)
  Dim S.a(255)
  Dim S2.a(255)

  ; setup index variables
  i.u = 0
  j.u = 0
  n.u = 0

  ; generate random 10 byte initialization vector (IV) (conveniently at the beginning of output)
  OpenCryptRandom()
  CryptRandomData(*output, 10)

  ; put first 246 bytes of key into S2 array
  CopyMemory(*key, @S2(), keyLen)

  ; copy IV (first 10 bytes of output) to end of user key in S2 array
  CopyMemory(*output, @S2(keyLen), 10)
  *output = *output + 10

  ; fill the array repeating key and IV
  For i = keyLen + 10 To 255
    S2(i) = S2(i - keyLen - 10)
  Next

  ; set up state array
  For i = 0 To 255
    S(i) = i
  Next

  ; mix up the state array
  j = 0
  For n = 1 To rounds ; 20 ist Standardwert von Ciphersaber-2, 10 wurde für die Testdatei 'cs2test1.cs2' benutzt
    For i = 0 To 255
      j    = (j + S(i) + S2(i)) % 256
      Swap S(i), S(j)
    Next
  Next

  ; ciphering operation
  j = 0
  i = 0
  n = 0

  While inputLen
    i = (i + 1) % 256
    j = (j + S(i)) % 256
    Swap S(i), S(j)
    n         = (S(i) + S(j)) % 256
    *output\a = *input\a ! S(n)
    *input + 1
    *output + 1
    inputLen - 1
  Wend

EndProcedure


Procedure decrypt(*input.Ascii, inputLen, *output.Ascii, *key.Ascii, keyLen, rounds = 20)

  ; max key length of 246 bytes
  If keyLen > 246
    keyLen = 246
  EndIf

  ; define state array (S) and key array (S2)
  Dim S.a(255)
  Dim S2.a(255)

  ; setup index variables
  i.i = 0
  j.u = 0
  n.u = 0

  ; put first 246 bytes of key into S2 array
  CopyMemory(*key, @S2(), keyLen)

  ; copy initialization vector (IV) from beginning of input to the end of user key in S2 array
  CopyMemory(*input, @S2(keyLen), 10)

  ; move input pointer (*input) ten bytes to start of content
  *input = *input + 10

  ; fill the array repeating key and IV
  For i = keyLen + 10 To 255
    S2(i) = S2(i - keyLen - 10)
  Next

  ; set up state array
  For i = 0 To 255
    S(i) = i
  Next

  ; mix up the state array
  j = 0
  For n = 1 To rounds ; 20 ist Standardwert von Ciphersaber-2, 10 wurde für die Testdatei 'cs2test1.cs2' benutzt
    For i = 0 To 255
      j = (j + S(i) + S2(i)) % 256
      Swap S(i), S(j)
    Next
  Next

  ; ciphering operation
  j = 0
  i = 0
  n = 0

  While inputLen
    i = (i + 1) % 256
    j = (j + S(i)) % 256
    Swap S(i), S(j)
    n         = (S(i) + S(j)) % 256
    *output\a = *input\a ! S(n)
    *input + 1
    *output + 1
    inputLen - 1
  Wend

EndProcedure


Define argc = CountProgramParameters()

If argc > 3
  OpenConsole()
  usage()
  CloseConsole()
  End 1
EndIf

Define key.s   = ""
Define *key
Define *passbuf
Define decrypt = 0
Define rounds  = 20
Define armored = 0

For i = 0 To argc
  If ProgramParameter(i) = "-h"
    OpenConsole()
    usage()
    CloseConsole()
    End 1
  ElseIf ProgramParameter(i) = "-d"
    decrypt = 1
  ElseIf ProgramParameter(i) = "-r"
    i      = i + 1
    rounds = Val(ProgramParameter(i))
  EndIf
Next


*key = AllocateMemory(250)

CompilerSelect #PB_Compiler_OS
  CompilerCase #PB_OS_MacOS
  *passbuf = AllocateMemory(250)
  *key     = readpassphrase("Passphrase? ", *passbuf, MemorySize(*passbuf), 0)
  CompilerCase #PB_OS_Linux
  ; *passbuf = AllocateMemory(250)
  ; *key     = readpassphrase("Passphrase? ", *passbuf, MemorySize(*passbuf), 0)
  *key = getpass("Passphrase? ")
CompilerEndSelect

keylen = StringByteLength(PeekS(*key))

OpenConsole()

ConsoleError("rounds = " + Str(rounds))

; --------------------- read input from stdin
Define TotalSize  = 0
Define BufferFree = 10000
Define *Buffer    = AllocateMemory(BufferFree)

Repeat
  ReadSize = ReadConsoleData(*Buffer + TotalSize, BufferFree) ; read a block of data
  TotalSize + ReadSize
  BufferFree - ReadSize
  If BufferFree < 100  ; resize the buffer if it is not large enough
    BufferFree = 10000
    *Buffer    = ReAllocateMemory(*Buffer, TotalSize + 10000)
  EndIf
Until ReadSize = 0 ; once 0 is returned, there is nothing else to read
; --------------------- read input from stdin

If TotalSize > 0
  Define length            = TotalSize
  Define *input            = *Buffer
  Define *output

  If decrypt
    *output = AllocateMemory(length - 10)
    decrypt(*input, length, *output, *key, keylen, rounds)
    WriteConsoleData(*output, MemorySize(*output))
  Else
    *output = AllocateMemory(length + 10)
    encrypt(*input, length, *output, *key, keylen, rounds)
    WriteConsoleData(*output, MemorySize(*output))
  EndIf
EndIf
