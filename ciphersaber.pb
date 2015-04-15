; ==============================================================
; Created on:         6.4.2015
; App/Lib-Name:       ciphersaber
; Author:             Niklas Hennigs
; Version:            0.1
; Compiler:           PureBasic 5.31 (MacOS X - x64)
; ==============================================================

Macro ciphersaber
  GetFilePart(ProgramFilename())
EndMacro


Procedure usage()
  PrintN("Usage: " + ciphersaber + " [-d] [-r rounds] key < infile > outfile")
  ;   PrintN("")
EndProcedure


Procedure.s byte2hex(*buffer, length)
  ; returns a string containing *buffer's bytes as lowercase hex (aa bb cc dd ...) wrapped after 66 chars

  Protected Dim hexa.s(length)
  Protected output.s = ""

  For i = 1 To length
    hexa(i) + Hex(PeekA(*buffer + (i - 1)))
    hexa(i) = RSet(hexa(i), 2, "0")
    hexa(i) = LCase(hexa(i))
    output  = output + hexa(i) + " "
    If (i % 22) = 0
      output = output + #CRLF$
    EndIf
  Next

  ProcedureReturn output
EndProcedure


Procedure hex2byte(address, hex$)
  ; converts hex into data.
  ; By Joakim L. Christiansen a.k.a JLC
  ; https://github.com/JoakimCh/JLCs_PB_stuff/blob/master/Hex%20library/hexLibrary.pbi

  Protected i, pos, len
  hex$ = RemoveString(hex$, " ")
  len  = Len(hex$)
  For i = 1 To len Step 2
    PokeB(address + pos, Val("$" + Mid(hex$, i, 2)))
    pos + 1
  Next
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


OpenConsole()

Define argc = CountProgramParameters()

If argc < 1 Or argc > 4
  usage()
  CloseConsole()
  End 1
EndIf

Define key.s   = ""
Define *key
Define decrypt = 0
Define rounds  = 20
Define armored = 0

For i = 0 To argc
  If ProgramParameter(i) = "-d"
    decrypt = 1
  ElseIf ProgramParameter(i) = "-r"
    i      = i + 1
    rounds = Val(ProgramParameter(i))
  ElseIf key = ""
    key = ProgramParameter(i)
  EndIf
Next


*key        = AllocateMemory(Len(key))
PokeS(*key, key, -1, #PB_Ascii | #PB_String_NoZero)

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
    If armored ; TODO: Ascii-armored Text fabriziert beim Entschlüsseln nur Mist!
      *output      = AllocateMemory(length / 3 - 10)
      Define *temp = AllocateMemory(MemorySize(*input))
      hex2byte(*temp, PeekS(*input, length))
      CopyMemory(*temp, *input, length)
      decrypt(*input, (length / 3), *output, *key, Len(key), rounds)
    Else
      decrypt(*input, (length), *output, *key, Len(key), rounds)
    EndIf
    WriteConsoleData(*output, MemorySize(*output))
  Else
    *output = AllocateMemory(length + 10)
    encrypt(*input, length, *output, *key, Len(key), rounds)
    If armored
      PrintN(byte2hex(*output, MemorySize(*output)))
    Else
      WriteConsoleData(*output, MemorySize(*output))
    EndIf
  EndIf
EndIf
; IDE Options = PureBasic 5.31 (MacOS X - x64)
; ExecutableFormat = Console
; CursorPosition = 256
; FirstLine = 216
; Folding = --
; EnableUnicode
; EnableXP
; Executable = ../bin/ciphersaber
; CompileSourceDirectory
; Debugger = Standalone