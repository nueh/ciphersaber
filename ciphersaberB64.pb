; ==============================================================
; Created on:         20.10.2015
; App/Lib-Name:       ciphersaberB64
; Author:             Niklas Hennigs
; Version:            0.3
; Compiler:           PureBasic 6.01 LTS - C Backend (Linux - arm32)
; ==============================================================

Macro ciphersaber
  GetFilePart(ProgramFilename())
EndMacro


Procedure usage()
  PrintN("Usage:")
  PrintN("  " + ciphersaber + " [-a] [-d] [-r rounds] key < infile > outfile")
  PrintN("")
  PrintN("Options:")
  PrintN("  -a          ASCII armor (Base64).")
  PrintN("  -d          Decrypt [Default: Encrypt].")
  PrintN("  -r rounds   Repetitons of state array mixing loop [Default: 20].")
  PrintN("  key         Encryption key.")
  PrintN("")
  PrintN("See:")
  PrintN("  http://ciphersaber.gurus.org/faq.html")
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
    n = (S(i) + S(j)) % 256
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

  While inputLen - 10
    i = (i + 1) % 256
    j = (j + S(i)) % 256
    Swap S(i), S(j)
    n = (S(i) + S(j)) % 256
    *output\a = *input\a ! S(n)
    *input + 1
    *output + 1
    inputLen - 1
  Wend
EndProcedure

Procedure.s SplitTextIntoEvenLines(text$, length.i=64)
; https://www.purebasic.fr/english/viewtopic.php?p=542434#p542434 
  Protected *in, *out, Result$, ByteLength.i, CRLFSize.i, *outHelp, *outEnd
 
 
  ByteLength = length * SizeOf(Character)
  CRLFSize = 2 * SizeOf(Character)
  *in = @text$
  *out = AllocateMemory(StringByteLength(text$) + (Len(text$) / length) * CRLFSize, #PB_Memory_NoClear)
  If *out
    *outHelp = *out
    *outEnd = *out + MemorySize(*out)
    While *outHelp + ByteLength < *outEnd
      CopyMemory(*in, *outHelp, ByteLength)
      *in + ByteLength
      *outHelp + ByteLength
      PokeS(*outHelp, #CRLF$, -1, #PB_String_NoZero)
      *outHelp + CRLFSize
    Wend
    If *outHelp < *outEnd
      CopyMemory(*in, *outHelp, *outEnd - *outHelp)
    EndIf
    Result$ = PeekS(*out, MemorySize(*out) / SizeOf(Character))
    FreeMemory(*out)
  EndIf
 
  ProcedureReturn Result$
 
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
  If ProgramParameter(i) = "-a"
    armored = 1
  ElseIf ProgramParameter(i) = "-d"
    decrypt = 1
  ElseIf ProgramParameter(i) = "-r"
    i = i + 1
    rounds = Val(ProgramParameter(i))
  ElseIf key = ""
    key = ProgramParameter(i)
  EndIf
Next


*key = AllocateMemory(Len(key))
PokeS(*key, key, -1, #PB_Ascii | #PB_String_NoZero)

;ConsoleError("rounds = " + Str(rounds))

;- Read input from stdin
Define TotalSize  = 0
Define BufferFree = 10000
Define *Buffer    = AllocateMemory(BufferFree)

Repeat
  ReadSize = ReadConsoleData(*Buffer + TotalSize, BufferFree) ; read a block of data
  TotalSize + ReadSize
  BufferFree - ReadSize
  If BufferFree < 100  ; resize the buffer if it is not large enough
    BufferFree = 10000
    *Buffer = ReAllocateMemory(*Buffer, TotalSize + 10000)
  EndIf
Until ReadSize = 0 ; once 0 is returned, there is nothing else to read
;END Read input from stdin

If TotalSize > 0
  Define length = TotalSize
  Define *input = *Buffer
  Define *output, *b64output, *DecodeBuffer
  Define b64Size, b64DecSize 

  If decrypt
    If armored
      *DecodeBuffer = AllocateMemory(length * 0.75)

      Enumeration RegEx
        #StripWhitepsace
        #TestValidBase64
      EndEnumeration

      CreateRegularExpression(#TestValidBase64, "^\s*(?:(?:[A-Za-z0-9+/]{4})+\s*)*[A-Za-z0-9+/]*={0,2}\s*$") ; https://stackoverflow.com/a/18661859
      CreateRegularExpression(#StripWhitepsace, "\s+")
  
      Define.s Eingabe = PeekS(*Buffer, -1, #PB_ASCII)

      If MatchRegularExpression(#TestValidBase64, Eingabe)
        Eingabe = ReplaceRegularExpression(#StripWhitepsace, Eingabe, "")
        PokeS(*input, Eingabe, StringByteLength(Eingabe, #PB_Ascii), #PB_Ascii|#PB_String_NoZero)
        b64DecSize = Base64DecoderBuffer(*input, StringByteLength(Eingabe, #PB_Ascii), *DecodeBuffer, MemorySize(*DecodeBuffer))
        *output = AllocateMemory(b64DecSize - 10) ; -10 because of IV
        decrypt(*DecodeBuffer, b64DecSize, *output, *key, Len(key), rounds)
      Else
        ConsoleError("Input is not a valid Base64 string!")
        CloseConsole()
        End 1
      EndIf
    Else
      *output = AllocateMemory(length - 10)
      decrypt(*input, length, *output, *key, Len(key), rounds)
    EndIf
    WriteConsoleData(*output, MemorySize(*output))
  Else ; encrypt
    *output = AllocateMemory(length + 10)
    encrypt(*input, length, *output, *key, Len(key), rounds)
    If armored
      Define.s b64out = Base64Encoder(*output, MemorySize(*output))
      PrintN(SplitTextIntoEvenLines(b64out))
    Else
      WriteConsoleData(*output, MemorySize(*output))
    EndIf
  EndIf
EndIf
; IDE Options = PureBasic 6.01 LTS - C Backend (Linux - arm32)
; ExecutableFormat = Console
; CursorPosition = 198
; FirstLine = 196
; Folding = -
; EnableXP
; DPIAware
; Executable = ciphersaberB64
; CompileSourceDirectory
; Debugger = Standalone
; Watchlist = InsertLineBreakAfterCharCount()>sOutput;InsertLineBreakAfterCharCount()>sInput
; Watchlist = InsertLineBreakAfterCharCount()>iCurrentCharCount
