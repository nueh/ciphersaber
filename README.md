see http://ruletheweb.co.uk/blog/2014/04/ciphersaber/

## CipherSaber Algorithm

### Ingredients

You will need:

  * A secret key (up to 246 bytes)
  * Binary data to be encrypted or decrypted (as many bytes as you like)
  * A number `num_rounds` which should equal 1 for the original CipherSaber algorithm, or 20 for [CipherSaber-2](http://ciphersaber.gurus.org/faq.html#cs2) (recommended). Or you can choose some other value if you like.

### Method

  1. Create two 256-byte arrays called `S` and `S2`.
  2. Initialize `S` by filling it with all the values from 0 to 255 (i.e., `S[0]=0`, `S[1]=1`, `S[2]=2`, and so on.)
  3.  Copy the secret key to the bytes at the start of `S2`.
  4. **If you're encrypting**, you should then generate ten bytes of random data (called the _initialization vector_). Write a copy of these ten bytes to your output file. **If you're decrypting**, read these ten bytes back in from the start of the binary data.
  5. Append the initialization vector to `S2`, directly after the secret key. Then fill up the remainder of `S2` by repeating the secret key and initialization vector until you have set all 256 positions in `S2`.
  6. Now we have to randomize the contents of `S` based on the contents of `S2`. This is done by swapping bytes in `S` according to the following method, using the value of `num_rounds` you chose earlier: 
  
 ```
    j = 0
    for n in (1 .. num_rounds)
        for i in (0 .. 255)
            j = (j + S[i] + S2[i]) mod 256
            swap S[i], S[j]
        end
    end
```
You can now discard `S2`; it won't be used any more.

  7. Use `S` to generate a pseudo-random stream of bytes to combine with the input data (using exclusive-or (XOR) operations). Since this is a symmetric cipher, the procedure is exactly the same for encryption and decryption: 
``` 
    i = 0; j = 0
    for each byte b of binary data:
        i = (i + 1) mod 256
        j = (j + S[i]) mod 256
        swap S[i], S[j]
        k = (S[i] + S[j]) mod 256
        output (b xor S[k])
    end
```
