Volume Header Test Cases

Folder Structure:
   volume_header_enc_1.hex
   volume_header_enc_2.hex
   volume_header_enc_3.hex
   keyfiles_1.txt
   keyfiles_2.txt
   keyfiles_3.txt
   keyfiles/keyfile_1.txt
   keyfiles/keyfile_2.txt
   RunTestCases.bat
   ForgotPasswordCombinationCheck.bat
   README_TestCases.txt

Test Case 1:
    password is "redorangeyellow"

    volume_header_enc_1.hex
    keyfiles_1.txt
    keyfiles/keyfile_1.txt

    keyfile_1.txt is SHA-256(red), SHA-256(orange), SHA-256(yellow)

    Hash Algorithm: RIPEMD-160
    Volume Encryption Algorithm: AES

Test case 2;
    password is "yelloworangered"

    volume_header_enc_2.hex
    keyfiles_2.txt
    keyfiles/keyfile_2.txt

    keyfile_1.txt is concatenated SHA-256(red), SHA-256(orange), SHA-256(yellow)
    keyfile_2.txt is concatenated SHA-256(yellow), SHA-256(orange), SHA-256(red)

    Hash Algorithm: Whirlpool
    Volume Encryption Algorithm: AES-Twofish-Serpent

Test Case 3:
    password is "orangeyellowred"

    volume_header_enc_3.hex
    keyfiles_3.txt
    keyfiles/keyfile_1.txt
    keyfiles/keyfile_2.txt

    keyfiles_3.txt is path to keyfile_1.txt and keyfile_2.txt

    Hash Algorithm: SHA-512
    Volume Encryption Algorithm: Twofish-Serpent

Test Case 4:
    password is "orangeredyellow"

    volume_header_enc_4.hex
    no keyfiles supplied

    Hash Algorithm: SHA-512
    Volume Encryption Algorithm: Serpent-Twofish-AES

Execution:
  Copy the Untrue.exe and dll's to the TestCases folder.
  Run the RunTestCases.bat batch file

Notes:
  The --password_key_files command line argument accepts a text file listing combinations of path and/or files.
  Specify the full path in the text file if the paths and/or files are not relative to the untrue executable.

  The RunTestCases.bat batch file runs each of the four test cases to decrypt the volume header.
  The ForgotPasswordCombinationCheck.bat is an example of iterating through some password combinations.
   **I had forgotten my password details but knew the general structure and it was easy enough to iterate those combinations.
   **The volume header can be extracted directly from the volume into the hex file using 'secinspect'.

    