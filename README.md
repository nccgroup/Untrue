# Untrue
Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Richard Turnbull, richard [dot] turnbull [at] nccgroup [dot] com

http://www.github.com/nccgroup/untrue

Released under AGPL, see LICENSE for more information

## Description

Untrue is a tool for checking passwords against TrueCrypt encrypted volumes and disks, and/or decrypting the data.

## System Requirements

Windows, with version 4.0 of the .NET Framework.

## Existing Work

TCHead is a tool which also checks passwords against volume headers, but [its website](http://16s.us/TCHead/) seems to be down, and in any case, it offers no capability to decrypt the data.
Björn Edström released [some Python code](http://blog.bjrn.se/2008/02/truecrypt-explained-truecrypt-5-update.html), which is effective at checking passwords, but has only limited decryption capabilities.

## Usage

There are three different tasks you can perform using Untrue, and the usage is a bit different for each.
Note that Untrue will try its best to intelligently determine the location of the volume header, and the location and size of the encrypted area. However, if this doesn't work, or you want more flexibility, there are options to control this.

### Check a password against a TrueCrypt volume or drive

    Untrue.exe [general_options] --password_check_only -p passphrase (--volume_header_file=input_file | --volume_header_hex=hex_string) [algorithm_options] [password_checking_options]

You need to provide the volume header. Normally you would do this by specifying a file, using the `--volume_header_file` option (normally this file would be a TrueCrypt encrypted volume, an image of a TrueCrypt encrypted drive, or an image of a TrueCrypt Rescue CD).
However, you can also provide the volume header as a hex string (512 bytes long), with the `--volume_header_hex` option.

### Decrypt a TrueCrypt volume or drive, using a given key

    Untrue.exe [general_options] -i input_file -o output_file (-k hex_string | --key_file=file_containing_key) [algorithm_options] [decryption_options]

You need to provide the volume encryption key, either as a hex string (with the `-k` option) or by pointing to a file containing it (with the `--key`_file option).
You also need to specify an input file (i.e. the encrypted volume or drive) and an output file. Untrue will refuse to write to an existing output file (to avoid accidental overwrites).

### Check a password against a TrueCrypt volume or drive, and then use the resultant key to decrypt the volume or drive contents

    Untrue.exe [general_options] -p passphrase -i input_file (--volume_header_file=input_file | --volume_header_hex=hex_string) -o output_file [password_checking_options] [algorithm_options] [decryption options]

You also need to specify an input file (i.e. the encrypted volume or drive) and an output file. Untrue will refuse to write to an existing output file (to avoid accidental overwrites).
If the volume header is not present in the input file (e.g. it's on a Rescue CD image), you can optionally specify the file containing the volume header (using `--volume_header_file`) or provide the volume header bytes (using `--volume_header_hex`). If you don't do either of these, the volume header will be read from the input file.
If the passphrase is wrong, decryption won't proceed.

### General Options

	-h, --help          Show usage information and exit
	-V, --version       Show version and exit
	-v, --verbose       Verbose mode (verbose information written to standard output)
	-d, --debug         Debug mode (even more information written to standard output)
	-q, --quiet         Quiet mode (nothing written to standard output)

### Password Checking Options

`--volume_header_location=VALUE`	
Location of the volume header in the volume header file. Note that this is specified as the sector number, assuming a sector size of 0x200 bytes. 

In most cases you should be safe to omit this option - Untrue will try to intelligently guess it if not specified. If no volume header file is specified (i.e. the volume header is in the input file) then Untrue will try to determine if the input file is an encrypted volume or encrypted drive image, and will set the volume header location accordingly. If a volume header file is specified, and appears to be a Rescue CD image, then the volume header location will again be set accordingly. Otherwise, the volume header location will default to 0. 

### Algorithm Options
You can specify the encryption algorithms to be attempted by Untrue (note that TrueCrypt offers various encryption algorithms, and there is no way to tell which has been used from inspection of an encrypted volume).
When password checking, if none of the options below are specified, all of them will be tried. However, if any of the below options are specified, only these algorithms will be tried.
When decrypting with a given key, if none of the options below are specified, TrueCrypt's default algorithm of AES will be used. Otherwise, if any one of the options below is specified (it is an error to select more than one), then that will be used.
When decrypting based on a successful password check, the algorithm specified in the decrypted volume header will be used (regardless of any of the options below).

	--aes							Try AES encryption algorithm
	--serpent        				Try Serpent encryption algorithm
	--twofish              			Try Twofish encryption algorithm
	--aes_twofish          			Try AES-Twofish encryption cascade
	--aes_twofish_serpent  			Try AES-Twofish-Serpent encryption cascade
	--serpent_aes          			Try Serpent-AES encryption cascade
	--serpent_twofish_aes  			Try Serpent-Twofish-AES encryption cascade
	--twofish_serpent      			Try Twofish-Serpent encryption cascade
	--all_encryption_algorithms     Try all encryption algorithms

You can specify the hash algorithms to be attempted by Untrue (note that TrueCrypt offers various hash algorithms, and there is no way to tell which has been used from inspection of an encrypted volume).
When password checking, if none of the options below are specified, all of them will be tried. However, if any of the below options are specified, only these hash algorithms will be tried.
Note that TrueCrypt uses a different number of PBKDF2 iterations for RIPEMD-160 when it is used for system (full-disk) encryption than when it is used for volume encryption. This is treated as two different hash algorithms by Untrue.

	--ripemd160            		    Try RIPEMD-160 hash algorithm
	--ripemd160_system     		    Try RIPEMD-160 hash algorithm (system encryption)
	--whirlpool            		    Try Whirlpool hash algorithm
	--sha512               		    Try SHA-512 hash algorithm
	--all_hash_algorithms  		    Try all hash algorithms

### Decryption Options

	-e, --encrypt          		
Perform encryption instead of decryption.
 Only likely to be useful when the Rescue CD decryption operation has been (accidentally) run multiple times against a drive.

	--first_decrypt_sector=VALUE    
Sector number in input file where decryption should begin. 
In most cases you can omit this option. If it is not specified, Untrue will read the correct value from the decrypted volume header (if available) or will otherwise attempt to determine the correct value by checking if the input file appears to be an encrypted volume or encrypted drive.

	--sectors_to_process=VALUE     
Number of sectors to decrypt
In most cases you can omit this option. If it is not specified, Untrue will read the correct value from the decrypted volume header (if available) or will otherwise attempt to determine the correct value by checking the length of the input file.

	--first_sector_offset=VALUE     
TrueCrypt logical sector number for first decrypted sector.
In order to successfully decrypt data, XTS mode needs to know the correct logical sector number for each sector.
In most cases you can omit this option. It will only be necessary if the input file is an extract from an encrypted volume or drive, rather than beginning at the start of it.

## Examples

Check the password 'foobar' against the TrueCrypt encrypted volume `vol.tc`:

	Untrue.exe --password_check_only --volume_header_file=vol.tc -p foobar

Do the same, where you know that the default encryption and hash algorithm options were used:

	Untrue.exe --password_check_only --volume_header_file=vol.tc -p foobar --aes --ripemd160

Do the same, but also produce a decrypt of the volume:

	Untrue.exe -i vol.tc -o decrypt.bin -p foobar --aes --ripemd160

Decrypt the volume, but with a specified key (no passphrase supplied this time, and no need to specify the hash algorithm):

	Untrue.exe -i vol.tc -o decrypt.bin -k F0839722F9DC490D985397860EAAED6350CAEC956B40A17B50CD397DD197442D9BBA43D0DB6C91167572D4E5630525FB3374EB49389DD5C8D78BB93AA1D4DC09 --aes 

Decrypt the TrueCrypt encrypted disk `disk.img`:

	Untrue.exe -i disk.img -p foobar -o output.bin 

Do the same, but this time the volume header is to be read from the Rescue CD image `cd.img` (Untrue will attempt to locate the volume header on the Rescue CD image):

	Untrue.exe -i disk.img -p foobar -o output.bin --volume_header_file=cd.img

Do the same, explicitly specifying where the volume header is on the Rescue CD image (it is at sector 0xA6 by default):

	Untrue.exe -i disk.img -p foobar -o output.bin --volume_header_file=cd.img --volume_header_location=0xA6

Do the same, but this time we know that the first sector of the disk image is missing, and we only want to decrypt 200 sectors:

	Untrue.exe -i disk2.img -p foobar -o output.bin --volume_header_file=cd.img --volume_header_location=0xA6 --sectors_to_process=200 --first_decrypt_sector=0x3E --first_sector_offset=0x3F

(By default, the encrypted data starts at sector 0x3F, but given that our input file here is missing the first sector, we specify the first sector to be decrypted is 0x3E. However, since this is actually sector 0x3F relative to the start of the original disk image, we have to specify a first sector offset of 0x3F.)

## Limitations

Untrue only supports the XTS cipher mode, which was introduced in TrueCrypt v5.0. Versions earlier than this use LRW or CBC mode, and are not supported by Untrue (for either password checking or decryption).

Untrue offers no support for checking passwords against TrueCrypt volumes which use keyfiles.

Untrue offers no support for checking passwords against, or decrypting, hidden volumes or hidden operating systems.

Untrue does not support TrueCrypt volumes/disks where the sector size is not 0x200 bytes.

Some or all of these features may be added at a later date.

## Libraries

Untrue uses the Bouncy Castle C# crypto library (http://www.bouncycastle.org/csharp/).
The license for this can be viewed at https://www.bouncycastle.org/licence.html.

Untrue also uses the NDesk.Options library (http://www.ndesk.org/Options).
This is released under the MIT License (http://opensource.org/licenses/mit-license.php).


