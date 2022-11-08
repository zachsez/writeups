# Keepin' it Real
Rev challenge from BuckeyeCTF 2022 by Battelle. I played this CTF solo, and was able to get the first first blood and the only solve on this challenge.

## Prompt
We managed to recover an old control system, but we can't seem to figure out how to get the thing to work! Device documentation suggests that it shipped with some kind of client software that is no longer available. Luckily, we were able to recover the firmware image from a flash chip on the board. It appears to be listening on TCP port 10033. Flag format: flag{...}

`nc -v kir.ctf.battelle.org 10033`

Hint: There is no prompt displayed on a successful connection, after connecting hit enter a few times to see proprietary data start to come back

Given firmware.img (MD5: 04c41b8cfdccec69248d037103e89e2c)

## Recon
Sure enough connecting to the IP and port doesn't given any ASCII feedback. So I fired up wireshark and captured a few packets. 

![Wireshark Capture](media/wireshark.png?raw=true)

Regardless of what I entered. I always got the same 9 byte reponse:

`d0d00b0e0001fffbfd`

Next I ran binwalk on the firmware.img, no luck other than I learned this was aarch64.

Finally I dropped firmware.img into Binary Ninja to look at the strings. There was a fake flag string `flag{this_is_n0t_the_flag}` and near by there was also a `Packet header has invalid checksum`. I figured this checksum string had to be challenge specific given its location to the fake flag. 

Knowning this was embedded control system and there was some type of checksum on packets. I figured the last byte might be the sum or xor of the other bytes. I created a little test program to monkey around with that idea:

```python
xor = 0 
add = 0 
for b in packet[:-1]: 
    xor ^= b 
    add += b 
    add &= 0xff 
```

After execution I got `xor = 0 and add = 0xb4`, I found it intresting that the xor value was zero, that happens when the same value is xored with itself. At this point I was little confused and decided to look for the checksum functionality in the code.

## Looking for the Checksum
Following the Xref for the checksum string I found myself in stub 0x2c04, the first thing I noticed was the constant 0xe0bd0d0 which is the same value as the first four bytes of out packet from earlier. This gave me some confidence to keep reversing this function since it might have something useful.

As I continued reversing I found that the checksum is the xor of the first 7 bytes and 8th byte is the checksum value. This explains why I got zero value from my earlier test program I was XORing an extra byte. Additionally the 5th and 6th bytes are byteswapped so I figured that must be sometype of int16 going from big to little endian.

At this point it was hard to keep track of all this in my head so I figured I create struct to better understand this proprietary protocal. 

```c
struct message __packed
{
    uint32_t header;
    int16_t something1;
    uint8_t something2;
    uint8_t checksum;
    uint8_t something3;
};
```

Finally I renamed stub 0x2c04 "checksum_checker" since its strings talked about finding invalid checksums.

## Time to look at Control Flow
Next I figured I should look at who calls checksum_checker. Looking at stub 0x1e38 I notice a while true loop. Having worked on embedded software in a past life, I figured this must be the server function. The server function would read incoming messages, verify the checksum then dispatch the message for processing. Depending if the return value is postive or negative from checksum_checker the server either goes to 0x2ef0 or 0x2d88.

I choose to start with 0x2d88, the negative number condtion which I'm assuming to be error condition. This felt like the path my "AAAAAAAAAAAAAAA" packet I sent via netcat would take.

Once again I see 0xe0bd0d0 but this time I also see 0x100 and 0xff all constants that appear in my captured packet. I fixed up the memory layout by assigning my struct to the local buffer.

![Binja Error Message Snap](media/error_msg_0x2d88.png?raw=true)

Sure enought the `msg.checksum` field was being assigned the return value of a function that takes a pointer to msg and 7 as parameters, could this be a compute_checksum function. Yup, 0x2d5c xors a buffer together, so confirmed.

![Binja Compute Checksum Snap](media/compute_checksum_0x2d5c.png?raw=true)

There is one final function call in function and its to 0x11708, I pretty quickly IDed this as memcpy, which makes sense we are coping the local msg buffer into the pointer provided as the first argument.

At this point I renamed 0x2d88 as error_msg and started to make some educated guesses on what other field in the message struct might be.

```c
struct message __packed
{
    uint32_t header;
    int16_t length;
    uint8_t cmd;
    uint8_t checksum;
    uint8_t data[0x1];
};
```

The `0001` is the length of the data field which in the case of the error_msg contains the error value. The `ff` is the command or message type being sent. I was getting a strong TLV vibe, from the message struct so I decided to try the no error case next to confirm my guesses.

## Stub 0x2ef0 Command Processor??
Skimming this function the first thing that stands out is the function pointer / indirect call and the global data. From my experience with embedded systems function pointers are pretty common when trying to access a global handler table.

Looking at first global data reference 0x2f5b0 I see what appears to be 0x10 size structured, the first qword is just a byte (maybe our command) and the second qword is 0xc000xxyy (maybe an address)? I create a new struct called handler:

```c
struct cmd_handler __packed
{
    uint8_t cmd;
    __padding char _1[7];
    void* process_func;
};
```

I rebased the firmware image to 0xc000_0000 to see if the process_func pointers lined up with functions and they did! At this point I had pretty good confidence this wsa the process_request function and renamed stub 0x2ef0.

![Binja handlers Snap](media/handler_0x2f5b0.png?raw=true)

## Sending a Valid Message
I clicked thought the command handlers till I landed on stub 0xc000_35c8 which contained the format string "SNO: %s Version %s". I remember seeing string "1.0.4 ARM Reel" from strings recon which looked like a version and figured this handler would be a great starting point to get the communication working with the remote.

I started a pwntools script to handle the interaction with the server.I made sure set the log level to debug so I would get all the bytes being sent and received over the wire. The command number was `0xd0` so I created a function for this message:

```python
def read_sno() -> bytes:
    message = bytearray()
    message += HEADER
    message += b"\x00\x00"
    message += b"\xd0"
    message += bytearray([checksum(message)])
    return message
```
Sure enough I was able to capture the serial number and version:

![SNO Command Output](media/sno_output.png?raw=true)

## Flag Store
During the setup of the ARM chip (stub 0x2830) the flag is copied from a static string to a global buffer which I named flag_store. The flag_store variable happend to be referenced in another function (0x3578) which also happened to be command handler for `0xbc`...

This is when I first encountered the `*(arg3 + sx.q(arg4) * 0x134 + <offset>))`, I tired to spend a little time reversing this pointer math but ended up assuming that arg3 and arg4 some how identify the current TCP session between the remote and my machine and what I care about is the offset.

Back to stub 0x3578, offset 0x1c4 is check if its true send back the contents of flag store, if its false send an error message.

![Binja Read Flag Store Snap](media/read_flag_0x3578.png?raw=true)

I renamed this stub process_read_flag_store and began creating a function in script to read the flag. Figured I YOLO and see if 0x1c4 is true by default, it is an embedded device ;) ... :( That didn't work received `d0d00b0e0001fffbfc` back from the remote, the expected error message.

How do I set offset 0x1c4 to true?

## Stub 0x320c
This is the only function that sets 0x1c4 to 1, but what events lead up to 0x1c4 being set? There are 2 string compare checks each successful check increments a variable, if said variable is 2 then 0x1c4 is set to 1.

![Binja Login Logic Snap](media/process_login.png?raw=true)

Unlike the other handlers this one contained a while loop, which I found strange could this be a multi part message?

To be honest this was the hardest part of the challenge for me, in retrospec the concept was pretty easy. This function is a login routine i.e. give me a username and password. But how are the username and password encoded into the message?

The answer is TLVs (Type Length Value) these are a pretty common method of serialization in embedded systems since their parsing code is on the order of 10s of lines of code instead of 100s or 1000s for JSON or XML. 

Our login request command (`0x22`) will include a data stream of 2 TLVs the first TLV is the username the second is password. Reversing the username was pretty easy since the value is compared against a static string "root" so to construct that TLV as follows:

```
T: 0x20
L: 0x04
V: root
```

The password follows the same form but make sure to include a null byte at the end of the string since this string compare is for 0x20 bytes, if you don't include a null byte the compare operation will fail.

```
T: 0x30
L: 0x06
V: admin\0
```

## What is the Password
If we revisit the setup function we see that default password is "root". I gave that a shot but did not get a successful login.

Next I tried to think of ways to leak the password, maybe the difference in the strings is return to the user therefore I could brute force the password byte by byte? Nope no side channels.

Maybe I can perform an overflow into the password buffer so I can control the value? Nope no user control data near the buffer.

As I click around in the binary and command handlers looking for anything useful I came across the string "resetting default password", which was tied to command `0x72`. This command handler verified that the data for the incoming request matched the serial number of the device if so copy the serial number to offset 0x1c6 and set offset 0x1c5 to 1.

![Binja Serial Number Snap](media/serial_number.png?raw=true)

At first this seemed useless, I don't need the offset 0x1c6 reset to the default password I need the global password buffer. But inspecting the login handler again I noticed that if the password check fails, the offset 0x1c6 is compared to the value in the password TLV if that checks out then offset 0x1c5 is check if that is set then we successfully authincate with the device!

## The Solve
The solve will include the following tasks, leak the serial number using the query version command, reset the password by provide the serial number to command `0x72`, login into the device using `root` and the serial number, and finally read the flag using the read flag command. 

As I coded up the solution I realized the serial number is constant, and is identical to the string in the firmware, so leaking the serial number isn't really required. But I left this in because if this device was in the wild you could exploit it with out needing the firmware dump, just its IP address.
