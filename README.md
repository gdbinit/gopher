Gopher

A PoC OS X ransomware PoC

(c) fG! 2015. All rights reserved

reverser@put.as - https://reverse.put.as

This is a very small OS X ransomware proof of concept based on libsodium (https://github.com/jedisct1/libsodium) crypto library.

It shows how simple it is to build a robust version of such annoying threat in a couple of C lines and an external crypto library. To my knowledge Apple crypto libraries have some limitations for what I wanted to achieve with this PoC design and OpenSSL is deprecated in OS X. Honestly libsodium usage is a matter of personal choice since it's a great and easy to use crypto library.

The design principle is that there exists a master encryption pub/private key pair which is in control of the ransomware master. The ransomware binary will use the public key to encrypt session keys that are generated on each target and encrypted with the master key. In theory a victim would have to send the encrypted private session key to be decrypted. This would make it impossible to recover the files without access to the private master key. I always had trouble to understand how some ransomware files could be recovered when it's rather easy to make it near impossible without complicating too much logistics.

The file section "algorithm" is extremely basic. It only searches for .docx files in ~/Documents folder. Something really better could be built on top of OS X Spotlight feature and/or libmagic. Definitely not the goal of this PoC.

You will need to compile yourself and add to the project libsodium static library or link against a dynamic version. I haven't included that on the project, only the include files (you might need to revise those for any incompatibilities that may arise with newer libsodium versions).

Code provided as it is, it used to work last time I tested it ;-)

Enjoy,

fG!
