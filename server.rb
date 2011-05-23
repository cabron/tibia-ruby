#!/usr/bin/env ruby
require 'rubygems'
require 'socket'
require 'rsa'
require 'XTEA'
require 'zlib'
require 'dump'

key_d = 46730330223584118622160180015036832148732986808519344675210555262940258739805766860224610646919605860206328024326703361630109888417839241959507572247284807035235569619173792292786907845791904955103601652822519121908367187885509270025388641700821735345222087940578381210879116823013776808975766851829020659073
key_p = 14299623962416399520070177382898895550795403345466153217470516082934737582776038882967213386204600674145392845853859217990626450972452084065728686565928113
key_q = 7630979195970404721891201847792002125535401292779123937207447574596692788513647179235335529307251350570728407373705564708871762033017096809910315212884101

s = TCPServer.new('localhost', 7171)
c = s.accept

data = c.read(c.read(2).unpack("S")[0])
dump data, "DATA"

rsa = data[21,128]
key = RSA::Key.new(key_p*key_q, key_d)
keyp = RSA::KeyPair.new(key, key)
rsa = keyp.decrypt(rsa)
dump rsa, "RSA DECRYPTED"

##############################################

xtea = XTEA.new(rsa[0, 16])
dump xtea.key_o, "XTEA KEY"

motd = "2\nWelcome to the Forgotten server!"
p = [0x14, motd.length, motd].pack("CSa*")
chars = [["Account Manager", "Forgotten", 0x7F000001, 7172], ["Lolek", "recorded", 0x0101007F, 7172], ["GoD CabroN", "Forgotten", 0x7F000101, 7172], ["GoD rtoip", "Forgotten", 0x7F000101, 7172]]	#array of characters: nick, server name, IP and port of game server
p += [0x64, chars.length].pack("CC")
chars.each {|char|
	p += [char[0].length, char[0], char[1].length, char[1], char[2], char[3]].pack("Sa*Sa*NS")
}
p += [0].pack("S")
p = xtea.encrypt([p.length].pack("S") + p)
dump ([p.length+4, Zlib.adler32(p)].pack("SV") + p), "SEND MOTD+CHARLIST ENCRYPTED"
c.write([p.length+4, Zlib.adler32(p)].pack("SV") + p)	#SEND

c.close
s.close

s = TCPServer.new('localhost', 7172)
c = s.accept

p = [0x1F, rand(2**16), rand(2**8)].pack("CVC")
p = [p.length].pack("S") + p
dump p, "TICKET 0x1F"
c.write([p.length+4, Zlib.adler32(p)].pack("SV") + p)

data = c.read(c.read(2).unpack("S")[0])
dump data.slice!(0, 4+1), "GAME LOGIN PACKET HEADER+ID"	#drop adler checksum and packet ID
os, version = data.slice!(0, 2+2).unpack("SS")
rsa = keyp.decrypt(data)
dump rsa, "GAME LOGIN PACKET 8.54 - RSA DECRYPTED PART"
xtea = XTEA.new(rsa[0, 16])

c.close
s.close


=begin
LOGIN PACKET FROM ORIGINAL CLIENT 8.60	====
	2	8		17				128 (RSA encrypted)
	9500 73482d72 0101005c0393792c4c9405224cd3c3e54a 358ead8721808c94e4b5ae5da61cda108642d81ed68d370c317bdc6203df3206f23eb7f2decf8a1f88cdea456c86f3ba0cfe55dd1fcd730cdceddd30fd750b1c03ef1d6c0d556c8d96a6c9cca2c713511770e2ea6de0c1a2e3ae68737827130b8173f0f9c0d7206f9047ed6f4ed915836068f9b1fe33bcbf12ff66e49ec9571d
	9500 5743c69a 0101005c0393792c4c9405224cd3c3e54a 603b3ff1e4d2f35d0ac59b463f1d29ae6b645a66b8ce18a2b5a0093ff5c50046ccd79184e0677a4abdd7b777fe0283aecc1d943374601ed28155752a480be87c2e7954ae81952a901235165526fcd05fd4ce4607dde1d2f49c733e3f2c1563b407649965253392e38c274101ea68b2e7d36934823a8fff3a651990f0718e99bc

UNENCRYPTED PART
9500			73482d72	01			0100			5c03					93792c4c	9405224c	d3c3e54a
length (145)	adler32	packet type	system(linux)	version(0x35c=860)	.dat		.spr		.pic versions

RSA ENCRYPTED PART (AFTER DECRYPTION)

c5b2d967677507a18e335a298047d5c1  0700  6163636e616d65  0800  70617373776f7264  6d0000000000020200000000000000000000000000000000000000000000000000000000000000000000000000000020818d90de6932cd205919a12899f5f6029d12852b33b7532876b5e154904cce251f8216f3a8e54582c66b9815
. . . g g u . . . 3 Z . . G . .   . .   a c c n a m e   . .   p a s s w o r d   m . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . i 2 . . Y . . . . . . . . . . . 3 . S . v . . T . L . . . . . . . . E . . k . .
5f6b804349462223ff11e967600b9602  0700  6163636e616d65  0800  70617373776f7264  6d00000000000202000000000000000000000000000000000000000000000000000000000000000000000000000000609b38e7821fe38897271c6dfe8d41a7d2df56429675bddc85b85009f2b0f8e4811bbfd4c354439b90e7969c17
. k . C I F . . . . . g . . . .   . .   a c c n a m e   . .   p a s s w o r d   m . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 8 . . . . . . . . m . . A . . . V B . u . . . . P 	 . . . . . . . . . T C . . . . . .
	XTEA key (16 bytes)		  len.  account name    len.  password          hardware data                                                                                 padding

8.54
9500 1d4b8616 01 0100 56039eb8 284b872c 1e4bd3c3 e54a7d5283ff65a15ea6ddd423f0ca0293e4ff07460b924671c80eb886dedbbe90b5908dc19688d282349bc2bdda3557544cf35cd5872f0fce3094fc2bb8184e7df2be7391cdf1c2cb772dd370a1d3b4d1dacbfdbc4817f23ced41839f5e5992d8e65588d81764de11114fbb3669a53313a3d96ad6c0502b8173bc826c65505d14c4

422dbb864cb81a990f2293d16b9e5871  0700  6163636e616d65  0800  70617373776f7264  6d00000000000202000000000000000000000000000000000000000000000000000000000000000000000000000000f77719792b0e4821e7b3fb670392a03b97328891def519f7dc79a92030d4fc6fe97236b28dee2633cbd5a601b6
B . . . L . . . . . . . k . X q   . .   a c c n a m e   . .   p a s s w o r d   m . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . w . y . . H . . . . g . . . . . 2 . . . . . . . y .   0 . . o . r 6 . . . . 3 . . . . .

FROM MY CLIENT
9500 67452973 01 0100 5c03 4c2c7993 4c220594 4ae5c3d3		086d99d0a9abee8fd39f5c667db9de046aa8d4028cfc3a32c2c99bc8ef4d3164b6b2cd5ca65a839125be2528dc50005ff9c9853f88eb7c708d39a54ec1cb8c192fa2cf102bec33ae6362099d123562d7a2ef29256929fee77b37b02d385a8dd03320f62d7bfa41893ad3495c9d9028526f762b201de5fb65d08faa2d13ecedc7

b40efa55137d68cf8def3c5b8f1c554c  0700  6163636e616d65  0800  70617373776f7264
. . . U . . h . . . . . . . U L   . .   a c c n a m e   . .   p a s s w o r d

9b00142200320a57656c636f6d6520746f2074686520466f72676f7474656e207365727665722164040f004163636f756e74204d616e616765720900466f72676f7474656e7f000101041c05004c6f6c656b08007265636f726465647f000101041c0a00476f4420436162726f4e0900466f72676f7474656e7f000101041c0900476f442072746f69700900466f72676f7474656e7f000101041c0000333333
9b00142200320a57656c636f6d6520746f2074686520466f72676f7474656e205365727665722164040f004163636f756e74204d616e616765720900466f72676f7474656e7f000101041c05004c6f6c656b08007265636f726465647f000101041c0a00476f4420436162726f4e0900466f72676f7474656e7f000101041c0900476f442072746f69700900466f72676f7474656e7f000101041c0000333333

TICKET
06001f28a0000066
. . . . . . . f

RSA DECRYPTED PART - GAME LOGIN PACKET (127)
fb4dd9410ef631bf99c83b779a41e1ba0007006163636e616d650f004163636f756e74204d616e61676572080070617373776f726428a000006660fffbaf6fceaa0d3fc3f5dcdc1ad0784afd9cafef05ada4b6f0d63c718fc2f07e731f141305749f42505abbd6078a31f067e7d8ae9d932f4234a51cd504bb665a2f1fb3bc
. M . A . . 1 . . . . w . A . . . . . a c c n a m e . . A c c o u n t   M a n a g e r . . p a s s w o r d . . . . f . . . . o . . . . . . . . . . x J . . . . . . . . . . . q . . . . s . . . . t . B P Z . . . . 1 . g . . . . . . B 4 . . . . . f Z . . . .

9b180eb090b35abd2dd38d4d29a8fa260003007061780f004163636f756e74204d616e616765720a006d61736c6f6d61736c6f748c0000f4
. . . . . . Z . . . . M . . . . . . . p a x . . A c c o u n t   M a n a g e r . . m a s l o m a s l o t . . . . 


 1064
2504  0a  d4060010  32  0000    64  3200  3200  070e  ff64  0000  ff64  0000  ff64  0000  ff64  0000ff640000ff640000ff640000ff640000ff640000ff640000ff640003ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640003ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640003ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640003ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640003ff640000ff640000ff640000ff9a01460800ff640000ff9a0100ff640000ff9a014a0800ff640000ff640000ff640003ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640003ff640000ff640000ff640000ff9a0100ff640000ff9a016100 00000000  d4060010  0f00  4163636f756e74204d616e61676572  64  02  6e00  0000000000            00 00  dc00  00 00 00 01 00ff640000  ff9a0100  ff640000  ff640000  ff640003ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640003ff640000ff640000ff640000ff9a01690000ff640000ff9a0100ff640000ff9a01580800ff640000ff640000ff640003ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640003ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640003ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640003ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640003ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff640000ff6400ffffffffffffffffffffffffffff02ff790179027903790479057906790779087909790aa096009600409c00000000000001000000000000000000d809a10a000a000a000a000a000a000a0082fad78dd40600100000a200007805680ba0960096004c9a00000000000001000000000000000000d8097806c60ca096009600889000000000000001000000000000000000d8097804ea0da096009600fc8500000000000001000000000000000000d8097803250ba096009600dc8200000000000001000000000000000000d809a096009600468200000000000001000000000000000000d809b4145e0048656c6c6f2c207479706520276163636f756e742720746f206d616e61676520796f7572206163636f756e7420616e6420696620796f752077616e7420746f207374617274206f766572207468656e2074797065202763616e63656c272e8332003200070b33
. .   .   . . . .   2   . .     d   2 .   2 .   . .   . d   . .   . d   . .   . d   . .   . d   . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . . . F . . . d . . . . . . . d . . . . . J . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . . . . . d . . . . . a .  . . . .   . . . .   . .   A c c o u n t   M a n a g e r   d   .   n .   . . . . .             .  .   . .   .  .  .  .  . . d . .   . . . .   . d . .   . d . .   . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . . . i . . . d . . . . . . . d . . . . . X . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . d . . . . . . . . . . . . . . . . . y . y . y . y . y . y . y . y . y . y . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . x . h . . . . . . L . . . . . . . . . . . . . . . . . . . x . . . . . . . . . . . . . . . . . . . . . . . . . . . . x . . . . . . . . . . . . . . . . . . . . . . . . . . . . x . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . F . . . . . . . . . . . . . . . . . . . . . . . H e l l o .   t y p e   . a c c o u n t .   t o   m a n a g e   y o u r   a c c o u n t   a n d   i f   y o u   w a n t   t o   s t a r t   o v e r   t h e n   t y p e   . c a n c e l . . . 2 . 2 . . . 3 
																																																																																																																																																																					CID		len		NICK						HP	DIR	look	head,b,l,f,a or lookit light speed s, sh, e, im
01001e3333333333
. . . 3 3 3 3 3 

=end