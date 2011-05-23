#!/usr/bin/env ruby1.9
require 'rubygems'
require 'socket'
require 'lib/crypt'
require 'lib/dump'
#require 'wx'

def sprite_to_rgba f
	colorkey = f.read(3).unpack("C*")
	size = f.read(2).unpack("S")[0]
	data = f.read(size)
	rgba = ''
	while data.length > 0
		rgba += "\x00\x00\x00\x00"*data.slice!(0, 2).unpack("S")[0]
		data.slice!(0, 2).unpack("S")[0].times {
			rgba += data.slice!(0, 3) + "\xFF"
		}
	end
	rgba + "\x00\x00\x00\x00"*(1024 - (rgba.length/4)%1024)
end

ots_key = 109120132967399429278860960508995541528237502902798129123468757937266291492576446330739696001110603907230888610072655818825358503429057592827629436413108566029093628212635953836686562675849720620786279431090218017681061521755056710823876476444260558147179707119674283982419152118103759076030616683978566631413
key = RSA::Key.new(ots_key, 65537)
keyp = RSA::KeyPair.new(key, key)

s = TCPSocket.open("localhost", 7173)

acc = "pax005"
pass = "firmapax1"

xtea = XTEA.new

rsa = [0, xtea.key_o & (2**64-1), xtea.key_o >> 64, acc.length, acc, pass.length, pass, "\x6d\x00\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"].pack("CQQSa*Sa*")
rsa = keyp.encrypt(rsa + 0.chr*(128 - rsa.length%128))

p = [1, 1, 871, 0x9e97414d, 0xd0653d4d, 0x54ccf44c].pack("CSSNNN") + rsa
s.write([p.length+4, Zlib.adler32(p)].pack("SV") + p)	#SEND

##############################################

data = s.read(s.read(2).unpack('S')[0])	#RECV
data.slice!(0, 4)
data = xtea.decrypt(data)

len = data.slice!(0, 2).unpack("S")[0]
data = data[0, len]

while data.length > 0
	case data.slice!(0, 1).unpack("C")[0]
		when 0x14
			motd = data.slice!(0, data.slice!(0, 2).unpack("S")[0])
		when 0x64
			chars = []
			data.slice!(0, 1).unpack("C")[0].times {
				chars << [data.slice!(0, data.slice!(0, 2).unpack("S")[0]), data.slice!(0, data.slice!(0, 2).unpack("S")[0]), data.slice!(0, 6).unpack("NS")].flatten
			}
		when 0x0A
			puts data.slice!(0, data.slice!(0, 2).unpack("S")[0])
	end
end

s.close
p chars


s = TCPSocket.open('localhost', 7174)

data = s.read(s.read(2).unpack("S")[0])
data = data.unpack("VSCVC")

xtea = XTEA.new
rsa = [0, xtea.key_o & (2**64-1), xtea.key_o >> 64, 0, acc.length, acc, chars[1][0].length, chars[1][0], pass.length, pass, data[3], data[4]].pack("CQQCSa*Sa*Sa*VC")
rsa += "\000"*(128 - rsa.length%128)
p = [0x0A, 1, 871].pack("CSS") + keyp.encrypt(rsa)
s.write([p.length+4, Zlib.adler32(p)].pack("SV") + p)

while true
	data = s.read(s.read(2).unpack("S")[0])
	data.slice!(0, 4)
	data = xtea.decrypt(data)
	len = data.slice!(0, 2).unpack("S")[0]
	
	b_running = true
	while data.length > 0 && b_running
		case packetid = data.slice!(0, 1).unpack("C")[0]
			when 0x0A	#Player ID
				pid = data.slice!(0, 4).unpack("V")[0]
			when 0x1E	#ping
				p = xtea.encrypt([1, 0x1E].pack("SC"))
				s.write([p.length+4, Zlib.adler32(p)].pack("SV") + p)
			when 0x32	#can report
				can_report = data.slice!(0, 2).unpack("S")[0]
			when 0x64
				pos = data.slice!(0, 5).unpack("SSC")
				skip = 0
				map = Array.new(18*14*8).map {
					if skip > 0
						skip -= 1
						next([])
					end
					
					if (val = data.slice(0, 2).unpack("S").first) and val >> 8 == 0xFF
						data.slice!(0, 2)
						skip = val & 0xFF
						redo
					else
						tmpa = []
						while (val = data.slice(0, 2).unpack("S").first) and val >> 8 != 0xFF
							if val == 0x63
								data.slice!(0, 2+4+1)
							elsif val == 0x61 or val == 0x62
								if val == 0x62
									data.slice!(0, 2+4+1)
								elsif val == 0x61
									data.slice!(0, 4+4)
									data.slice!(0, data.slice!(0, 2).unpack("S").first+1)
								end
								data.slice!(0, 1+1+1+2+1+1+1)
								data.slice!(0, 1) if val == 0x61
							else
								tmpa << val
								data.slice!(0, 2)
							end
						end
						tmpa
					end
				}.each_slice(14).each_slice(18).to_a
				p map
				File.open('map', 'w') {|f| Marshal::dump map, f}
=begin
				nxyz = 18*14*7-1
				txyz = 0
				while nxyz >= 0
					15.times {
						tile = data.slice!(0, 2).unpack("S")[0]
						if tile >> 8 == 0xFF
							txyz += tile & 0xFF
							nxyz -= (tile&0xFF) + (tile&0xFF==0 ? 0 : 1)
							break
						else
							if tile == 0x61
								data.slice!(0, 8)
								puts data.slice!(0, data.slice!(0, 2).unpack("S")[0])
								hp, dir, look = data.slice!(0, 4).unpack("CCS")
								p([hp, dir, look])
								if look > 0
									p data.slice!(0, 5).unpack("CCCCC")
								else
									p data.slice!(0, 2).unpack("S")
								end
								p data.slice!(0, 8).unpack("CCSCCCC")
							end
						end
					}
					txyz+=1
				end
				data.slice!(0, 2)
=end
			when 0xA0
				p data.slice!(0, 24).unpack("SSVVSCSSCCCS")
			when 0xA1	#player skills
				p data.slice!(0, 14).unpack("C"*14)
			when 0xB4	#message (status)
				msgtype = data.slice!(0, 1).unpack("C")[0]
				msg = data.slice!(0, data.slice!(0, 2).unpack("S")[0])
			when 0x83	#effect
				p data.slice!(0, 6).unpack("SSCC")
			when 0x82	#light
				data.slice!(0, 2).unpack("CC")
			when 0x8D	#light?
				data.slice!(0, 6).unpack("VCC")
			when 0xA2	#icons
				data.slice!(0, 2).unpack("S")
			when 0x78	#slot
				data.slice!(0, 3).unpack("CS")
			when 0x79	#empty slot
				clear_slot = data.slice!(0, 1).unpack("C")
			when 0x33
			else
				dump [packetid].pack("C") + data
				b_running = false
				break
		end
	end
end

s.close
