class XTEA
	attr_reader :key, :key_o
	
	MASK = 0xFFFFFFFF
	DELTA = 0x9E3779B9
	
	def initialize(key=rand(2**128), n=32)
		@key_o = key
		@n = n
		
		if key.class == Bignum
			@key = [key & MASK, key>>32 & MASK, key>>64 & MASK, key>>96 & MASK]
		elsif key.class == String
			@key = key.unpack('LLLL')
		end
	end
	
	def decrypt(s)
		s.unpack('L*').each_slice(2).to_a.each {|v|
			sum = (DELTA*@n) & MASK
			@n.times {
				v[1] = (v[1] - (((v[0]<<4 ^ v[0]>>5) + v[0]) ^ (sum + @key[sum>>11 & 3]))) & MASK
				sum = (sum - DELTA) & MASK
				v[0] = (v[0] - (((v[1]<<4 ^ v[1]>>5) + v[1]) ^ (sum + @key[sum & 3]))) & MASK
			}
		}[0].pack('L*')
	end
	
	def encrypt(s)
		s.unpack('L*').each_slice(2).to_a.each {|v|
			sum = 0
			@n.times {
				v[0] = (v[0] + (((v[1]<<4 ^ v[1]>>5) + v[1]) ^ (sum + @key[sum & 3]))) & MASK
				sum = (sum + DELTA) & MASK
				v[1] = (v[1] + (((v[0]<<4 ^ v[0]>>5) + v[0]) ^ (sum + @key[sum>>11 & 3]))) & MASK
			}
		}[0].pack('L*')
	end
end
