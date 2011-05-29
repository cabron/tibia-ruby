#!/usr/bin/env ruby
require 'enumerator'
require 'rubygems'
require 'sys/proctable'

if not proc = Sys::ProcTable.ps.select {|e| e.name == "Tibia"}.first
	puts "Not found"
	exit
end

pmap = `pmap #{proc.pid}`
m = pmap.scan(/([0-9a-f]+)\s+([0-9]+)K\s+r[w-][x-]--\s+./)[0, 4]
dumps = m.enum_for(:each_with_index).collect {|e, i| "dump binary memory .dump#{i}.bin 0x#{e[0]} 0x#{(e[0].to_i(16) + e[1].to_i*1024).to_s 16}\n"}.join

File.open('.findcmds', 'w') {|f|
	f.write(%{
		attach #{proc.pid}
		#{dumps}
		detach
		quit})
}

puts "Dumping from #{proc.pid}"

`gdb -x .findcmds`
File.delete(".findcmds")

data = []

4.times {|i|
	File.open(".dump#{i}.bin") {|f|
		str = f.read
		off = m[i][0].to_i(16)
		
		if match = str.match(/[0-9]{20,}/)
			data << ["RSA", match.offset(0)[0] + off]
		end
		str.scan(/login[0-9]+\.tibia\.com|tibia[0-9]+\.cipsoft\.com/) {|c| data << [c, $~.offset(0)[0] + off]}
	}
	#File.delete(".dump#{i}.bin")
}

data.each {|d|
	puts "#{d[0]}\t0x#{d[1].to_s 16}"
}