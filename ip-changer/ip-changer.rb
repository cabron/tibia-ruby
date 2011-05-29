#!/usr/bin/env ruby

win = RUBY_PLATFORM =~ /win32/

require 'ini'
require 'rubygems'
require 'optparse'
require 'ostruct'
require 'ptrace'
if win
	require 'dl'
	require 'Win32API'
else
	require 'sys/proctable'
end
#http://otfans.net/archive/index.php/t-120805.html

rsa = '109120132967399429278860960508995541528237502902798129123468757937266291492576446330739696001110603907230888610072655818825358503429057592827629436413108566029093628212635953836686562675849720620786279431090218017681061521755056710823876476444260558147179707119674283982419152118103759076030616683978566631413'

class String
	def ljustmod(n, padstr="\0")
		ljust(length + 4-length%n, padstr)
	end
end

class Client
	attr_accessor :v
	
	def initialize(pid)
		@pid = pid
	end
	
	def changeIP(ip, port)
		
	end
	
	if win
		def attach
			if block_given?
				begin
					attach
					yield
				ensure
					detach
				end
			else
				ppid = 0.chr*4
				window, args = FindWindow.call(nil, 'Tibia') 
				GetWindowThreadProcessId.call(window, ppid)
				@h = OpenProcess.call(PROCESS_ALL_ACCESS, 0, ppid.unpack('L').first)
			end
		end
	
		def detach
			#CloseHandle.call(@h)
		end
	
		def [](addr)
			s = 0.chr*1024
			count = 0.chr*4
			ReadProcessMemory.call(@h, addr, s, s.length, count)
			s
		end
	
		def []=(addr, data)
			count = 0.chr*4
			case data
				when String:
					WriteProcessMemory.call(@h, addr, data+0.chr, data.length+1, count)
			end
		end
	else
		def attach
			if block_given?
				begin
					attach
					wait 0
					yield
				ensure
					detach
				end
			else
				ptrace(PTRACE_ATTACH, @pid, 0, 0)
			end
		end
	
		def detach
			ptrace(PTRACE_DETACH, @pid, 0, 0)
		end
	
		def [](addr)
			s = '....'
			ptrace(PTRACE_PEEKDATA, @pid, addr, s)
			s
		end
	
		def []=(addr, data)
		#	case data
		#		when String:
		p data
					data.ljustmod(4).unpack("V*").each_with_index {|x, i| ptrace(PTRACE_POKEDATA, @pid, addr+i*4, x)}
		#		when Fixnum:
		#			ptrace(PTRACE_POKEDATA, @pid, addr+i*4, data)
		#	end
		end
	end
end

ini = Ini.new('versions.ini')

if not proc = Sys::ProcTable.ps.select {|e| e.name == "Tibia"}.first
	puts "Tibia not found"
	exit
end

p proc.pid

client = Client.new(proc.pid)

o = OpenStruct.new
o.ip = 'localhost'
opt = OptionParser.new {|opts|
	opts.banner = "Usage: ip-chaner.rb [options] IP"
	
	opts.on('-c', '--cmd', 'Command-line only') do
		o.c = true
	end
	
	opts.on('-v', '--version VERSION', String, 'Specify client version') do |v|
		o.v = v
	end
	
	opts.on('--ip IP', String, 'Specify server IP') do |ip|
		o.ip = ip
	end
	
	opts.on('--port PORT', Integer, 'Specify server port') do |port|
		o.port = port
	end
	
	opts.on( '-h', '--help', 'Display this screen') do
		puts opts
		exit
	end
}
opt.parse!

if not o.v
	puts "Detecting version..."
	client.attach {
		if ver = ini.inihash.select {|k, v| client[v['RSA'].to_i(16)-1].match(/\000[0-9]{3}/)}.first
			o.v = ver[0]
			o.rsa = ini[o.v]['RSA'].to_i 16
			o.servers = ini[o.v]['Servers'].to_i
			o.portstep = ini[o.v]['PortStep'].to_i 16
			o.serverstep = ini[o.v]['ServerStep'].to_i 16
			o.loginservers = ini[o.v]['LoginServersStart'].to_i 16
		end
	}
	
	if not o.v
		puts "Version cannot be recognized"
		exit
	end
end

puts "### #{o.v} #{proc.pid}"

client.attach {
	o.servers.times {|i| client[o.loginservers + i*o.serverstep] = o.ip}
	client[o.rsa] = rsa
	sss = ''
	100.times do |i| sss << client[o.loginservers+i*4] end
	p sss
}
