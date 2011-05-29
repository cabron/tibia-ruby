#!/usr/bin/env ruby

PTRACE_TRACEME	=  	0
PTRACE_PEEKTEXT	=	1
PTRACE_PEEKDATA	=	2
PTRACE_POKEDATA	=   5

PTRACE_ATTACH	=	16
PTRACE_DETACH	=	17

#sys_ptrace = 26
#sys_waitpid = 7

def ptrace *arg
	syscall(26, *arg)
end

def wait status
	syscall(7, -1, status, 0)
end
