" hadafs.vim: GNU Vim Syntax file for HADAFS .vol specification
" Copyright (C) 2007-2009 HADA, Inc. <http://www.hada.com>
" This file is part of HADAFS.
"
" HADAFS is free software; you can redistribute it and/or modify
" it under the terms of the GNU General Public License as published
" by the Free Software Foundation; either version 3 of the License,
" or (at your option) any later version.
"
" HADAFS is distributed in the hope that it will be useful, but
" WITHOUT ANY WARRANTY; without even the implied warranty of
" MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
" General Public License for more details.
"
" You should have received a copy of the GNU General Public License
" along with this program.  If not, see
" <http://www.gnu.org/licenses/>.
"
" Last Modified: Wed Aug  1 00:47:10 IST 2007
" Version: 0.8 

syntax clear
syntax case match

setlocal iskeyword+=-
setlocal iskeyword+=%
setlocal iskeyword+=.
setlocal iskeyword+=*
setlocal iskeyword+=:
setlocal iskeyword+=,


"************************************************************************
" Initially, consider everything an error. Then start eliminating one
"   field after the other. Whatever is not eliminated (due to defined
"   properties) is an error - Multiples Values for a key
"************************************************************************
syn match hadafsError /[^ 	]\+/ skipwhite
syn match hadafsComment "#.*" contains=hadafsTodo

syn keyword	hadafsTodo	contained TODO FIXME NOTE

"------------------------------------------------------------------------
" 'Type' Begin
"------------------------------------------------------------------------
" Handle all the 'Type' keys and values. Here, a '/' is used to separate
" the key-value pair, they are clubbed together for convenience
syn match hadafsType "^\s*type\s\+" skipwhite nextgroup=hadafsTypeKeyVal

syn match hadafsTypeKeyVal contained "\<protocol/\(client\|server\)\>"
syn match hadafsTypeKeyVal contained "\<cluster/\(unify\|afr\|stripe\)\>"
syn match hadafsTypeKeyVal contained "\<debug/\(trace\)\>"
syn match hadafsTypeKeyVal contained "\<encryption/\(rot-13\)\>"
syn match hadafsTypeKeyVal contained "\<storage/\(posix\)\>"
"syn match hadafsTypeKeyVal contained "\<features/\(trash\)\>"
syn match hadafsTypeKeyVal contained "\<features/\(trash\|posix-locks\|fixed-id\|filter\)\>"
syn match hadafsTypeKeyVal contained "\<performance/\(io-threads\|write-behind\|io-cache\|read-ahead\)\>"
"------------------------------------------------------------------------
" 'Type' End
"------------------------------------------------------------------------


"************************************************************************

"------------------------------------------------------------------------
" 'Volume' Begin
"------------------------------------------------------------------------
" NOTE 1: Only one volume name allowed after 'volume' keyword
" NOTE 2: Multiple volumes allowed after 'subvolumes'
" NOTE 3: Some other options (like remote-subvolume, namespace etc) use
"   volume name (single)
syn match hadafsVol "^\s*volume\s\+" nextgroup=hadafsVolName
syn match hadafsVolName "\<\k\+" contained

syn match hadafsVol "^\s*subvolumes\s\+" skipwhite nextgroup=hadafsSubVolName
syn match hadafsSubVolName "\<\k\+\>" skipwhite contained nextgroup=hadafsSubVolName

syn match hadafsVol "^\s*end-volume\>"
"------------------------------------------------------------------------
" 'Volume' End
"------------------------------------------------------------------------





"------------------------------------------------------------------------
" 'Options' Begin
"------------------------------------------------------------------------
syn match hadafsOpt "^\s*option\s\+" nextgroup=hadafsOptKey


syn keyword hadafsOptKey contained transport-type skipwhite nextgroup=hadafsOptValTransportType
syn match hadafsOptValTransportType contained "\<\(tcp\|ib\-verbs\|ib-sdp\)/\(client\|server\)\>"

syn keyword hadafsOptKey contained remote-subvolume skipwhite nextgroup=hadafsVolName

syn keyword hadafsOptKey contained auth.addr.ra8.allow auth.addr.ra7.allow auth.addr.ra6.allow auth.addr.ra5.allow auth.addr.ra4.allow auth.addr.ra3.allow auth.addr.ra2.allow auth.addr.ra1.allow auth.addr.brick-ns.allow skipwhite nextgroup=hadafsOptVal

syn keyword hadafsOptKey contained client-volume-filename directory trash-dir skipwhite nextgroup=hadafsOpt_Path
syn match hadafsOpt_Path contained "\s\+\f\+\>"

syn keyword hadafsOptKey contained debug self-heal encrypt-write decrypt-read mandatory nextgroup=hadafsOpt_OnOff
syn match hadafsOpt_OnOff contained "\s\+\(on\|off\)\>"

syn keyword hadafsOptKey contained flush-behind non-blocking-connect nextgroup=hadafsOpt_OnOffNoYes
syn keyword hadafsOpt_OnOffNoYes contained on off no yes

syn keyword hadafsOptKey contained page-size cache-size nextgroup=hadafsOpt_Size

syn keyword hadafsOptKey contained fixed-gid fixed-uid cache-seconds page-count thread-count aggregate-size listen-port remote-port transport-timeout inode-lru-limit nextgroup=hadafsOpt_Number

syn keyword hadafsOptKey contained alu.disk-usage.entry-threshold alu.disk-usage.exit-threshold nextgroup=hadafsOpt_Size

syn keyword hadafsOptKey contained alu.order skipwhite nextgroup=hadafsOptValAluOrder
syn match hadafsOptValAluOrder contained "\s\+\(\(disk-usage\|write-usage\|read-usage\|open-files-usage\|disk-speed\):\)*\(disk-usage\|write-usage\|read-usage\|open-files-usage\|disk-speed\)\>"

syn keyword hadafsOptKey contained alu.open-files-usage.entry-threshold alu.open-files-usage.exit-threshold alu.limits.max-open-files rr.refresh-interval random.refresh-interval nufa.refresh-interval nextgroup=hadafsOpt_Number

syn keyword hadafsOptKey contained nufa.local-volume-name skipwhite nextgroup=hadafsVolName

syn keyword hadafsOptKey contained ib-verbs-work-request-send-size ib-verbs-work-request-recv-size nextgroup=hadafsOpt_Size
syn match hadafsOpt_Size contained "\s\+\d\+\([gGmMkK][bB]\)\=\>"

syn keyword hadafsOptKey contained ib-verbs-work-request-send-count ib-verbs-work-request-recv-count ib-verbs-port nextgroup=hadafsOpt_Number

syn keyword hadafsOptKey contained ib-verbs-mtu nextgroup=hadafsOptValIBVerbsMtu
syn match hadafsOptValIBVerbsMtu "\s\+\(256\|512\|1024\|2048\|4096\)\>" contained

syn keyword hadafsOptKey contained ib-verbs-device-name nextgroup=hadafsOptVal

syn match hadafsOpt_Number contained "\s\+\d\+\>"

syn keyword hadafsOptKey contained scheduler skipwhite nextgroup=hadafsOptValScheduler
syn keyword hadafsOptValScheduler contained rr alu random nufa

syn keyword hadafsOptKey contained namespace skipwhite nextgroup=hadafsVolName

syn keyword hadafsOptKey contained lock-node skipwhite nextgroup=hadafsVolName



syn keyword hadafsOptKey contained alu.write-usage.entry-threshold alu.write-usage.exit-threshold alu.read-usage.entry-threshold alu.read-usage.exit-threshold alu.limits.min-free-disk nextgroup=hadafsOpt_Percentage

syn keyword hadafsOptKey contained random.limits.min-free-disk nextgroup=hadafsOpt_Percentage
syn keyword hadafsOptKey contained rr.limits.min-disk-free nextgroup=hadafsOpt_Size

syn keyword hadafsOptKey contained nufa.limits.min-free-disk nextgroup=hadafsOpt_Percentage

syn match hadafsOpt_Percentage contained "\s\+\d\+%\=\>"









syn keyword hadafsOptKey contained remote-host bind-address nextgroup=hadafsOpt_IP,hadafsOpt_Domain
syn match hadafsOpt_IP contained "\s\+\d\d\=\d\=\.\d\d\=\d\=\.\d\d\=\d\=\.\d\d\=\d\=\>"
syn match hadafsOpt_Domain contained "\s\+\a[a-zA-Z0-9_-]*\(\.\a\+\)*\>"

syn match hadafsVolNames "\s*\<\S\+\>" contained skipwhite nextgroup=hadafsVolNames

syn keyword hadafsOptKey contained block-size replicate skipwhite nextgroup=hadafsOpt_Pattern

syn match hadafsOpt_Pattern contained "\s\+\k\+\>"
syn match hadafsOptVal contained "\s\+\S\+\>"





hi link hadafsError Error
hi link hadafsComment Comment

hi link hadafsVol keyword

hi link hadafsVolName function
hi link hadafsSubVolName function

hi link hadafsType Keyword
hi link hadafsTypeKeyVal String

hi link hadafsOpt Keyword

hi link hadafsOptKey Special
hi link hadafsOptVal Normal

hi link hadafsOptValTransportType String
hi link hadafsOptValScheduler String
hi link hadafsOptValAluOrder String
hi link hadafsOptValIBVerbsMtu String

hi link hadafsOpt_OnOff String
hi link hadafsOpt_OnOffNoYes String


" Options that require
hi link hadafsOpt_Size PreProc
hi link hadafsOpt_Domain PreProc
hi link hadafsOpt_Percentage PreProc
hi link hadafsOpt_IP PreProc
hi link hadafsOpt_Pattern PreProc
hi link hadafsOpt_Number Preproc
hi link hadafsOpt_Path Preproc



let b:current_syntax = "hadafs"
