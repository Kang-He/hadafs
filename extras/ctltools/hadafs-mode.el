;;; Copyright (C) 2007-2009 HADA Inc. <http://www.hada.com>
;;;  
;;; This program is free software; you can redistribute it and/or modify
;;; it under the terms of the GNU General Public License as published by
;;; the Free Software Foundation; either version 2 of the License, or
;;; (at your option) any later version.
;;;  
;;; This program is distributed in the hope that it will be useful,
;;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;; GNU General Public License for more details.
;;;  
;;; You should have received a copy of the GNU General Public License
;;; along with this program; if not, write to the Free Software
;;; Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
;;;  

(defvar hadafs-mode-hook nil)

;; (defvar hadafs-mode-map
;;   (let ((hadafs-mode-map (make-keymap)))
;;     (define-key hadafs-mode-map "\C-j" 'newline-and-indent)
;;     hadafs-mode-map)
;;   "Keymap for WPDL major mode")

(add-to-list 'auto-mode-alist '("\\.vol\\'" . hadafs-mode))

(defconst hadafs-font-lock-keywords-1
  (list
					; "cluster/{unify,afr,stripe}" 
					; "performance/{io-cache,io-threads,write-behind,read-ahead,stat-prefetch}"
					; "protocol/{client/server}"
					; "features/{trash,posix-locks,fixed-id,filter}"
					; "stroage/posix"
					; "encryption/rot-13"
					; "debug/trace"
    '("\\<\\(cluster/\\(unify\\|afr\\|replicate\\|stripe\\|ha\\|dht\\|distribute\\)\\|\\performance/\\(io-\\(cache\\|threads\\)\\|write-behind\\|read-ahead\\|symlink-cache\\)\\|protocol/\\(server\\|client\\)\\|features/\\(trash\\|posix-locks\\|locks\\|path-converter\\|filter\\)\\|storage/\\(posix\\|bdb\\)\\|encryption/rot-13\\|debug/trace\\)\\>" . font-lock-keyword-face))
"Additional Keywords to highlight in HADAFS mode.")

(defconst hadafs-font-lock-keywords-2
  (append hadafs-font-lock-keywords-1
	  (list
      ; "replicate" "namespace" "scheduler" "remote-subvolume" "remote-host" 
      ; "auth.addr" "block-size" "remote-port" "listen-port" "transport-type"
      ; "limits.min-free-disk" "directory"
	; TODO: add all the keys here.
	   '("\\<\\(inode-lru-limit\\|replicate\\|namespace\\|scheduler\\|username\\|password\\|allow\\|reject\\|block-size\\|listen-port\\|transport-type\\|transport-timeout\\|directory\\|page-size\\|page-count\\|aggregate-size\\|non-blocking-io\\|client-volume-filename\\|bind-address\\|self-heal\\|read-only-subvolumes\\|read-subvolume\\|thread-count\\|cache-size\\|window-size\\|force-revalidate-timeout\\|priority\\|include\\|exclude\\|remote-\\(host\\|subvolume\\|port\\)\\|auth.\\(addr\\|login\\)\\|limits.\\(min-disk-free\\|transaction-size\\|ib-verbs-\\(work-request-\\(send-\\|recv-\\(count\\|size\\)\\)\\|port\\|mtu\\|device-name\\)\\)\\)\ \\>" . font-lock-constant-face)))
  "option keys in HADAFS mode.")

(defconst hadafs-font-lock-keywords-3
  (append hadafs-font-lock-keywords-2
	  (list
					; "option" "volume" "end-volume" "subvolumes" "type"
	   '("\\<\\(option\ \\|volume\ \\|subvolumes\ \\|type\ \\|end-volume\\)\\>" . font-lock-builtin-face)))
					;'((regexp-opt (" option " "^volume " "^end-volume" "subvolumes " " type ") t) . font-lock-builtin-face))
  "Minimal highlighting expressions for HADAFS mode.")


(defvar hadafs-font-lock-keywords hadafs-font-lock-keywords-3
  "Default highlighting expressions for HADAFS mode.")

(defvar hadafs-mode-syntax-table
  (let ((hadafs-mode-syntax-table (make-syntax-table)))
    (modify-syntax-entry ?\# "<"  hadafs-mode-syntax-table)
    (modify-syntax-entry ?* ". 23"  hadafs-mode-syntax-table)
    (modify-syntax-entry ?\n ">#"  hadafs-mode-syntax-table)
    hadafs-mode-syntax-table)
  "Syntax table for hadafs-mode")

;; TODO: add an indentation table

(defun hadafs-indent-line ()
  "Indent current line as HADAFS code"
  (interactive)
  (beginning-of-line)
  (if (bobp)
      (indent-line-to 0)   ; First line is always non-indented
    (let ((not-indented t) cur-indent)
      (if (looking-at "^[ \t]*volume\ ")
	  (progn
	    (save-excursion
	      (forward-line -1)
	      (setq not-indented nil)
	      (setq cur-indent 0))))
      (if (looking-at "^[ \t]*end-volume")
	  (progn
	    (save-excursion
	      (forward-line -1)
	      (setq cur-indent 0))
	    (if (< cur-indent 0) ; We can't indent past the left margin
		(setq cur-indent 0)))
	(save-excursion
	  (while not-indented ; Iterate backwards until we find an indentation hint
	    (progn
	      (setq cur-indent 2) ; Do the actual indenting
	      (setq not-indented nil)))))
      (if cur-indent
	  (indent-line-to cur-indent)
	(indent-line-to 0)))))

(defun hadafs-mode ()
  (interactive)
  (kill-all-local-variables)
  ;; (use-local-map hadafs-mode-map)
  (set-syntax-table hadafs-mode-syntax-table)
  (set (make-local-variable 'indent-line-function) 'hadafs-indent-line)  
  (set (make-local-variable 'font-lock-defaults) '(hadafs-font-lock-keywords))
  (setq major-mode 'hadafs-mode)
  (setq mode-name "HADAFS")
  (run-hooks 'hadafs-mode-hook))

(provide 'hadafs-mode)
