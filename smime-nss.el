;;; smime-nss.el --- S/MIME support using NSS -*- lexical-binding: t; -*-

;; Copyright (C) 2016 Free Software Foundation, Inc.

;; Author: Daiki Ueno <ueno@gnu.org>
;; Keywords: S/MIME, NSS

;; This file is part of GNU Emacs.

;; GNU Emacs is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; GNU Emacs is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with GNU Emacs.  If not, see <http://www.gnu.org/licenses/>.

;;; Commentary:

;; This library perform cryptographic operations on a messasge in the
;; CMS (Cryptographic Message Syntax) format.
;;
;; It uses the "cmsutil" and "signver" commands from NSS.  To import
;; certificates or private keys into `smime-nss-database-directory', use
;; "certutil" and "pk12util".
;;
;; For example, to import CAcert root certificates and mark it trusted
;; as CA, do:
;;
;;   certutil -A -d <directory> -n 'CAcert root' -t 'TCu,Cu,Tu' -i root.txt
;;
;; to import your private key, do:
;;
;;   pk12util -i your-key.p12 -d <directory>

;;; Code:

(require 'cl-lib)
(require 'password-cache)

(defgroup smime-nss nil
  "S/MIME configuration, specific to NSS."
  :group 'smime)

(defcustom smime-nss-database-directory
  (expand-file-name "nss" user-emacs-directory)
  "Directory that holds the database of certificates and private keys."
  :type 'directory
  :group 'smime-nss)

(defcustom smime-nss-cmsutil-program "cmsutil"
  "Name of \"cmsutil\" executable."
  :type 'string
  :group 'smime-nss)

(defcustom smime-nss-signver-program "signver"
  "Name of \"signver\" executable."
  :type 'string
  :group 'smime-nss)

(defvar smime-nss-error-buffer nil)
(defvar smime-nss-read-point nil)
(defvar smime-nss-context nil)

(cl-defstruct (smime-nss-context
	       (:constructor nil)
	       (:constructor smime-nss-make-context (program))
	       (:copier nil)
               (:predicate nil))
  program
  process
  error-process)

(defun smime-nss--reset-process-buffer (buffer context)
  (with-current-buffer buffer
    (if (fboundp 'set-buffer-multibyte)
        (set-buffer-multibyte nil))
    (make-local-variable 'smime-nss-read-point)
    (setq smime-nss-read-point (point-min))
    (make-local-variable 'smime-nss-context)
    (setq smime-nss-context context)))

(defun smime-nss--start-program (context args)
  "Start context's program in a subprocess with given ARGS."
  (if (and (smime-nss-context-process context)
	   (eq (process-status (smime-nss-context-process context)) 'run))
      (error "%s is already running in this context"
	     (smime-nss-context-program context)))
  (let ((buffer (generate-new-buffer " *smime-nss*"))
        (error-buffer (generate-new-buffer " *smime-nss-error*"))
	process
        error-process)
    (smime-nss--reset-process-buffer buffer context)
    (smime-nss--reset-process-buffer error-buffer context)
    (setq error-process
	  (make-pipe-process :name "smime-nss-error"
			     :buffer error-buffer
			     ;; Suppress "XXX finished" line.
			     :sentinel #'ignore
			     :noquery t))
    (setf (smime-nss-context-error-process context) error-process)
    (with-file-modes 448
      (setq process (make-process :name (file-name-nondirectory
					 (smime-nss-context-program context))
				  :buffer buffer
				  :command (cons (smime-nss-context-program
						  context)
						 args)
				  :connection-type 'pipe
				  :coding '(binary . binary)
				  :stderr error-process
                                  ;; Suppress "XXX finished" line.
                                  :sentinel #'ignore
				  :noquery t)))
    (setf (smime-nss-context-process context) process)))

(defun smime-nss--wait-for-completion (context)
  "Wait until context's process completes."
  (while (eq (process-status (smime-nss-context-process context)) 'run)
    (accept-process-output (smime-nss-context-process context) 1))
  ;; This line is needed to run the process-filter right now.
  (sleep-for 0.1))

(defun smime-nss--reset (context)
  "Reset the CONTEXT."
  (when (and (smime-nss-context-process context)
	     (buffer-live-p (process-buffer
			     (smime-nss-context-process context))))
    (kill-buffer (process-buffer (smime-nss-context-process context))))
  (when (and (smime-nss-context-error-process context)
	     (buffer-live-p (process-buffer
			     (smime-nss-context-error-process context))))
    (kill-buffer (process-buffer (smime-nss-context-error-process context)))))

(defun smime-nss--display-error (context)
  (let ((buffer (get-buffer-create "*Error*")))
      (save-selected-window
	(unless (and smime-nss-error-buffer
                     (buffer-live-p smime-nss-error-buffer))
	  (setq smime-nss-error-buffer (generate-new-buffer "*Error*")))
	(if (get-buffer-window smime-nss-error-buffer)
	    (delete-window (get-buffer-window smime-nss-error-buffer)))
	(with-current-buffer buffer
	  (let ((inhibit-read-only t)
		buffer-read-only)
	    (erase-buffer)
            (insert-buffer-substring
             (process-buffer (smime-nss-context-error-process context))))
	  (special-mode)
	  (goto-char (point-min)))
	(display-buffer buffer))))

(defun smime-nss-decrypt-string (cipher)
  "Decrypt S/MIME message CIPHER and return the decrypted content as string."
  (let ((context (smime-nss-make-context smime-nss-cmsutil-program))
        (password (read-passwd "Password for NSS database: ")))
    (unwind-protect
	(progn
	  (smime-nss--start-program
           context
           (list "-D" "-d" smime-nss-database-directory
                 "-p" password))
	  (process-send-string (smime-nss-context-process context) cipher)
	  (process-send-eof (smime-nss-context-process context))
	  (smime-nss--wait-for-completion context)
	  (pcase (process-status (smime-nss-context-process context))
	    ((and `exit
                  (guard (zerop (process-exit-status
                                 (smime-nss-context-process context)))))
	     (with-current-buffer (process-buffer
				   (smime-nss-context-process context))
	       (buffer-string)))
	    (_
	     (smime-nss--display-error context))))
      (clear-string password)
      (smime-nss--reset context))))

(defun smime-nss--find-signer-subjects (signer-infos certificates)
  (delq nil
        (mapcar
         (lambda (signer-info)
           (let ((issuer (cdr (assoc "issuerName" signer-info)))
                 (serial (cdr (assoc "serialNumber" signer-info))))
             (when (and issuer serial)
               (let ((certificate
                      (cl-find-if
                       (lambda (certificate)
                         (let ((cert-issuer
                                (cdr (assoc "data.issuerName"
                                            certificate)))
                               (cert-serial
                                (cdr (assoc "data.serialNumber"
                                            certificate))))
                           (when (and (equal cert-issuer issuer)
                                      (equal cert-serial serial))
                             certificate)))
                       certificates)))
                 (list (cdr (assoc "data.subject" certificate))
                       (cdr (assoc "data.issuerName" certificate))
                       (cdr (assoc "data.serialNumber" certificate)))))))
         signer-infos)))

(defun smime-nss--parse-verify-output ()
  (let (valid certificates signer-infos)
    (goto-char (point-min))
    (while (not (eobp))
      (when (looking-at "\\([^=]+\\)=\\(.*\\)")
        (let ((key (match-string 1))
              (value (match-string 2)))
        (pcase key
          ("signatureValid"
           (when (equal value "yes")
             (setq valid t)))
          ((pred
            (string-match "\\`certificate\\[\\([[:digit:]]+\\)\\]\\."))
           (let* ((number (string-to-number (match-string 1 key)))
                  (string (substring key (match-end 0)))
                  (entry (assq number certificates)))
             (unless entry
               (setq entry (list number))
               (push entry certificates))
             (push (cons string value) (cdr entry))))
          ((pred
            (string-match "\\`signerInformation\\[\\([[:digit:]]+\\)\\]\\."))
           (let* ((number (string-to-number (match-string 1 key)))
                  (string (substring key (match-end 0)))
                  (entry (assq number signer-infos)))
             (unless entry
               (setq entry (list number))
               (push entry signer-infos))
             (push (cons string value) (cdr entry)))))))
      (beginning-of-line 2))
    (setq certificates (mapcar #'cdr certificates)
          signer-infos (mapcar #'cdr signer-infos))
    (cons valid
          (smime-nss--find-signer-subjects signer-infos certificates))))

(defun smime-nss-verify-string (text signature)
  "Verify S/MIME signature SIGNATURE against TEXT.

It returns a cons in the form of (VALID . SIGNERS), where VALID
indicates if the signature is valid or not, and SIGNERS contains
a list of signers in the form of (SUBJECT ISSUER-NAME SERIAL-NUMBER)."
  (let ((context (smime-nss-make-context smime-nss-signver-program))
        (tempfile (with-file-modes 448 (make-temp-file "smime-nss")))
        (coding-system-for-write 'binary))
    (unwind-protect
	(progn
          (write-region text nil tempfile nil 'quiet)
	  (smime-nss--start-program
           context
           (list "-V" "-A" "-d" smime-nss-database-directory "-i" tempfile))
	  (process-send-string (smime-nss-context-process context) signature)
	  (process-send-eof (smime-nss-context-process context))
	  (smime-nss--wait-for-completion context)
	  (pcase (process-status (smime-nss-context-process context))
	    ((and `exit
                  (guard (zerop (process-exit-status
                                 (smime-nss-context-process context)))))
	     (with-current-buffer (process-buffer
				   (smime-nss-context-process context))
               (smime-nss--parse-verify-output)))
	    (_
	     (smime-nss--display-error context))))
      (smime-nss--reset context)
      (and tempfile
           (file-exists-p tempfile)
           (delete-file tempfile)))))

(defun smime-nss-sign-string (text signers)
  "Create a detached S/MIME signature from TEXT for SIGNERS."
  (let ((context (smime-nss-make-context smime-nss-cmsutil-program))
        (password (read-passwd "Password for NSS database: ")))
    (unwind-protect
	(progn
	  (smime-nss--start-program
           context
           (append (list "-S" "-d" smime-nss-database-directory "-T"
                         "-p" password)
                   (apply #'nconc (mapcar (lambda (signer)
                                            (list "-N" signer))
                                          signers))))
	  (process-send-string (smime-nss-context-process context) text)
	  (process-send-eof (smime-nss-context-process context))
	  (smime-nss--wait-for-completion context)
	  (pcase (process-status (smime-nss-context-process context))
	    ((and `exit
                  (guard (zerop (process-exit-status
                                 (smime-nss-context-process context)))))
	     (with-current-buffer (process-buffer
				   (smime-nss-context-process context))
               (buffer-string)))
	    (_
	     (smime-nss--display-error context))))
      (clear-string password)
      (smime-nss--reset context))))

(defun smime-nss-encrypt-string (plain recipients)
  "Encrypt PLAIN and create an S/MIME message for RECIPIENTS."
  (let ((context (smime-nss-make-context smime-nss-cmsutil-program)))
    (unwind-protect
	(progn
	  (smime-nss--start-program
           context
           (append (list "-E" "-d" smime-nss-database-directory)
                   (apply #'nconc
                          (mapcar (lambda (recipient)
                                    (list "-r" recipient))
                                  recipients))))
	  (process-send-string (smime-nss-context-process context) plain)
	  (process-send-eof (smime-nss-context-process context))
	  (smime-nss--wait-for-completion context)
	  (pcase (process-status (smime-nss-context-process context))
	    ((and `exit
                  (guard (zerop (process-exit-status
                                 (smime-nss-context-process context)))))
	     (with-current-buffer (process-buffer
				   (smime-nss-context-process context))
	       (buffer-string)))
	    (_
	     (smime-nss--display-error context))))
      (smime-nss--reset context))))

(provide 'smime-nss)

;;; smime-nss.el ends here
