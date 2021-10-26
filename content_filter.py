#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Date: 2019/8/2
# content_filter by H.Shirouzu
#

# content_filter.py の使い方
#
# 1. 設定ファイル（spam_dat.py）を適宜、変更します。
#
# 2. content_filter.py を起動します。
#
# 3. master.cf の smtp行を下記に書き換えます。
#
#    smtp      inet  n       -       n       -       20      smtpd
#         -o smtpd_proxy_filter=127.0.0.1:60025
#         -o smtpd_client_connection_count_limit=20
#
# 4. master.cf に下記を追記します。
#    127.0.0.1:60026 inet n  -       n       -        -      smtpd
#            -o smtpd_authorized_xforward_hosts=127.0.0.0/8
#            -o smtpd_recipient_restrictions=permit_mynetworks,reject
#            -o smtpd_data_restrictions=permit_mynetworks
#            -o mynetworks=127.0.0.0/8
#
# 5. Postfix をリスタートします。
#
# 6. syslog(mail.log) の content_filter出力を確認します。
#
#
# 参考:「Postfix キュー投入前コンテンツフィルタ」
#   http://www.postfix-jp.info/trans-2.2/jhtml/SMTPD_PROXY_README.html
#

VER = "0.65"

import sys
import time
import os
import re
import syslog
import traceback
import signal

import select
import _thread
import socket
import base64
import quopri
import importlib
import getopt
import email.header

sys.path.append("/etc/postfix/")
import spam_dat

# 汎用オブジェクトクラス
class Obj:
	def __init__(self, **kw): self.__dict__.update(kw)
	def __repr__(self): return "Obj: " + self.__dict__.__repr__()

# 定数定義
STD_ENC, QP_ENC, B64_ENC = range(3)
HEADER_PHASE, DATA_PHASE = range(2)

# グローバル設定データ類（loadcheck_spam_dat で設定）
G = Obj(
		WHITE_RE		= None,
		CHECK_RE		= None,
		DBG				= None,
		TMP_DIR			= None,
		SPAM_ERRCODE	= None,
		STAT			= None,

		# これは例外（スレッド数カウンタ）
		THR_CNT			= 0,
		IS_DAEMON		= True,
		VERBOSE			= False,
	)

# 正規表現の事前定義コンパイル
MSGID_RE = re.compile(rb'(?<=^Message-ID:)[ \t]*<.*>', re.IGNORECASE)
XFORWARD_RE = re.compile(rb'^XFORWARD[^\n]+\n', re.IGNORECASE)
RECEIVESPF_RE = re.compile(rb'^Received-SPF:', re.IGNORECASE)
SUBJECT_RE = re.compile(rb'Subject: ([^\r\n]+)')
FROM_RE    = re.compile(rb'From: ([^\r\n]+)')
TO_RE      = re.compile(rb'To: ([^\r\n]+)')

def bytes2str(s):
	try:
		s = str(s, "utf8")
	except:
		s = str(s)
	return s

# syslog & 画面出力
def putlog(s, only_print=False):
	try:
		if type(s) != str:
			s = bytes2str(s)
		if not only_print and G.IS_DAEMON:
			syslog.syslog(s.strip('\r\n'))
		print(s)
	except:
		pass

def time_to_str(t):
	if not t or t.t == 0: return "0"
	return	time.strftime("%Y%m%d_%H%M%S", time.localtime(t.t)) + ("_%d" % t.idx)

def smtp_fname(t):
	return "smtp_%s.txt" % time_to_str(t)

def spam_fname(t):
	return "spam_%s.txt" % time_to_str(t)

def sdec_fname(t):
	return "sdec_%s.txt" % time_to_str(t)

# ログファイル出力(& syslog)
def write_log(t, smtp_data, msg_id):
	fname = tmppath(smtp_fname(t))
	putlog("smtp_log for msg_id=%s to %s" % (bytes2str(msg_id), fname))
	f = open(fname, "wb")
	f.write(smtp_data)


# SMTPデータ等の保存パス生成
def tmppath(fname):
	if not os.access(G.TMP_DIR, os.F_OK):
		os.mkdir(G.TMP_DIR)
	return	os.path.join(G.TMP_DIR, fname)

# SMTPデータ等の保存パス生成
def check_head(L, head_phase, enc_mode, boundary):
	bound_key = b'boundary='
	enc_key = b'Content-Transfer-Encoding:'
	cur_bs = boundary and boundary[-1] or b''

	if cur_bs and L[:len(cur_bs)] == cur_bs:
		head_phase = True
		enc_mode = STD_ENC
		if L[len(cur_bs):][:2] == b'--':
			boundary.pop(-1)
	elif head_phase:
		idx = L.find(bound_key)
		if idx > 0:
			bs = L[idx + len(bound_key):]
			bs = b'--' + bs.strip(b'"\r\n')
			boundary.append(bs)
		elif L == b'\r' or L == b'':
			head_phase = False
		elif L[:len(enc_key)] == enc_key:
			if L.lower().find(b'quoted-printable') >= 0:
				enc_mode = QP_ENC
			elif L.lower().find(b'base64') >= 0:
				enc_mode = B64_ENC
			else:
				enc_mode = STD_ENC

	return	head_phase, enc_mode, boundary

# メールの MIMEパート毎の base64 / quoted-printable のデコード
# （なお、文字コードはそのまま）
def decode_mail(s):
	ll = s.split(b'\n')
	d = []
	enc_mode = STD_ENC
	head_phase = True
	boundary = []
	msg_id = b''

	for L in ll:
		head_phase, enc_mode, boundary = check_head(L, head_phase, enc_mode, boundary)
		# putlog("%s %s %s %s" % (str(head_phase), enc_mode, boundary, str(L)), True)

		if not msg_id and head_phase:
			m = MSGID_RE.search(L)
			if m:
				msg_id = m.group().strip()

		try:
			# 分割されたheader行の連結
			if head_phase and len(L) > 0 and b'\t '.find(L[0:1]) >= 0 and len(d) > 0 and d[-1][-1:] == b'\r':
				d[-1] = d[-1][:-1]

			if enc_mode == STD_ENC or head_phase or L == b'\r':
				d.append(L)
			elif enc_mode == B64_ENC:
				d.append(base64.decodebytes(L))
			elif enc_mode == QP_ENC:
				s = quopri.decodestring(L)
				d.append(s)
			else:
				d.append(L)
		except:
			d.append(L)

	msg = b''.join(d)
	msg = msg.replace(b'\n', b'')
	msg = msg.replace(b'\r', b'\r\n')

	head, body = msg.split(b'\r\n\r\n', 1)

	for r in [SUBJECT_RE, FROM_RE, TO_RE]:
		head = replace_re_data(r, head)

	msg = head + body

	return	msg, msg_id

def strip_ln(s):
	return s.replace(b'\r\n', b' ').replace(b'\n', b' ').replace(b'\r', b' ')

# 正規表現リストのマッチ検査
def is_match(data, re_list):
	for re_i, ll in enumerate(re_list):
		m = []
		for L in ll:
			r = L.search(data)
			if r:
				m.append(strip_ln(r.group(0)[:100]))
			else:
				break
		else:
			return	True, re_i, b", ".join(m)

	return	False, -1, b""

def replace_re_data(re_obj, data):
	ret = b''
	m = re_obj.search(data)
	if m:
		targ = m[0]
		try:
			dd = email.header.decode_header(targ.decode("utf8"))
			ss = b""
			for s, enc in dd:
				if enc:
					ss += s.decode(enc).encode("utf8")
				else:
					ss += s
			data = data[:m.start()] + ss + data[m.end():]
		except Exception as e:
			# print("exp", e)
			pass
	return data

def get_re_data(re_obj, data):
	ret = b''
	m = re_obj.search(data)
	if m:
		ret = m.groups()[0]
		try:
			dd = email.header.decode_header(ret.decode("utf8"))
			ss = b""
			for s, enc in dd:
				if enc:
					ss += s.decode(enc).encode("utf8")
				else:
					ss += s
			ret = ss
		except Exception as e:
			# print("exp", e)
			pass
	return ret


#スパム判定
def is_spam(data, msg_id, t):
	head = data.split(b'\r\n\r\n')[0]

	# ホワイトリスト検査
	ret, re_i, ms = is_match(head, G.WHITE_HEAD_RE)

	sdecfn = sdec_fname(t).encode("utf8")
	spamfn = spam_fname(t).encode("utf8")
	lim_num = G.VERBOSE and 1000 or 100

	if ret:
		putlog(b'pass-white f=%s msg_id=%s WHITE_HEAD(%d) = [ %.*s ] m=<%s>\r\n' % (sdecfn, msg_id, re_i, lim_num, strip_ln(b', '.join(G.WHITE_HEAD[re_i])), ms))
		return	False

	ret, re_i, ms = is_match(data, G.WHITE_RE)
	if ret:
		putlog(b'pass-white f=%s msg_id=%s WHITE_DATA(%d) = [ %.*s ] m=<%s>\r\n' % (sdecfn, msg_id, re_i, lim_num, strip_ln(b', '.join(G.WHITE_DATA[re_i])), ms))
		return	False

	# スパム検査
	ret, re_i, ms = is_match(head, G.CHECK_HEAD_RE)
	if ret:
		subject = get_re_data(SUBJECT_RE, data)
		from_s  = get_re_data(FROM_RE, data)
		to_s    = get_re_data(TO_RE, data)
		strip_s = strip_ln(b', '.join(G.CHECK_HEAD[re_i]))
		msg = b'SPAM is detected. f=%s msg_id=%s CHECK_HEAD(%d) = [ %.*s ] m=<%s> from=<%s> to=<%s> s=<%s>\r\n' % (spamfn, msg_id, re_i, lim_num, strip_s, ms, from_s, to_s, subject)
		putlog(msg)
		spam_log(msg, data, t)
		return True

	ret, re_i, ms = is_match(data, G.CHECK_RE)
	if ret:
		subject = get_re_data(SUBJECT_RE, data)
		from_s  = get_re_data(FROM_RE, data)
		to_s    = get_re_data(TO_RE, data)
		strip_s = strip_ln(b', '.join(G.CHECK_DATA[re_i]))
		msg = b'SPAM is detected. f=%s msg_id=%s CHECK_DATA(%d) = [ %.*s ] m=<%s> from=<%s> to=<%s> s=<%s>\r\n' % (spamfn, msg_id, re_i, lim_num, strip_s, ms, from_s, to_s, subject)
		putlog(msg)
		spam_log(msg, data, t)
		return True

	putlog(b'pass f=%s msg_id=%s' % (sdecfn, msg_id))
	return	False

#スパムデータ出力
def spam_log(msg, data, t):
	if G.DBG >= 1:
		fname = tmppath(spam_fname(t))
		f = open(fname, "wb")
		f.write(data)
		f.write(msg)

class SpamError(Exception):
	pass

# メールの検査（データフェーズ終了時）
def data_proc(data, param):
	if param.phase == HEADER_PHASE:
		xkey = b'XFORWARD NAME='
		xval = b'SOURCE=LOCAL'
		if data[:len(xkey)] == xkey and data.find(xval) > 0:
			param.is_local = True
			param.rdata = b''
			return
		elif data[:4] == b'DATA':
			param.phase = DATA_PHASE

	param.rdata += data
	if data[-5:] == b'\r\n.\r\n':
		dec_data, param.msg_id = decode_mail(param.rdata)
		if not param.is_local:
			if is_spam(dec_data, param.msg_id, param.t):
				raise SpamError()
			elif G.DBG >= 2:
				open(tmppath(sdec_fname(param.t)), "wb").write(dec_data)

def rewrite_filter(data, param):
	if not param.xforward:
		m = XFORWARD_RE.search(data)
		if m:
			param.xforward = m.group().strip()
		return data

	if param.xforward and param.need_rewrite:
		m = RECEIVESPF_RE.search(data)
		if m:
			data = b"X-Forward: %s file=%s\r\n%s" % (
				param.xforward[9:], smtp_fname(param.t).encode("utf8"), data)
			param.need_rewrite = False

	return data

# フィルター動作コア部
def content_filter_core(r, dst_addr, t):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(dst_addr)
		s_map = {
			s.fileno(): Obj(Sock=s, SWait=True, RWait=True, RSockF=r.fileno(), Data=b""),
			r.fileno(): Obj(Sock=r, SWait=True, RWait=True, RSockF=s.fileno(), Data=b"")
		}
		smtp_data = b''

		param = Obj(rdata=b'', phase=HEADER_PHASE, is_local=False, t=t, msg_id=b'',
					xforward=b'', need_rewrite=True)

		while s_map[s.fileno()].RWait and s_map[r.fileno()].RWait:
			rfds = [x.Sock.fileno() for x in s_map.values() if x.RWait]
			wfds = [x.Sock.fileno() for x in s_map.values() if x.Data and x.SWait]

			rl, wl, xl = select.select(rfds, wfds, [])

			for i in rl:
				data = s_map[i].Sock.recv(1000000)
				if len(data) > 0:
					if param.need_rewrite:
						data = rewrite_filter(data, param)
					s_map[s_map[i].RSockF].Data += data
				else:
					s_map[i].RWait = False

				if data:
					rmode = (i == r.fileno())
					smtp_data += (rmode and b"R: " or b"S: ") + data
					if rmode and not param.is_local:
						data_proc(data, param) # spamの場合、SpamError例外発生

			for i in wl:
				sent = s_map[i].Sock.send(s_map[i].Data)
				if sent >= 0:
					s_map[i].Data = s_map[i].Data[sent:]
				else:
					s_map[i].SWait = False

		if G.DBG >= 2 and not param.is_local:
			write_log(t, smtp_data, param.msg_id)

	except SpamError:
		ret = b"%d SPAM checker was invoked.\r\n" % G.SPAM_ERRCODE
		r.send(ret)
		time.sleep(0.1)
		putlog(ret)
		if G.DBG >= 1:
			write_log(t, smtp_data + ret, param.msg_id)

	except Exception:
		ret = b"450 internal error\r\n"
		r.send(ret)
		time.sleep(0.1)
		msg = traceback.format_exc()
		putlog(msg)
		if G.DBG >= 0:
			write_log(t, msg.encode("utf8") + smtp_data, param.msg_id)

	try:
		s.close()
		r.close()

	except Exception:
		msg = traceback.format_exc()
		putlog(msg)
		if G.DBG >= 0:
			write_log(t, msg.encode("utf8") + smtp_data, param.msg_id)

# フィルター動作ラッパ部
def content_filter_proc(r, dst_addr, t):
	try:
		G.THR_CNT += 1
		content_filter_core(r, dst_addr, t)

	finally:
		G.THR_CNT -= 1

# タイムスタンプ用時刻オブジェクト生成
def gen_timeobj(last_t=None):
	t = Obj(t=int(time.time()), idx=0)

	if last_t and last_t.t == t.t:
		t.idx = last_t.idx + 1
	return	t

# フィルタリクエスト受付
def content_filter(src_addr, dst_addr):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind(src_addr)
	s.listen(10)
	last_t = Obj(t=0, idx=0)

	while True:
		try:
			r, addr = s.accept()
			t = gen_timeobj(last_t)
			_thread.start_new_thread(content_filter_core, (r, dst_addr, t))
			last_t = t

		except Exception as e:
			time.sleep(1)
			msg = traceback.format_exc()
			putlog(msg)

# デーモン化
def daemonize():
	if os.fork() > 0: sys.exit(0)
	os.setsid()
	if os.fork() > 0: sys.exit(0)
	sys.stdin = sys.stdout = sys.stderr = open("/dev/null", "r+")

# 設定ファイルの動的読み込み
# （変更があった場合、自動的に再ロードする）
def loadcheck_spam_dat():
	while True:
		nstat = os.stat(spam_dat.__file__)
		if G.STAT and nstat.st_mtime == G.STAT.st_mtime:
			return
		if nstat.st_size > 0:
			try:
				importlib.reload(spam_dat)
				obj = Obj(
					SRC_ADDR     = spam_dat.SRC_ADDR,
					DST_ADDR     = spam_dat.DST_ADDR,
					WHITE_HEAD   = spam_dat.WHITE_HEAD,
					WHITE_DATA   = spam_dat.WHITE_DATA,
					CHECK_HEAD   = spam_dat.CHECK_HEAD,
					CHECK_DATA   = spam_dat.CHECK_DATA,
					TMP_DIR      = spam_dat.TMP_DIR,
					DBG          = spam_dat.DBG,
					SPAM_ERRCODE = spam_dat.SPAM_ERRCODE,
				)
				obj.WHITE_RE = [[re.compile(x, re.IGNORECASE) for x in y] for y in obj.WHITE_DATA]
				obj.CHECK_RE = [[re.compile(x, re.IGNORECASE) for x in y] for y in obj.CHECK_DATA]
				obj.WHITE_HEAD_RE = [[re.compile(x, re.IGNORECASE) for x in y] for y in obj.WHITE_HEAD]
				obj.CHECK_HEAD_RE = [[re.compile(x, re.IGNORECASE) for x in y] for y in obj.CHECK_HEAD]
				list(map(lambda kv: G.__setattr__(kv[0], kv[1]), obj.__dict__.items()))

				if G.STAT:
					putlog("reload done")
				G.STAT = nstat
				return
			except:
				msg = traceback.format_exc()
				putlog(msg)
		time.sleep(2)

def load_smtpfile(f):
	ll = []
	for L in open(f, "rb").readlines():
		if L[:3] == b"S: ":
			continue
		elif L[:3] == b"R: ":
			ll.append(L[3:])
		else:
			ll.append(L)
	#open("/tmp/a.txt", "wb").write(b"".join(ll))
	return	b"".join(ll)

# フィルターメイン
def content_filter_server():
	G.IS_DAEMON = True

	loadcheck_spam_dat()

	optlist, args = getopt.getopt(sys.argv[1:], "vdf:")
	for key, val in optlist:
		key = key.replace("-", "")
		if key == "d":
			G.IS_DAEMON = False
			continue
		if key == "v":
			G.VERBOSE = True
			continue
		elif key == "f":
			G.IS_DAEMON = False
			t = Obj(t=0, idx=0)  # spam_0.txt / sdec_0.txt などが作成される
			if val[:5] == 'spam_' or val[:5] == 'sdec_':
				val = 'smtp_' + val[5:]
			if len(val) > 10 and val.find(".") == -1:
				val += ".txt"
			dec_data, msg_id = decode_mail(load_smtpfile(val))
			open(sdec_fname(t), "wb").write(dec_data)
			is_spam(dec_data, msg_id, t)
			return

	if G.IS_DAEMON:
		syslog.openlog("content_filter", syslog.LOG_PID, syslog.LOG_MAIL)
	putlog("content_filter ver%s started." % VER)

	def sig_func(k, s):
		raise Exception()
	signal.signal(signal.SIGTERM, sig_func)
	signal.signal(signal.SIGINT,  sig_func)

	if G.IS_DAEMON:
		daemonize()
	_thread.start_new_thread(content_filter, (G.SRC_ADDR, G.DST_ADDR))

	try:
		while True:
			loadcheck_spam_dat()
			time.sleep(1)
	except:
		pass

	if G.THR_CNT > 0:
		putlog("Wait for threads...\n")
		for i in range(60):
			if G.THR_CNT <= 0:
				break
			time.sleep(1)
		else:
			putlog("...timeout.")
	putlog("content_filter terminated.")

if __name__ == "__main__":
	content_filter_server()

