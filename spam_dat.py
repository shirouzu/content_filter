#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Date: 2019/8/2
# spam_dat for content_filter by H.Shirouzu
#
# content_filter.py用設定ファイル
#
# 最初＆データ変更直後は
#   SPAM_ERRCODE = 450
#   DBG = 1
# で動作確認すると良い
#
# なお内容を変更すると、自動的に再ロード。
#

# ポート指定（起動時のみ使われ、spam_dat のリロードでは使われない）
#
SRC_ADDR   = ("localhost", 60025)
DST_ADDR   = ("localhost", 60026)

# マッチ指定の基本書式 (WHITE_DATA / CHECK_DATA)
#
# CHECK_DATA = [
#   [ b'正規表現1_1', b'正規表現1_2,... ],  # ルール1
#   [ b'正規表現2_1', b'正規表現2_2,... ],  # ルール2
#       :
#   [ b'正規表現n_1', b'正規表現2_2,... ],  # ルールn
# ]
#
#  1. 指定は正規表現で行う
#  2. １ルールにつき、１つ以上の正規表現文字列（バイト列）を列挙
#  3. １ルール内の全要素がマッチ（AND条件）＝ そのルールにマッチ
#  4. どれか１つのルールにマッチすると、判定終了
#

# これのどれかにマッチするメールは、無条件でSPAM除外判定
#
WHITE_DATA = [
	# @ntt.co.jp かつ ecl.ntt.co.jp（メールサーバ想定）を含むメールは
	# ホワイトリストに入れる
	[rb'@ntt\.co\.jp', rb'ecl\.ntt\.co\.jp'],
]

# （上記を除いて）どれかにマッチするメールはSPAM判定
# （なお、base64/quoted-printable はデコードされるが、文字コードはそのまま）
# （つまり、元メールが JIS であれば、"xxx".encode("iso-2022-jp")等で指定）
CHECK_DATA = [
	# href=, Sunglasses, Deal をすべて含む場合メールを SPAMに
	[rb'href=', rb'Sunglasses', rb'Deal'],

	# Bitcoin と BTC を含み、"copy and paste" / Ƿorn / ... /video のいずれかを含むもの
	# （b64デコード後の）元メール文字コードに合わせる必要あり。
	[rb'Bitcoin', rb'BTC', r'(copy and paste|Ƿorn|Ƿayment|camera|video)'.encode('utf8')],
]

# SPAM判定されたメールのリターンコード
# （550: パーマネントエラー（再送なし）、450:テンポラリエラー（再送あり））
#
SPAM_ERRCODE = 550

# デバッグオプション（-1でファイル保存せず）
#
#  0: 内部エラー発生時だけ、SMTP通信内容をsmtpファイルとして保存。（TMP_DIR）
#
#  1:（上記に加えて）スパムの場合にも、smtpファイルを保存。
#     さらに、受信デコード内容及びマッチしたルールをspamファイルとして保存。
#
#  2:（上記に加えて）通常メールであっても、smtpファイルを保存。
#     さらに、受信デコード内容をsdecファイルとして保存。
#
DBG = 1

# 上記で、ファイルを作成する場合のディレクトリ
# 
TMP_DIR = "/tmp/content_filter/"


