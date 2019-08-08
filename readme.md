# PositfixでのSPAM対策<br>（キュー投入前コンテンツフィルタ）
白水啓章
作成 2019/08/05
更新 2019/08/07

## 概要
「Postfix キュー投入前コンテンツフィルタ」の枠組みを利用したSPAM対策

## 「Postfix キュー投入前コンテンツフィルタ」とは
仕組みの説明はこちらをご覧ください。
http://www.postfix-jp.info/trans-2.2/jhtml/SMTPD_PROXY_README.html

Postfix内部に入り込んて、通信を中継します。
そして「必要があれば」それを変更します。（man in the middle のようなもの）

それを SPAMフィルタとして使うメリットは下記の通り。
1. header_checks/body_checks（＝１行毎の判断）よりも柔軟（＝メール全体での判断が可能）。
2. SPAMと見做した時点ではまだSMTP通信中のため、直接エラーコードを返せる。<br>
（「キュー投入後コンテンツフィルタ」と違い、「受信のSMTP通信で成功」を返さない＆エラーメールも発生せず）

## content_filter.py の特徴
1. base64 や quoted-printable をデコードした後の判定が可能<br>
2. （メールヘッダだけでなく）SMTPレベルの MAIL FROM: / RCPT TO:、さらに XFORWARD（逆引き名、IPアドレス、ポート、HELO内容等）を含む判断が可能<br>
3. SPAM判定となり、エラーを返して受信拒否した場合も、全体の受信内容をファイルとして保存可能。<br>
（つまり、SPAM条件が適正だったか正確な事後調査が可能。spam_dat.DBG=1以上で有効）
2. ホワイトリストによる除外指定が可能。
3. syslog に SPAM判定されたメールの message-id 及び、マッチした正規表現リストを出力。
  
## 無償・無保証で、ご自由にお使いください。
　（SMTPにさほど詳しく無いので、フィードバック歓迎します）

## content_filter.py の使い方

１．設定ファイル（spam_dat.py）を適宜、変更します。

２．content_filter.py を起動します。

３．master.cf の smtp行を下記に書き換えます。

    smtp      inet  n       -       n       -       20      smtpd
         -o smtpd_proxy_filter=127.0.0.1:60025
         -o smtpd_client_connection_count_limit=20

４．master.cf に下記を追記します。<br>

    127.0.0.1:60026 inet n  -       n       -        -      smtpd
            -o smtpd_authorized_xforward_hosts=127.0.0.0/8
            -o smtpd_recipient_restrictions=permit_mynetworks,reject
            -o smtpd_data_restrictions=permit_mynetworks
            -o mynetworks=127.0.0.0/8

５．Postfix をリスタートします。

６．syslog(mail.log) の content_filter出力を確認します。


## 設定ファイル(spam_dat.py)でのマッチ指定書式
 下記の書式で、ホワイトリスト定義(WHITE_HEAD/WHITE_DATA)とSPAM定義(CHECK_HEAD/CHECK_DATA)を指定。
 （HEADはヘッダのみ検査、DATAはヘッダ＆ボディを検査）

    CHECK_DATA = [
      [ b'正規表現1_1', b'正規表現1_2,... ],  # ルール1
      [ b'正規表現2_1', b'正規表現2_2,... ],  # ルール2
          :
      [ b'正規表現n_1', b'正規表現2_2,... ],  # ルールn
    ]

  1. 指定は正規表現で行う
  2. １ルールにつき、１つ以上の正規表現文字列（バイト列）を列挙
  3. １ルール内の全要素がマッチ（AND条件）＝ そのルールにマッチ
  4. どれか１つのルールにマッチすると、判定終了

  それ以外の設定項目の説明は spam_dat.py を参照してください。
  
  ## 
