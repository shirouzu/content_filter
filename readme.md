# 「Postfix キュー投入前コンテンツフィルタ」の実装例です。<br>
   http://www.postfix-jp.info/trans-2.2/jhtml/SMTPD_PROXY_README.html
   
# メリット
 1. メール受信を完了する前に、メール本文を含めたSPAM判定が可能になります。<br>
  （つまり、メール本文を確認しつつも、450/550といったエラーコードを送信元に返せます）
 2. SPAM判定となり、エラーを返した場合も、全体の受信内容をファイルとして保存できます。<br>
  （つまり、内容が適正だったかの正確な事後調査が出来ます）
 3. header_checksのように1行入力毎に条件を判定するのではなく、<br>
  メール全体で判定します。（正規表現１にマッチし、かつ正規表現２にもマッチする別の文があればSPAM、<br>
  といった判定が可能となります）
  4. ホワイトリストによる除外指定ができます。
  5. syslog に、SPAM判定されたメールの message-id 及び、マッチした正規表現リストを出力します。
  
# 無償・無保証で、ご自由にお使いください。
　（SMTPにさほど詳しく無いので、フィードバック歓迎します）

# content_filter.py の使い方

 1. 設定ファイル（spam_dat.py）を適宜、変更します。

 2. content_filter.py を起動します。

 3. master.cf の smtp行を下記に書き換えます。

    smtp      inet  n       -       n       -       20      smtpd
         -o smtpd_proxy_filter=127.0.0.1:60025
         -o smtpd_client_connection_count_limit=20

 4. master.cf に下記を追記します。
    127.0.0.1:60026 inet n  -       n       -        -      smtpd
            -o smtpd_authorized_xforward_hosts=127.0.0.0/8
            -o smtpd_recipient_restrictions=permit_mynetworks,reject
            -o smtpd_data_restrictions=permit_mynetworks
            -o mynetworks=127.0.0.0/8

 5. Postfix をリスタートします。

 6. syslog(mail.log) の content_filter出力を確認します。


# 設定ファイル(spam_dat.py)でのマッチ指定書式
 下記の書式で、ホワイトリスト定義(WHITE_DATA)とSPAM定義(CHECK_DATA)を指定。

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
