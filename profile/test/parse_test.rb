# frozen_string_literal: true

# Unit tests of the profile's pure parsers (plain Ruby, no InSpec):
#   ruby profile/test/parse_test.rb
# Fixtures are real outputs captured from nginx, PostgreSQL, MySQL and
# MariaDB; the other inputs are inline so each case reads on its own.
require 'minitest/autorun'
require_relative '../libraries/01_sdw_parse'

class ParseTest < Minitest::Test
  P = SdwParse
  FIX = File.join(__dir__, 'fixtures')

  def fixture(name)
    File.read(File.join(FIX, name))
  end

  # An `nginx -T` dump made of the given files.
  def nginx_dump(files)
    "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\n" +
      files.map { |path, text| "# configuration file #{path}:\n#{text}\n" }.join
  end

  # ── nginx ──────────────────────────────────────────────────────────────

  def test_nginx_stock_config
    tree = P.nginx_tree(fixture('nginx-T.txt'))
    assert_equal 'nginx', P.nginx_user(tree)
    tokens = P.nginx_server_tokens_on(tree)
    assert_equal 1, tokens.size
    assert_match(/\Ahttp \(.*nginx\.conf:\d+\): server_tokens not set \(default on\)\z/, tokens.first)
    assert_empty P.nginx_autoindex_on(tree)
    assert_empty P.nginx_legacy_tls(tree, '1.27.0')
  end

  def test_nginx_includes_tokens_and_tls
    dump = nginx_dump(
      '/etc/nginx/nginx.conf' => "user root;\nhttp {\n  server_tokens off;\n  include /etc/nginx/conf.d/*.conf;\n}\n",
      '/etc/nginx/conf.d/a.conf' => "server {\n  listen 443 ssl;\n  server_name a;\n  location /x { server_tokens on; autoindex on; }\n}\n",
      '/etc/nginx/conf.d/b.conf' => "server {\n  listen 8443 ssl;\n  server_name b;\n  ssl_protocols TLSv1 TLSv1.2;\n}\n"
    )
    tree = P.nginx_tree(dump)
    assert_equal 'root', P.nginx_user(tree)
    assert_equal ['location (/etc/nginx/conf.d/a.conf:4): server_tokens on'], P.nginx_server_tokens_on(tree)
    assert_equal ['autoindex on (/etc/nginx/conf.d/a.conf:4)'], P.nginx_autoindex_on(tree)

    # Before 1.23.4 the default list still has TLS 1.0 and 1.1.
    old = P.nginx_legacy_tls(tree, '1.22.1')
    assert_equal 2, old.size
    assert(old.any? { |f| f.start_with?('server a ') && f.end_with?('allows TLSv1, TLSv1.1') })
    # Recent nginx, or a system OpenSSL floor, only leaves the explicit list.
    assert_equal ['server b (/etc/nginx/conf.d/b.conf:1): ssl_protocols allows TLSv1'], P.nginx_legacy_tls(tree, '1.24.0')
    assert_equal 1, P.nginx_legacy_tls(tree, '1.22.1', 'TLSv1.2').size
  end

  # ── Apache httpd ───────────────────────────────────────────────────────

  APACHE_INCLUDES = <<~OUT
    Included configuration files:
      (*) /etc/apache2/apache2.conf
        (3) /etc/apache2/mods-enabled/ssl.load
        (4) /etc/apache2/conf-enabled/security.conf
        (5) /etc/apache2/sites-enabled/default-ssl.conf
  OUT

  APACHE_FILES = {
    '/etc/apache2/apache2.conf' => "ServerRoot /etc/apache2\nUser www-data\nInclude mods-enabled/*.load\nIncludeOptional conf-enabled/*.conf\nIncludeOptional sites-enabled/*.conf\n" \
                                   "<Directory /var/www/>\n  Options Indexes FollowSymLinks\n</Directory>\n",
    '/etc/apache2/mods-enabled/ssl.load' => "LoadModule ssl_module /usr/lib/apache2/modules/mod_ssl.so\n",
    '/etc/apache2/conf-enabled/security.conf' => "ServerTokens OS\nServerSignature On\nTraceEnable Off\n",
    '/etc/apache2/sites-enabled/default-ssl.conf' => "<VirtualHost *:443>\n  SSLEngine on\n  TraceEnable On\n</VirtualHost>\n" \
                                                     "<VirtualHost *:8443>\n  SSLEngine on\n  SSLProtocol -all +TLSv1.2 +TLSv1.3\n</VirtualHost>\n",
  }.freeze

  def apache_dirs
    inc = P.apache_includes(APACHE_INCLUDES)
    assert_equal [[0, nil, '/etc/apache2/apache2.conf'], [1, 3, '/etc/apache2/mods-enabled/ssl.load']], inc.first(2)
    P.apache_directives(P.apache_flatten(inc, ->(p) { APACHE_FILES[p] }))
  end

  def test_apache_effective_tree
    dirs = apache_dirs
    assert_equal ['ServerTokens OS', 'ServerSignature On'], P.apache_version_disclosure(dirs)
    assert_equal ['TraceEnable On in VirtualHost *:443'], P.apache_trace_enabled(dirs)
    assert_equal ['Options Indexes FollowSymLinks in Directory /var/www/'], P.apache_indexes(dirs)
    assert_equal ['<VirtualHost *:443>: SSLProtocol all -SSLv3 allows TLSv1, TLSv1.1'], P.apache_legacy_tls(dirs)
    assert_empty P.apache_legacy_tls(dirs, 'TLSv1.2')
  end

  # Real output of httpd:2.4: a single file, and a warning line to ignore.
  def test_apache_includes_single_file
    assert_equal [[0, nil, '/usr/local/apache2/conf/httpd.conf']], P.apache_includes(fixture('httpd-includes.txt'))
  end

  def test_apache_protocol_spec
    assert_equal %w[TLSv1.2 TLSv1.3], P.apache_protocols('-all +TLSv1.2 +TLSv1.3')
    assert_equal %w[TLSv1 TLSv1.1 TLSv1.2 TLSv1.3], P.apache_protocols('all -SSLv3')
  end

  # ── HAProxy, Caddy, Tomcat ─────────────────────────────────────────────

  HAPROXY = <<~CFG
    global
        user haproxy
        ssl-default-bind-options ssl-min-ver TLSv1.0
    frontend fe
        bind :443 ssl crt /etc/haproxy/site.pem
        bind :8443 ssl crt /etc/haproxy/site.pem ssl-min-ver TLSv1.2
    listen stats
        bind 127.0.0.1:8404
        stats enable
        stats uri /stats
    listen stats_ok
        bind :8405
        stats enable
        stats auth admin:long-secret
  CFG

  def test_haproxy
    secs = P.haproxy_sections(HAPROXY)
    assert_equal %w[global frontend listen listen], secs.map { |s| s[:kind] }
    assert_equal ['frontend fe: bind :443 accepts TLSv1 and later'], P.haproxy_legacy_tls(secs, '3.0.5')
    assert_equal ['listen stats: statistics page without authentication'], P.haproxy_open_stats(secs)

    plain = P.haproxy_sections("frontend fe\n    bind :443 ssl crt /x.pem\n")
    assert_equal 1, P.haproxy_legacy_tls(plain, '2.0.33').size
    assert_empty P.haproxy_legacy_tls(plain, '2.8.0')
    assert_empty P.haproxy_legacy_tls(plain, '2.0.33', 'TLSv1.2')
  end

  def test_caddy_admin
    assert_nil P.caddy_admin_exposed({})
    assert_nil P.caddy_admin_exposed('admin' => { 'listen' => 'unix//run/caddy.sock' })
    assert_nil P.caddy_admin_exposed('admin' => { 'disabled' => true, 'listen' => '0.0.0.0:2019' })
    assert_nil P.caddy_admin_exposed('admin' => { 'listen' => '[::1]:2019' })
    assert_equal '0.0.0.0:2019', P.caddy_admin_exposed('admin' => { 'listen' => '0.0.0.0:2019' })
    assert_equal 'tcp/:2019', P.caddy_admin_exposed('admin' => { 'listen' => 'tcp/:2019' })
  end

  def test_tomcat_shutdown
    assert P.tomcat_shutdown_open?(%(<?xml version="1.0"?>\n<Server port="8005" shutdown="SHUTDOWN">\n</Server>))
    refute P.tomcat_shutdown_open?(%(<Server port="-1" shutdown="SHUTDOWN">))
    refute P.tomcat_shutdown_open?(%(<Server port="8005" shutdown="k3Yq9-random">))
  end

  # ── PostgreSQL ─────────────────────────────────────────────────────────

  def test_pg_hba
    rows = P.pg_hba_rows(fixture('pg-hba.txt'))
    assert_equal 7, rows.size
    assert_equal 6, P.pg_trust(rows).size
    assert_empty P.pg_weak_password(rows)
    plain = P.pg_plaintext(rows)
    assert_equal 1, plain.size
    assert_match(/line 128: host all all all scram-sha-256/, plain.first)

    assert P.pg_listens_remote?('*')
    assert P.pg_listens_remote?('localhost, 10.0.0.5')
    refute P.pg_listens_remote?('localhost')
    refute P.pg_listens_remote?('')

    weak = P.pg_hba_rows("host|all|all|10.0.0.0/8|md5|90\nhostssl|all|all|10.0.0.0/8|password|91\nhostssl|all|all|10.0.0.0/8|scram-sha-256|92\n")
    assert_equal 2, P.pg_weak_password(weak).size
    assert_equal 1, P.pg_plaintext(weak).size
  end

  # ── MySQL / MariaDB ────────────────────────────────────────────────────

  def test_mysql_accounts
    acc = P.mysql_accounts(fixture('mysql-accounts.txt'))
    assert_equal [%w[root %], %w[root localhost]], acc.map { |a| [a[:user], a[:host]] }
    assert_empty P.mysql_passwordless(acc)
    assert_equal ["'root'@'%' is an administrator reachable from other hosts"], P.mysql_remote_admins(acc, [])
  end

  def test_mariadb_accounts
    acc = P.mysql_accounts(fixture('mariadb-accounts.txt'))
    refute(acc.any? { |a| a[:user] == 'mariadb.sys' }, 'locked accounts are left out')
    assert_empty P.mysql_passwordless(acc)
    assert_empty P.mysql_anonymous(acc)
    # SUPER on a local account is fine; root reachable from '%' is not.
    assert_equal ["'root'@'%' is an administrator reachable from other hosts"], P.mysql_remote_admins(acc, ['healthcheck@127.0.0.1'])
    open = P.mysql_accounts("\tlocalhost\tmysql_native_password\t1\tN\napp\t%\tmysql_native_password\t1\tN\nroot\tlocalhost\tunix_socket\t1\tN\n")
    assert_equal ["anonymous account ''@'localhost'"], P.mysql_anonymous(open)
    assert_equal 2, P.mysql_passwordless(open).size
  end

  def test_mysqld_help_and_switches
    v = P.mysqld_help_values("Variables (--variable-name=value)\nand boolean options {FALSE|TRUE}  Value (after reading options)\n" \
                             "--------------------------------- ----------------------------------------\nlocal-infile                      FALSE\n" \
                             "secure-file-priv                  (No default value)\n")
    assert_equal 'FALSE', v['local-infile']
    assert_equal '(No default value)', v['secure-file-priv']
    assert P.mysql_on?('ON')
    refute P.mysql_on?('OFF')
  end

  # ── Redis, MongoDB, Memcached ──────────────────────────────────────────

  def test_redis
    conf = P.redis_conf("bind 127.0.0.1\nrequirepass \"s3cret\"\nrename-command CONFIG \"\"\nrename-command FLUSHALL \"\"\n")
    assert P.redis_conf_requires_auth?(conf)
    assert_equal %w[FLUSHDB DEBUG MODULE SHUTDOWN], P.redis_dangerous_left(conf, '')
    assert_empty P.redis_dangerous_left(conf, 'user default on sanitize-payload #abc ~* &* +@all -@dangerous')

    open = P.redis_conf("user default on nopass ~* +@all\n")
    refute P.redis_conf_requires_auth?(open)
    assert P.redis_conf_requires_auth?(P.redis_conf("user default on >secret ~* +@all\n"))
    assert_equal({ 'dir' => '/data', 'requirepass' => '' }, P.redis_config_get("dir\n/data\nrequirepass\n\n"))
  end

  def test_mongod_options
    o = P.mongod_options(%w[mongod --auth --noscripting --bind_ip 127.0.0.1], {})
    assert o[:auth]
    assert_equal false, o[:javascript]
    refute P.mongod_exposed?(o)

    y = { 'net' => { 'bindIp' => '0.0.0.0', 'tls' => { 'mode' => 'requireTLS' } }, 'security' => { 'authorization' => 'enabled' } }
    o = P.mongod_options(%w[mongod --config /etc/mongod.conf], y)
    assert o[:auth]
    assert P.mongod_exposed?(o)
    assert_equal 'requireTLS', o[:tls_mode]
    assert_nil o[:javascript]
    assert P.mongod_exposed?(P.mongod_options(%w[mongod --bind_ip_all], {}))
  end

  def test_memcached
    o = P.memcached_options(%w[memcached -m 64 -p 11211 -u memcache -l 127.0.0.1 -P /run/memcached.pid])
    refute P.memcached_exposed?(o)
    refute P.memcached_udp_on?(o, '1.6.21')
    assert P.memcached_udp_on?(o, '1.5.4')
    assert P.memcached_udp_on?(P.memcached_options(%w[memcached -U 11211]), '1.6.21')
    refute P.memcached_udp_on?(P.memcached_options(%w[memcached -U 0]), '1.4.0')
    assert P.memcached_exposed?(P.memcached_options(%w[memcached]))
    assert P.memcached_options(%w[memcached -S])[:sasl]
  end

  # ── TLS endpoints ──────────────────────────────────────────────────────

  def test_x509_and_headers
    f = P.x509_facts("notAfter=Oct  6 15:50:36 2026 GMT\n        Subject Public Key Info:\n            Public Key Algorithm: rsaEncryption\n" \
                     "                Public-Key: (1024 bit)\n")
    assert_equal 'Oct  6 15:50:36 2026 GMT', f[:not_after]
    assert P.weak_key?(f, 2048)
    refute P.weak_key?({ algorithm: 'id-ecPublicKey', bits: 256 }, 2048)
    assert P.weak_key?({ algorithm: 'id-ecPublicKey', bits: 192 }, 2048)

    h = P.http_headers("HTTP/1.1 200 OK\r\nServer: nginx\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\n\r\nbody: no\r\n")
    assert_equal 'nginx', h['server']
    refute h.key?('body')
    assert P.hsts_ok?(h['strict-transport-security'], 15_768_000)
    refute P.hsts_ok?('max-age=300', 15_768_000)
    refute P.hsts_ok?(nil, 1)
  end

  def test_openssl_floor
    assert_equal 'TLSv1.2', P.openssl_min_protocol("[system_default_sect]\nMinProtocol = TLSv1.2\nCipherString = DEFAULT@SECLEVEL=2\n")
    assert_equal 'TLSv1.2', P.openssl_min_protocol("TLS.MinProtocol = TLSv1.2\n# MinProtocol = TLSv1\n")
    assert_nil P.openssl_min_protocol("# MinProtocol = TLSv1.2\n")
  end

  # ── CPU, firmware, BMC ─────────────────────────────────────────────────

  VULNS = {
    'meltdown' => 'Not affected',
    'mds' => 'Mitigation: Clear CPU buffers; SMT vulnerable',
    'mmio_stale_data' => 'Vulnerable: Clear CPU buffers attempted, no microcode; SMT Host state unknown',
    'spectre_v2' => 'Mitigation: Enhanced / Automatic IBRS; IBPB: conditional; RSB filling',
  }.freeze

  def test_cpu_flaws
    assert_equal ['mmio_stale_data: Vulnerable: Clear CPU buffers attempted, no microcode; SMT Host state unknown'], P.cpu_vulnerable(VULNS)
    assert_equal %w[mds mmio_stale_data], P.cpu_smt_exposed(VULNS).map { |f| f.split(':').first }
    line = 'BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro quiet mitigations=off nopti spectre_v2=on iommu=pt'
    assert_equal %w[mitigations=off nopti], P.mitigation_off_params(line)
    assert_equal ['iommu=pt'], P.iommu_off_params(line)
    refute P.nosmt_at_boot?(line)
    assert P.nosmt_at_boot?('ro mitigations=auto,nosmt')
    assert P.nosmt_at_boot?('ro nosmt')
    assert P.nosmt_at_boot?('ro mds=full,nosmt')
  end

  LAN_PRINT = <<~OUT
    Set in Progress         : Set Complete
    Auth Type Support       : NONE MD2 MD5 PASSWORD
    Auth Type Enable        : Callback : MD2 MD5 PASSWORD
                            : User     : NONE MD2 MD5 PASSWORD
                            : Operator : MD2 MD5 PASSWORD
                            : Admin    : MD2 MD5 PASSWORD
                            : OEM      :
    IP Address Source       : Static Address
    RMCP+ Cipher Suites     : 0,1,2,3,17
    Cipher Suite Priv Max   : aaaaXXaXXXXXXXX
  OUT

  def test_ipmi
    assert P.ipmi_cipher0_enabled?(LAN_PRINT)
    refute P.ipmi_cipher0_enabled?(LAN_PRINT.sub('aaaaXXaXXXXXXXX', 'XXXaXXXXXXXXXXX'))
    assert_nil P.ipmi_cipher0_enabled?('Set in Progress : Set Complete')
    assert_equal ['User'], P.ipmi_none_auth(LAN_PRINT)
    assert_empty P.ipmi_none_auth(LAN_PRINT.sub('User     : NONE MD2', 'User     : MD2'))
  end

  def test_fwupd
    assert_equal [:ok, 'no update'], P.fwupd_state(0, '{"Devices":[]}', '')
    state, detail = P.fwupd_state(0, '{"Devices":[{"Name":"System Firmware","Releases":[{"Version":"1.12.0"}]}]}', '')
    assert_equal :pending, state
    assert_equal ['System Firmware: 1.12.0'], detail
    assert_equal :ok, P.fwupd_state(2, '', 'No updatable devices').first
    assert_equal :unknown, P.fwupd_state(1, '', 'Firmware metadata has not been updated for 30 days').first
  end

  # ── shared ─────────────────────────────────────────────────────────────

  def test_shared
    assert P.loopback?('127.0.0.53')
    assert P.loopback?('[::1]')
    assert P.loopback?('localhost')
    refute P.loopback?('0.0.0.0')
    refute P.loopback?('*')
    assert P.version_at_least?('1.23.4', '1.23.4')
    assert P.version_at_least?('1.24', '1.23.4')
    refute P.version_at_least?('1.9.15', '1.23.4')
    refute P.version_at_least?(nil, '1.0')
    assert_equal 'TLSv1', P.tls_name('TLSv1.0')
    assert_equal %w[TLSv1 TLSv1.1], P.legacy(%w[TLSv1 tlsv1_1 TLSv1.2])
  end
end
