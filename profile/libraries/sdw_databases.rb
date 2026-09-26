# frozen_string_literal: true

require 'yaml'

# Database servers running on the target, read the way they apply their own
# configuration: PostgreSQL through psql as its OS user (pg_hba_file_rules,
# pg_settings), MySQL/MariaDB through the socket (accounts, global variables)
# and `mysqld --verbose --help` (what the next start applies), Redis/Valkey
# through their CLI, MongoDB and Memcached from the options of the running
# process, Elasticsearch/OpenSearch over local HTTP. A server that runs but
# cannot be queried is reported in the findings (fail-closed).
class ::SdwDatabases < Inspec.resource(1)
  name 'sdw_databases'
  desc 'Database servers running on the target and their effective settings.'
  example "describe sdw_databases do\n  its('auth_gaps') { should be_empty }\nend"

  include SdwHelpers

  ENGINES = {
    'postgresql' => 'PostgreSQL', 'mysql' => 'MySQL/MariaDB', 'redis' => 'Redis/Valkey',
    'mongodb' => 'MongoDB', 'memcached' => 'Memcached', 'elasticsearch' => 'Elasticsearch/OpenSearch',
  }.freeze

  def initialize(opts = {})
    @pg_user = opts.fetch(:pg_user, 'postgres').to_s
    @mysql_options = opts.fetch(:mysql_options, '').to_s
  end

  def running
    SdwMemo.fetch(:db_running) do
      {
        'postgresql' => pg_procs, 'mysql' => mysql_procs, 'redis' => redis_procs,
        'mongodb' => mongo_procs, 'memcached' => memcached_procs, 'elasticsearch' => es_procs,
      }.reject { |_, v| v.empty? }.keys
    end
  end

  def any?
    !running.empty?
  end

  def running?(engine)
    running.include?(engine)
  end

  def label
    running.empty? ? 'database servers (none running)' : "database servers (#{running.map { |e| ENGINES[e] }.join(', ')})"
  end

  def to_s
    label
  end

  # ── authentication ─────────────────────────────────────────────────────

  # Configurations that let a client in without credentials.
  def auth_gaps
    out = []
    if running?('postgresql')
      rows = pg_hba
      rows ? out.concat(SdwParse.pg_trust(rows).map { |r| "PostgreSQL: pg_hba #{r} (no authentication)" }) : out << pg_unreadable
    end
    if running?('mysql')
      acc = mysql_accounts
      if acc
        out.concat(SdwParse.mysql_passwordless(acc).map { |f| "MySQL/MariaDB: #{f}" })
        out.concat(SdwParse.mysql_anonymous(acc).map { |f| "MySQL/MariaDB: #{f}" })
      else
        out << mysql_unreadable
      end
    end
    redis_procs.each do |p|
      conf = redis_file_conf(p)
      ok = if conf then SdwParse.redis_conf_requires_auth?(conf)
           else redis_server_requires_auth?(p)
           end
      out << "#{redis_label(p)}: no password required (#{conf ? redis_conf_path(p) : 'server settings, no config file'})" unless ok
    end
    mongo_procs.each do |p|
      o = mongo_options(p)
      out << "MongoDB (pid #{p[:pid]}): access control disabled (security.authorization / --auth not set)" unless o[:auth]
    end
    memcached_procs.each do |p|
      o = SdwParse.memcached_options(p[:args])
      next unless SdwParse.memcached_exposed?(o) && !o[:sasl]

      out << "Memcached (pid #{p[:pid]}): reachable on #{o[:listen] || 'every address'} without SASL"
    end
    es_procs.each do |p|
      off = es_setting(p, 'xpack.security.enabled') == 'false' || es_setting(p, 'plugins.security.disabled') == 'true'
      out << "#{es_name(p)} (pid #{p[:pid]}): security disabled in its configuration" if off
    end
    out
  end

  # Servers that answer a request made without credentials, now.
  def runtime_auth_gaps
    out = []
    redis_procs.each do |p|
      reply = redis_cmd(p, 'PING', auth: false).to_s
      out << "#{redis_label(p)}: answers PING without authentication" if reply.include?('PONG')
    end
    mongo_procs.each do |p|
      shell = which('mongosh') || which('mongo')
      unless shell
        out << "MongoDB (pid #{p[:pid]}): no mongosh on the target, the unauthenticated probe could not run"
        next
      end
      host, port = mongo_addr(p)
      r = sh("timeout 10 #{shell} --quiet --host #{host} --port #{port} --eval 'db.adminCommand({listDatabases:1, nameOnly:true, authorizedDatabases:false}).ok' 2>&1").stdout.to_s
      out << "MongoDB #{host}:#{port}: lists databases without authentication" if r.lines.map(&:strip).include?('1')
    end
    es_procs.each do |p|
      code = es_status(p)
      out << "#{es_name(p)} 127.0.0.1:9200: answers #{code} to an unauthenticated request" if code == '200'
    end
    out
  end

  # ── PostgreSQL specifics ───────────────────────────────────────────────

  def pg_weak_password_methods
    return [] unless running?('postgresql')

    s = pg_settings
    rows = pg_hba
    return [pg_unreadable] unless s && rows

    out = []
    out << "password_encryption = #{s['password_encryption']}" unless s['password_encryption'] == 'scram-sha-256'
    out.concat(SdwParse.pg_weak_password(rows).map { |r| "pg_hba #{r}" })
    out.map { |f| "PostgreSQL: #{f}" }
  end

  def pg_connection_logging_off
    return [] unless running?('postgresql')

    s = pg_settings
    return [pg_unreadable] unless s

    %w[log_connections log_disconnections].reject { |k| s[k] == 'on' }.map { |k| "PostgreSQL: #{k} = #{s[k]}" }
  end

  # ── network encryption ─────────────────────────────────────────────────

  def plaintext_network
    out = []
    if running?('postgresql')
      s = pg_settings
      rows = pg_hba
      if s && rows
        if SdwParse.pg_listens_remote?(s['listen_addresses'])
          plain = SdwParse.pg_plaintext(rows)
          out.concat(plain.map { |r| "PostgreSQL: pg_hba #{r} accepts network clients without TLS" })
          remote = rows.any? { |r| SdwParse.pg_remote?(r) && r[:method] != 'reject' }
          out << 'PostgreSQL: ssl = off while network clients are accepted' if remote && s['ssl'] != 'on'
        end
      else
        out << pg_unreadable
      end
    end
    if running?('mysql')
      v = mysql_variables
      if v
        exposed = !(SdwParse.mysql_on?(v['skip_networking']) || SdwParse.loopback?(v['bind_address'].to_s.split(',').first))
        out << "MySQL/MariaDB: listens on #{v['bind_address'].to_s.empty? ? 'every address' : v['bind_address']} without require_secure_transport" if exposed && !SdwParse.mysql_on?(v['require_secure_transport'])
      else
        out << mysql_unreadable
      end
    end
    mongo_procs.each do |p|
      o = mongo_options(p)
      next unless SdwParse.mongod_exposed?(o) && o[:tls_mode].to_s != 'requireTLS'

      out << "MongoDB (pid #{p[:pid]}): bound to #{o[:bind_all] ? 'every address' : o[:bind_ip]} with TLS mode #{o[:tls_mode] || 'disabled'}"
    end
    redis_procs.each do |p|
      port = redis_addr(p).last
      next if port == '0' # TLS port only

      open = redis_bind(p).reject { |h| SdwParse.loopback?(h) }
      out << "#{redis_name(p)} port #{port}: clear-text port bound to #{open.join(', ')}" unless open.empty?
    end
    memcached_procs.each do |p|
      o = SdwParse.memcached_options(p[:args])
      out << "Memcached (pid #{p[:pid]}): reachable on #{o[:listen] || 'every address'} without TLS" if SdwParse.memcached_exposed?(o) && !p[:args].include?('-Z') && !p[:args].include?('--enable-ssl')
    end
    es_procs.each do |p|
      host = es_setting(p, 'network.host').to_s
      ssl = (es_setting(p, 'xpack.security.http.ssl.enabled') || es_setting(p, 'plugins.security.ssl.http.enabled')).to_s
      ssl = 'false' if es_setting(p, 'xpack.security.enabled') == 'false' || es_setting(p, 'plugins.security.disabled') == 'true'
      out << "#{es_name(p)} (pid #{p[:pid]}): network.host #{host} with HTTP TLS off" if !host.empty? && !SdwParse.loopback?(host) && ssl != 'true'
    end
    out
  end

  # ── MySQL / MariaDB specifics ──────────────────────────────────────────

  def mysql_remote_admin_accounts
    return [] unless running?('mysql')

    acc = mysql_accounts
    return [mysql_unreadable] unless acc

    supers = (mysql_query("SELECT CONCAT(user,'@',host) FROM mysql.user WHERE Super_priv='Y'") || '').lines.map(&:strip)
    SdwParse.mysql_remote_admins(acc, supers).map { |f| "MySQL/MariaDB: #{f}" }
  end

  def runtime_local_infile
    mysql_var_check('local_infile') { |v| SdwParse.mysql_on?(v) ? "local_infile = #{v}" : nil }
  end

  def persistent_local_infile
    mysql_start_check('local-infile') { |v| %w[true on 1].include?(v.to_s.downcase) ? "local-infile at next start: #{v}" : nil }
  end

  def runtime_open_file_priv
    mysql_var_check('secure_file_priv') { |v| v.to_s.empty? ? 'secure_file_priv is empty (any directory)' : nil }
  end

  def persistent_open_file_priv
    mysql_start_check('secure-file-priv') { |v| v.to_s.empty? || v.to_s.start_with?('(No default') ? 'secure-file-priv unset at next start (any directory)' : nil }
  end

  # ── Redis, Memcached, MongoDB specifics ────────────────────────────────

  def redis_dangerous_commands
    redis_procs.filter_map do |p|
      conf = redis_file_conf(p) || { 'rename-command' => [] }
      acl = redis_cmd(p, 'ACL GETUSER default').to_s.tr("\n", ' ')
      if acl.include?('NOAUTH') || acl.include?('NOPERM')
        next "#{redis_label(p)}: ACL of the default user unreadable (#{acl.strip[0, 60]})"
      end

      left = SdwParse.redis_dangerous_left(conf, acl.include?('ERR') ? '' : acl)
      "#{redis_label(p)}: #{left.join(', ')} callable by the default user" unless left.empty?
    end
  end

  def runtime_memcached_udp
    memcached_procs.filter_map do |p|
      o = SdwParse.memcached_options(p[:args])
      "Memcached (pid #{p[:pid]}): UDP port #{o[:udp] || '11211 (default of this version)'} open" if SdwParse.memcached_udp_on?(o, memcached_version)
    end
  end

  def mongo_javascript
    mongo_procs.filter_map do |p|
      o = mongo_options(p)
      "MongoDB (pid #{p[:pid]}): server-side JavaScript enabled (security.javascriptEnabled / --noscripting)" unless o[:javascript] == false
    end
  end

  # ── every engine ───────────────────────────────────────────────────────

  def runtime_root_servers
    (pg_procs + mysql_procs + redis_procs + mongo_procs + memcached_procs + es_procs).select { |p| p[:uid].zero? }
                                                                                   .map { |p| "#{p[:comm]} (pid #{p[:pid]}) runs as root" }
  end

  # Data directories other users can enter or read.
  def open_data_dirs
    dirs = []
    dirs << ['PostgreSQL', pg_settings&.dig('data_directory')] if running?('postgresql')
    dirs << ['MySQL/MariaDB', mysql_variables&.dig('datadir')] if running?('mysql')
    redis_procs.each { |p| dirs << [redis_name(p), redis_dir(p)] }
    mongo_procs.each { |p| dirs << ['MongoDB', mongo_dbpath(p)] }
    es_procs.each { |p| dirs << [es_name(p), es_data_dir(p)] }
    dirs.filter_map do |engine, dir|
      next "#{engine}: data directory unknown (server settings unreadable)" if dir.to_s.empty?

      mode = cmd_ok("stat -L -c %a #{Shellwords.escape(dir)} 2>/dev/null").to_s.strip
      next "#{engine}: #{dir} not found" if mode.empty?

      "#{engine}: #{dir} mode #{mode} (others have access)" unless (mode.to_i(8) & 0o007).zero?
    end
  end

  private

  def procs
    inspec.sdw_procs
  end

  def esc(s)
    Shellwords.escape(s)
  end

  # ── PostgreSQL ─────────────────────────────────────────────────────────

  def pg_procs
    procs.named('postgres', 'postmaster').reject { |p| p[:args].first.to_s.start_with?('postgres:') }
  end

  def psql(sql)
    inner = "psql -XAtq -c #{esc(sql)}"
    cmd = which('runuser') ? "runuser -u #{esc(@pg_user)} -- #{inner}" : "su -s /bin/sh #{esc(@pg_user)} -c #{esc(inner)}"
    r = sh("cd / && #{cmd} 2>&1")
    r.exit_status.zero? ? r.stdout : nil
  end

  def pg_hba
    SdwMemo.fetch(:pg_hba) do
      out = psql("SELECT type, array_to_string(database, ','), array_to_string(user_name, ','), coalesce(address, ''), auth_method, line_number FROM pg_hba_file_rules WHERE error IS NULL")
      out && SdwParse.pg_hba_rows(out)
    end
  end

  def pg_settings
    SdwMemo.fetch(:pg_settings) do
      out = psql("SELECT name || '=' || setting FROM pg_settings WHERE name IN ('password_encryption','ssl','log_connections','log_disconnections','listen_addresses','data_directory')")
      out&.lines&.to_h { |l| l.chomp.split('=', 2) }
    end
  end

  def pg_unreadable
    "PostgreSQL: running, but psql as #{@pg_user} could not read its settings"
  end

  # ── MySQL / MariaDB ────────────────────────────────────────────────────

  def mysql_procs
    procs.named('mysqld', 'mariadbd')
  end

  def mysql_query(sql)
    client = which('mariadb') || which('mysql')
    return nil unless client

    r = sh("#{client} #{@mysql_options} -N -B -e #{esc(sql)} 2>&1")
    r.exit_status.zero? ? r.stdout : nil
  end

  # Accounts that can log in. MySQL keeps them in mysql.user; MariaDB 10.4+
  # in mysql.global_priv (its mysql.user view has no account_locked).
  def mysql_accounts
    SdwMemo.fetch(:mysql_accounts) do
      out = mysql_query("SELECT user, host, plugin, IF(COALESCE(authentication_string,'')='',1,0), account_locked FROM mysql.user") ||
            mysql_query("SELECT user, host, JSON_VALUE(priv,'$.plugin'), IF(COALESCE(JSON_VALUE(priv,'$.authentication_string'),'')='',1,0), " \
                        "IF(JSON_VALUE(priv,'$.account_locked') IN ('true','1'),'Y','N') FROM mysql.global_priv")
      out && SdwParse.mysql_accounts(out)
    end
  end

  def mysql_variables
    SdwMemo.fetch(:mysql_variables) do
      out = mysql_query("SHOW GLOBAL VARIABLES WHERE Variable_name IN ('local_infile','secure_file_priv','require_secure_transport','bind_address','skip_networking','datadir','version')")
      out&.lines&.to_h { |l| k, v = l.chomp.split("\t", 2); [k, v.to_s] }
    end
  end

  def mysql_start_values
    SdwMemo.fetch(:mysql_start) do
      bin = which('mariadbd') || which('mysqld')
      bin && SdwParse.mysqld_help_values(sh("#{bin} --verbose --help 2>/dev/null").stdout)
    end
  end

  def mysql_var_check(name)
    return [] unless running?('mysql')

    v = mysql_variables
    return [mysql_unreadable] unless v

    f = yield(v[name])
    f ? ["MySQL/MariaDB: #{f}"] : []
  end

  def mysql_start_check(name)
    return [] unless running?('mysql')

    v = mysql_start_values
    return ['MySQL/MariaDB: the server options of the next start could not be read (mysqld --verbose --help)'] if v.nil? || v.empty?

    f = yield(v[name])
    f ? ["MySQL/MariaDB: #{f}"] : []
  end

  def mysql_unreadable
    "MySQL/MariaDB: running, but the client could not query it as root (socket authentication, /root/.my.cnf or the sdw_mysql_client_options input)"
  end

  # ── Redis / Valkey ─────────────────────────────────────────────────────

  def redis_procs
    procs.named('redis-server', 'valkey-server')
  end

  def redis_name(p)
    p[:comm].start_with?('valkey') ? 'Valkey' : 'Redis'
  end

  # Address from the process title ("redis-server 127.0.0.1:6379").
  def redis_addr(p)
    m = p[:args].join(' ').match(/(\S+):(\d+)\s*\z/)
    host = m ? m[1] : '127.0.0.1'
    host = '127.0.0.1' if ['*', '0.0.0.0', ''].include?(host)
    [host.delete_prefix('[').delete_suffix(']'), m ? m[2] : '6379']
  end

  def redis_label(p)
    "#{redis_name(p)} port #{redis_addr(p).last}"
  end

  # Addresses of the clear-text port: CONFIG GET bind when readable, else
  # the host of the process title ("*" = every address).
  def redis_bind(p)
    b = redis_server_config(p)&.dig('bind').to_s.split.map { |h| h.delete_prefix('-') }
    b = [p[:args].join(' ')[/(\S+):\d+\s*\z/, 1] || '*'] if b.empty?
    b
  end

  # Data directory: the config file, the live settings, or the working
  # directory of the process (Redis changes into `dir` at start).
  def redis_dir(p)
    d = redis_file_conf(p)&.dig('dir').to_s
    d = redis_server_config(p)&.dig('dir').to_s unless d.start_with?('/')
    d = cmd_ok("readlink /proc/#{p[:pid]}/cwd 2>/dev/null").to_s.strip unless d.start_with?('/')
    d.start_with?('/') ? d : nil
  end

  def redis_cli(p)
    p[:comm].start_with?('valkey') ? (which('valkey-cli') || which('redis-cli')) : (which('redis-cli') || which('valkey-cli'))
  end

  def redis_cmd(p, cmd, auth: true)
    cli = redis_cli(p)
    return nil unless cli

    host, port = redis_addr(p)
    pass = auth ? redis_file_conf(p)&.dig('requirepass') : nil
    env = pass.to_s.empty? ? '' : "REDISCLI_AUTH=#{esc(pass)} "
    sh("#{env}timeout 5 #{cli} --no-auth-warning -h #{esc(host)} -p #{esc(port)} #{cmd} 2>&1").stdout
  end

  def redis_server_config(p)
    SdwMemo.fetch([:redis_config, p[:pid]]) do
      out = redis_cmd(p, "CONFIG GET '*'").to_s
      out.include?('NOAUTH') || out.include?('ERR') || out.strip.empty? ? nil : SdwParse.redis_config_get(out)
    end
  end

  def redis_server_requires_auth?(p)
    c = redis_server_config(p)
    return true if c.nil? && redis_cmd(p, 'PING', auth: false).to_s.include?('NOAUTH')
    return false unless c

    !c['requirepass'].to_s.empty? || !redis_cmd(p, 'ACL GETUSER default').to_s.include?('nopass')
  end

  def redis_conf_path(p)
    SdwMemo.fetch([:redis_conf_path, p[:pid]]) do
      info = redis_cmd(p, 'INFO server', auth: false).to_s
      path = info[/^config_file:(\S+)/, 1]
      path ||= %w[/etc/redis/redis.conf /etc/redis.conf /etc/valkey/valkey.conf /etc/redis/valkey.conf /usr/local/etc/redis/redis.conf].find { |f| read_file(f) }
      path
    end
  end

  def redis_file_conf(p)
    path = redis_conf_path(p)
    text = path && read_file(path)
    text && SdwParse.redis_conf(text)
  end

  # ── MongoDB ────────────────────────────────────────────────────────────

  def mongo_procs
    procs.named('mongod')
  end

  def mongo_yaml(p)
    a = p[:args]
    i = a.index('--config') || a.index('-f')
    path = i ? a[i + 1] : a.grep(/\A--config=/).first&.split('=', 2)&.last
    text = path && read_file(path)
    text ? (YAML.safe_load(text) rescue {}) : {}
  end

  def mongo_options(p)
    SdwMemo.fetch([:mongo_opts, p[:pid]]) { SdwParse.mongod_options(p[:args], mongo_yaml(p)) }
  end

  def mongo_addr(p)
    a = p[:args]
    port = (a.index('--port') && a[a.index('--port') + 1]) || mongo_yaml(p).dig('net', 'port') || 27_017
    host = mongo_options(p)[:bind_ip].to_s.split(',').first.to_s.strip
    host = '127.0.0.1' if host.empty? || host == '0.0.0.0' || host == 'localhost' || mongo_options(p)[:bind_all]
    [host, port.to_s]
  end

  def mongo_dbpath(p)
    a = p[:args]
    (a.index('--dbpath') && a[a.index('--dbpath') + 1]) || mongo_yaml(p).dig('storage', 'dbPath') ||
      (read_file('/etc/mongod.conf') ? '/var/lib/mongodb' : '/data/db')
  end

  # ── Memcached ──────────────────────────────────────────────────────────

  def memcached_procs
    procs.named('memcached')
  end

  def memcached_version
    SdwMemo.fetch(:memcached_version) { which('memcached') ? sh('memcached -V 2>&1').stdout.to_s[/([\d.]+)/, 1] : nil }
  end

  # ── Elasticsearch / OpenSearch ─────────────────────────────────────────

  def es_procs
    procs.matching(/org\.(elasticsearch|opensearch)\.bootstrap/)
  end

  def es_name(p)
    p[:args].join(' ').include?('opensearch') ? 'OpenSearch' : 'Elasticsearch'
  end

  # Settings of elasticsearch.yml / opensearch.yml flattened to dotted keys,
  # overridden by the settings the server takes from its environment (the
  # Docker images pass them so: xpack.security.enabled=false) and by the
  # -Ekey=value options of the launcher.
  def es_yaml(p)
    SdwMemo.fetch([:es_yaml, p[:pid]]) do
      family = procs.matching(/org\.(elasticsearch|opensearch)\./)
      home = family.flat_map { |q| q[:args] }.grep(/\A-D(es|opensearch)\.path\.home=/).first&.split('=', 2)&.last
      candidates = ['/etc/elasticsearch/elasticsearch.yml', '/etc/opensearch/opensearch.yml',
                    '/usr/share/elasticsearch/config/elasticsearch.yml', '/usr/share/opensearch/config/opensearch.yml']
      candidates.unshift("#{home}/config/elasticsearch.yml", "#{home}/config/opensearch.yml") if home
      text = candidates.filter_map { |f| read_file(f) }.first
      y = text ? (YAML.safe_load(text) rescue nil) : nil
      flat = {}
      walk = lambda do |h, prefix|
        h.each { |k, v| v.is_a?(Hash) ? walk.call(v, "#{prefix}#{k}.") : flat["#{prefix}#{k}"] = v }
      end
      walk.call(y, '') if y.is_a?(Hash)
      flat['path.home'] ||= home if home
      env = cmd_ok("tr '\\000' '\\n' < /proc/#{p[:pid]}/environ 2>/dev/null").to_s
      env.lines.map(&:chomp).grep(/\A[a-z0-9_]+(\.[a-z0-9_]+)+=/).each { |l| k, v = l.split('=', 2); flat[k] = v }
      family.each do |q|
        q[:args].grep(/\A-E[^=]+=/).each { |a| k, v = a.delete_prefix('-E').split('=', 2); flat[k] = v }
      end
      flat
    end
  end

  # First data path: path.data (a string or a list), else the server's
  # default, $ES_HOME/data (the packages set path.data explicitly).
  def es_data_dir(p)
    v = es_yaml(p)['path.data']
    v = v.to_s.delete('[]').split(',').first if v.is_a?(String)
    v = Array(v).first.to_s.strip
    return v unless v.empty?

    home = es_setting(p, 'path.home')
    home ? "#{home}/data" : nil
  end

  def es_setting(p, key)
    v = es_yaml(p)[key]
    v.nil? ? nil : v.to_s
  end

  # HTTP status of an unauthenticated GET on the local REST port, or nil.
  def es_status(p)
    SdwMemo.fetch([:es_status, p[:pid]]) do
      %w[http https].lazy.map { |scheme| http_code("#{scheme}://127.0.0.1:9200/") }.find { |c| c =~ /\A[1-5]\d\d\z/ }
    end
  end

  def http_code(url)
    if which('curl')
      sh("curl -sk -o /dev/null -w '%{http_code}' --max-time 5 #{url} 2>/dev/null").stdout.to_s.strip
    else
      sh("wget -q -S -O /dev/null --no-check-certificate -T 5 #{url} 2>&1").stdout.to_s[%r{HTTP/\S+\s+(\d{3})}, 1].to_s
    end
  end
end
