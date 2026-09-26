# frozen_string_literal: true

# Pure parsing and evaluation helpers: text in, facts out. No InSpec, no I/O,
# so profile/test/parse_test.rb exercises every branch with plain Ruby,
# including hardware and services this machine does not have.
require 'json'

module ::SdwParse
  module_function

  # ── TLS protocol names ───────────────────────────────────────────────────

  LEGACY_TLS = %w[SSLv2 SSLv3 TLSv1 TLSv1.1].freeze
  ALL_TLS = %w[SSLv3 TLSv1 TLSv1.1 TLSv1.2 TLSv1.3].freeze

  # "TLSv1.0" and "tlsv1_1" style spellings to the canonical names above.
  def tls_name(tok)
    t = tok.to_s.strip.delete_prefix('+').delete_prefix('-')
    case t.downcase.tr('_', '.')
    when 'sslv2' then 'SSLv2'
    when 'sslv3' then 'SSLv3'
    when 'tlsv1', 'tlsv1.0', 'tls1', 'tls1.0' then 'TLSv1'
    when 'tlsv1.1', 'tls1.1' then 'TLSv1.1'
    when 'tlsv1.2', 'tls1.2' then 'TLSv1.2'
    when 'tlsv1.3', 'tls1.3' then 'TLSv1.3'
    when 'all' then 'all'
    end
  end

  # Protocols older than TLS 1.2 in a list of names.
  def legacy(protocols)
    Array(protocols).map { |p| tls_name(p) }.compact & LEGACY_TLS
  end

  # MinProtocol of the system OpenSSL configuration (openssl.cnf, RHEL crypto
  # policy back-end), nil when it sets none. Servers that keep their default
  # protocol list inherit it.
  def openssl_min_protocol(cnf_text)
    v = cnf_text.to_s.lines.map { |l| l.sub(/#.*/, '') }.grep(/^\s*(TLS\.)?MinProtocol\s*=/).last
    v && tls_name(v.split('=', 2).last)
  end

  def modern_floor?(system_min)
    %w[TLSv1.2 TLSv1.3].include?(system_min)
  end

  # Apache SSLProtocol / lighttpd-style list: "all -SSLv3 -TLSv1 +TLSv1.2".
  # Tokens without a sign replace the set; +X adds, -X removes.
  def apache_protocols(spec)
    set = []
    spec.to_s.split.each do |tok|
      name = tls_name(tok)
      next unless name

      names = name == 'all' ? ALL_TLS : [name]
      case tok[0]
      when '+' then set |= names
      when '-' then set -= names
      else set = names.dup
      end
    end
    set
  end

  # ── nginx -T ──────────────────────────────────────────────────────────────

  # One directive: name, arguments, and children for a block ({ ... }).
  NginxNode = Struct.new(:name, :args, :children, :file, :line)

  # Files of an `nginx -T` dump, in order: { path => text }.
  def nginx_dump_files(dump)
    files = {}
    cur = nil
    dump.to_s.each_line do |l|
      if (m = l.match(/\A# configuration file (.+):\s*\z/))
        cur = m[1]
        files[cur] = +''
      elsif cur
        files[cur] << l
      end
    end
    files
  end

  def nginx_tokens(text)
    toks = []
    s = text.to_s
    i = 0
    line = 1
    while i < s.length
      c = s[i]
      if c == "\n"
        line += 1
        i += 1
      elsif c =~ /\s/
        i += 1
      elsif c == '#'
        i += 1 while i < s.length && s[i] != "\n"
      elsif c == '{' || c == '}' || c == ';'
        toks << [c, line]
        i += 1
      elsif c == '"' || c == "'"
        q = c
        j = i + 1
        buf = +''
        while j < s.length && s[j] != q
          if s[j] == '\\' && j + 1 < s.length
            buf << s[j + 1]
            j += 2
          else
            line += 1 if s[j] == "\n"
            buf << s[j]
            j += 1
          end
        end
        toks << [buf, line, :quoted]
        i = j + 1
      else
        j = i
        j += 1 while j < s.length && s[j] !~ /[\s{};]/
        toks << [s[i...j], line]
        i = j
      end
    end
    toks
  end

  # The configuration as nginx builds it: the main file with every include
  # replaced by the files it names (as they appear in the dump).
  def nginx_tree(dump, main = nil)
    files = nginx_dump_files(dump)
    main ||= files.keys.first
    return [] unless main

    nginx_parse_file(files, main, File.dirname(main), 0)
  end

  def nginx_parse_file(files, path, prefix, depth)
    return [] if depth > 20

    toks = nginx_tokens(files[path])
    pos = 0
    parse = lambda do
      nodes = []
      words = []
      start = nil
      while pos < toks.size
        t, ln, quoted = toks[pos]
        pos += 1
        if t == ';' && !quoted
          name, *args = words
          words = []
          next unless name

          if name == 'include' && args.size == 1
            nodes.concat(nginx_include(files, args.first, prefix, depth))
          else
            nodes << NginxNode.new(name, args, nil, path, start)
          end
        elsif t == '{' && !quoted
          name, *args = words
          words = []
          nodes << NginxNode.new(name, args, parse.call, path, start)
        elsif t == '}' && !quoted
          return nodes
        else
          start = ln if words.empty?
          words << t
        end
      end
      nodes
    end
    parse.call
  end

  def nginx_include(files, pattern, prefix, depth)
    pat = pattern.start_with?('/') ? pattern : File.join(prefix, pattern)
    files.keys.select { |f| File.fnmatch(pat, f, File::FNM_PATHNAME) }.sort.flat_map do |f|
      nginx_parse_file(files, f, prefix, depth + 1)
    end
  end

  # Visits every node with the chain of its enclosing blocks.
  def nginx_walk(nodes, parents = [], &blk)
    nodes.each do |n|
      blk.call(n, parents)
      nginx_walk(n.children, parents + [n], &blk) if n.children
    end
  end

  def nginx_blocks(nodes, name)
    out = []
    nginx_walk(nodes) { |n, parents| out << [n, parents] if n.children && n.name == name }
    out
  end

  # Value of a directive in a block, or inherited from the enclosing blocks.
  def nginx_effective(block, parents, name)
    ([block] + parents.reverse).each do |b|
      d = Array(b&.children).reverse.find { |n| n.name == name && n.children.nil? }
      return d.args if d
    end
    nil
  end

  def nginx_top(tree, name)
    tree.reverse.find { |n| n.name == name && n.children.nil? }&.args
  end

  # Where the version gets shown: the http block when the effective value
  # there is not "off" (unset means on), and every server or location that
  # sets it back on.
  def nginx_server_tokens_on(tree)
    out = []
    nginx_blocks(tree, 'http').each do |blk, parents|
      v = nginx_effective(blk, parents, 'server_tokens') || nginx_top(tree, 'server_tokens')
      next if v&.first.to_s.downcase == 'off'

      out << "http (#{blk.file}:#{blk.line}): server_tokens #{v ? v.join(' ') : 'not set (default on)'}"
    end
    nginx_walk(tree) do |n, parents|
      next unless n.name == 'server_tokens' && n.children.nil? && n.args.first.to_s.downcase != 'off'
      next unless parents.last && %w[server location if].include?(parents.last.name)

      out << "#{parents.last.name} (#{n.file}:#{n.line}): server_tokens #{n.args.join(' ')}"
    end
    out
  end

  def nginx_autoindex_on(tree)
    out = []
    nginx_walk(tree) do |n, _|
      next unless n.name == 'autoindex' && n.children.nil? && n.args.first.to_s.downcase == 'on'

      out << "autoindex on (#{n.file}:#{n.line})"
    end
    out
  end

  # Servers that terminate TLS and still accept a protocol older than
  # TLS 1.2. The default of ssl_protocols depends on the nginx version.
  # A server that keeps the default list is left out when the system OpenSSL
  # already refuses anything below TLS 1.2 (system_min).
  def nginx_legacy_tls(tree, version, system_min = nil)
    default = version_at_least?(version, '1.23.4') ? %w[TLSv1.2 TLSv1.3] : %w[TLSv1 TLSv1.1 TLSv1.2 TLSv1.3]
    out = []
    nginx_blocks(tree, 'server').each do |srv, parents|
      tls = srv.children.any? { |n| n.name == 'listen' && n.args.map(&:downcase).include?('ssl') } ||
            srv.children.any? { |n| n.name == 'ssl' && n.args.first.to_s.downcase == 'on' }
      next unless tls

      set = nginx_effective(srv, parents, 'ssl_protocols')
      next if set.nil? && modern_floor?(system_min)

      bad = legacy(set || default)
      next if bad.empty?

      label = nginx_effective(srv, [], 'server_name')&.first || srv.children.find { |n| n.name == 'listen' }&.args&.first
      out << "server #{label} (#{srv.file}:#{srv.line}): ssl_protocols allows #{bad.join(', ')}"
    end
    out
  end

  # The `user` of the worker processes; nginx keeps "nobody" when unset.
  def nginx_user(tree)
    (nginx_top(tree, 'user') || ['nobody']).first
  end

  # ── Apache httpd ─────────────────────────────────────────────────────────

  # `apachectl -t -D DUMP_INCLUDES`: [[depth, line_in_parent, path]], in order.
  def apache_includes(out)
    rows = []
    out.to_s.each_line do |l|
      m = l.match(/\A(\s*)\((\*|\d+)\)\s+(\S.*?)\s*\z/)
      next unless m

      rows << [m[1].size, m[2] == '*' ? nil : m[2].to_i, m[3]]
    end
    return rows if rows.empty?

    base = rows.first[0]
    step = rows.map(&:first).uniq.sort.each_cons(2).map { |a, b| b - a }.min || 2
    rows.map { |d, ln, p| [(d - base) / step, ln, p] }
  end

  # The configuration as httpd reads it: each file with its Include lines
  # replaced by the included files, from the DUMP_INCLUDES tree. `read` maps a
  # path to its text.
  def apache_flatten(includes, read)
    return '' if includes.empty?

    children = Hash.new { |h, k| h[k] = [] }
    stack = []
    includes.each_with_index do |(depth, _line, _path), i|
      stack = stack.first(depth)
      children[stack.last] << i if depth.positive?
      stack << i
    end
    expand = lambda do |i, guard|
      return '' if guard > 30

      _, _, path = includes[i]
      lines = read.call(path).to_s.lines
      kids = children[i].group_by { |k| includes[k][1] }
      out = +''
      lines.each_with_index do |l, n|
        if (ks = kids[n + 1])
          ks.each { |k| out << expand.call(k, guard + 1) << "\n" }
        else
          out << l
        end
      end
      out
    end
    expand.call(0, 0)
  end

  ApacheDirective = Struct.new(:name, :args, :sections)

  # Directives in order, each with the stack of sections it sits in
  # (["VirtualHost *:443", "Directory /var/www"]).
  def apache_directives(text)
    out = []
    sections = []
    joined = text.to_s.gsub(/\\\n/, ' ')
    joined.each_line do |raw|
      l = raw.strip
      next if l.empty? || l.start_with?('#')

      if (m = l.match(%r{\A</\s*([A-Za-z]+)\s*>}))
        sections.pop if sections.any?
        next
      end
      if (m = l.match(/\A<\s*([A-Za-z]+)\s*(.*?)\s*>\z/))
        sections << "#{m[1]} #{m[2]}".strip
        next
      end
      name, rest = l.split(/\s+/, 2)
      out << ApacheDirective.new(name, split_args(rest.to_s), sections.dup)
    end
    out
  end

  def split_args(s)
    s.scan(/"([^"]*)"|'([^']*)'|(\S+)/).map { |a, b, c| a || b || c }
  end

  def apache_global(dirs, name)
    dirs.reverse.find { |d| d.name.casecmp?(name) && d.sections.none? { |s| s =~ /\AVirtualHost/i } }
  end

  def apache_in_vhosts(dirs, name)
    dirs.select { |d| d.name.casecmp?(name) && d.sections.any? { |s| s =~ /\AVirtualHost/i } }
  end

  # ServerTokens (global, default Full) and ServerSignature (anywhere).
  def apache_version_disclosure(dirs)
    out = []
    tokens = apache_global(dirs, 'ServerTokens')&.args&.first || 'Full'
    out << "ServerTokens #{tokens}" unless %w[prod productonly].include?(tokens.downcase)
    dirs.select { |d| d.name.casecmp?('ServerSignature') }.each do |d|
      v = d.args.first.to_s
      out << "ServerSignature #{v}#{d.sections.empty? ? '' : " in #{d.sections.join(' > ')}"}" unless v.casecmp?('off')
    end
    out
  end

  # TraceEnable defaults to On.
  def apache_trace_enabled(dirs)
    out = []
    g = apache_global(dirs, 'TraceEnable')&.args&.first || 'On'
    out << "TraceEnable #{g} (server)" unless g.casecmp?('off')
    apache_in_vhosts(dirs, 'TraceEnable').each do |d|
      out << "TraceEnable #{d.args.first} in #{d.sections.join(' > ')}" unless d.args.first.to_s.casecmp?('off')
    end
    out
  end

  # Options that grant Indexes: "Indexes", "+Indexes" or "All".
  def apache_indexes(dirs)
    dirs.select { |d| d.name.casecmp?('Options') }.filter_map do |d|
      grants = d.args.any? { |a| %w[indexes +indexes all].include?(a.downcase) }
      next unless grants

      "Options #{d.args.join(' ')}#{d.sections.empty? ? '' : " in #{d.sections.join(' > ')}"}"
    end
  end

  # SSLProtocol of each TLS virtual host (its own, else the server's, else
  # httpd's default "all -SSLv3").
  def apache_legacy_tls(dirs, system_min = nil)
    global = apache_global(dirs, 'SSLProtocol')&.args&.join(' ')
    vhosts = dirs.map { |d| d.sections.find { |s| s =~ /\AVirtualHost/i } }.compact.uniq
    out = []
    vhosts.each do |vh|
      inside = dirs.select { |d| d.sections.include?(vh) }
      engine = inside.reverse.find { |d| d.name.casecmp?('SSLEngine') }
      next unless engine && engine.args.first.to_s.casecmp?('on')

      spec = inside.reverse.find { |d| d.name.casecmp?('SSLProtocol') }&.args&.join(' ') || global
      next if spec.nil? && modern_floor?(system_min)

      spec ||= 'all -SSLv3'
      bad = legacy(apache_protocols(spec))
      out << "<#{vh}>: SSLProtocol #{spec} allows #{bad.join(', ')}" unless bad.empty?
    end
    out
  end

  # `DUMP_RUN_CFG`: User: name="www-data" id=33
  def apache_run_user(run_cfg)
    m = run_cfg.to_s.match(/^User:\s+name="([^"]*)"\s+id=(\d+)/)
    m ? { name: m[1], id: m[2].to_i } : nil
  end

  # ── HAProxy ──────────────────────────────────────────────────────────────

  # Sections in order: [{ kind:, name:, lines: [[keyword args...], ...] }].
  def haproxy_sections(text)
    secs = []
    cur = nil
    text.to_s.each_line do |raw|
      l = raw.sub(/(^|\s)#.*$/, '').strip
      next if l.empty?

      words = l.split
      if %w[global defaults frontend backend listen peers resolvers userlist program cache mailers ring http-errors].include?(words.first) && raw !~ /\A\s/
        cur = { kind: words.first, name: words[1].to_s, lines: [] }
        secs << cur
      elsif cur
        cur[:lines] << words
      end
    end
    secs
  end

  def haproxy_min_tls(words)
    i = words.index('ssl-min-ver')
    return tls_name(words[i + 1]) if i && words[i + 1]

    return 'TLSv1.2' if words.include?('no-tlsv10') && words.include?('no-tlsv11')
    return 'TLSv1.1' if words.include?('no-tlsv10')

    nil
  end

  # `bind ... ssl` lines whose minimum protocol is below TLS 1.2. HAProxy 2.2
  # and later default to TLS 1.2.
  def haproxy_legacy_tls(secs, version, system_min = nil)
    global = secs.select { |s| s[:kind] == 'global' }.flat_map { |s| s[:lines] }
    opts = global.reverse.find { |w| w.first == 'ssl-default-bind-options' }
    default = version_at_least?(version, '2.2') ? 'TLSv1.2' : 'TLSv1'
    default = system_min if modern_floor?(system_min)
    base = (opts && haproxy_min_tls(opts)) || default
    out = []
    secs.each do |s|
      s[:lines].each do |w|
        next unless w.first == 'bind' && w.include?('ssl')

        min = haproxy_min_tls(w) || base
        out << "#{s[:kind]} #{s[:name]}: bind #{w[1]} accepts #{min} and later" if LEGACY_TLS.include?(min)
      end
    end
    out
  end

  def haproxy_open_stats(secs)
    secs.filter_map do |s|
      next unless %w[frontend listen backend defaults].include?(s[:kind])

      stats = s[:lines].select { |w| w.first == 'stats' }
      on = stats.any? { |w| %w[enable uri].include?(w[1]) }
      next unless on

      auth = stats.any? { |w| w[1] == 'auth' } ||
             s[:lines].any? { |w| w.first == 'http-request' && w[1] == 'auth' }
      "#{s[:kind]} #{s[:name]}: statistics page without authentication" unless auth
    end
  end

  # ── Caddy (JSON from `caddy adapt`) ──────────────────────────────────────

  # nil when the admin endpoint is disabled or local only, else its address.
  def caddy_admin_exposed(json)
    admin = json.is_a?(Hash) ? (json['admin'] || {}) : {}
    return nil if admin['disabled'] == true

    listen = admin['listen'] || 'localhost:2019'
    return nil if listen.start_with?('unix/')

    host = listen.sub(%r{\Atcp/}, '').rpartition(':').first
    loopback?(host) ? nil : listen
  end

  # ── Tomcat server.xml ────────────────────────────────────────────────────

  def tomcat_shutdown(xml)
    m = xml.to_s.match(/<Server\b([^>]*)>/m)
    return nil unless m

    attrs = m[1].scan(/([A-Za-z]+)\s*=\s*"([^"]*)"/).to_h
    { port: attrs['port'], shutdown: attrs['shutdown'] }
  end

  # The shutdown port is safe when disabled (-1) or its command is not the
  # well-known default.
  def tomcat_shutdown_open?(xml)
    s = tomcat_shutdown(xml)
    return false unless s

    s[:port].to_s != '-1' && s[:shutdown].to_s.upcase == 'SHUTDOWN'
  end

  # ── PostgreSQL ───────────────────────────────────────────────────────────

  # Rows of `pg_hba_file_rules` as "type|database|user_name|address|auth_method|line_number".
  def pg_hba_rows(out)
    out.to_s.lines.filter_map do |l|
      t, db, user, addr, method, line = l.chomp.split('|', -1)
      next unless method

      { type: t, database: db, user: user, address: addr, method: method, line: line }
    end
  end

  def pg_rule(r)
    "line #{r[:line]}: #{[r[:type], r[:database], r[:user], r[:address], r[:method]].reject { |x| x.to_s.empty? }.join(' ')}"
  end

  def pg_trust(rows)
    rows.select { |r| r[:method] == 'trust' }.map { |r| pg_rule(r) }
  end

  def pg_weak_password(rows)
    rows.select { |r| %w[md5 password].include?(r[:method]) }.map { |r| pg_rule(r) }
  end

  def pg_remote?(r)
    addr = r[:address].to_s.split('/').first.to_s
    r[:type].to_s.start_with?('host') && !loopback?(addr) && addr != 'samehost'
  end

  # Network rules that do not require TLS (host, hostnossl) and accept.
  # Does listen_addresses open a TCP socket beyond the loopback? Empty means
  # Unix sockets only.
  def pg_listens_remote?(listen)
    listen.to_s.split(',').map(&:strip).any? { |h| !h.empty? && !loopback?(h) }
  end

  def pg_plaintext(rows)
    rows.select { |r| %w[host hostnossl].include?(r[:type]) && pg_remote?(r) && r[:method] != 'reject' }.map { |r| pg_rule(r) }
  end

  # ── MySQL / MariaDB ─────────────────────────────────────────────────────

  # Rows "user|host|plugin|empty" (empty: 1 when authentication_string is empty).
  # Rows "user\thost\tplugin\tempty(1|0)\tlocked(Y|N)"; locked accounts
  # cannot log in and are left out.
  def mysql_accounts(out)
    out.to_s.lines.filter_map do |l|
      user, host, plugin, empty, locked = l.chomp.split("\t", -1)
      next unless host
      next if locked.to_s.strip.upcase == 'Y'

      { user: user, host: host, plugin: plugin.to_s, empty: empty.to_s.strip == '1' }
    end
  end

  SOCKET_PLUGINS = %w[unix_socket auth_socket].freeze

  def mysql_passwordless(accounts)
    accounts.select { |a| a[:empty] && !SOCKET_PLUGINS.include?(a[:plugin]) && a[:plugin] != 'mysql_no_login' && a[:plugin] != 'invalid' }
            .map { |a| "'#{a[:user]}'@'#{a[:host]}' has no password (#{a[:plugin].empty? ? 'no plugin' : a[:plugin]})" }
  end

  def mysql_anonymous(accounts)
    accounts.select { |a| a[:user].to_s.empty? }.map { |a| "anonymous account ''@'#{a[:host]}'" }
  end

  LOCAL_HOSTS = %w[localhost 127.0.0.1 ::1].freeze

  # Privileged accounts (root, or listed as SUPER) reachable from other hosts.
  def mysql_remote_admins(accounts, supers)
    accounts.select do |a|
      (a[:user] == 'root' || supers.include?("#{a[:user]}@#{a[:host]}")) && !LOCAL_HOSTS.include?(a[:host])
    end.map { |a| "'#{a[:user]}'@'#{a[:host]}' is an administrator reachable from other hosts" }
  end

  # `mysqld --verbose --help` table: option names to values ("local-infile  FALSE").
  def mysqld_help_values(out)
    h = {}
    started = false
    out.to_s.each_line do |l|
      if l =~ /\A-{5,}\s+-{5,}/
        started = true
        next
      end
      next unless started
      break if l.strip.empty?

      k, v = l.strip.split(/\s+/, 2)
      h[k.tr('_', '-')] = v.to_s.strip if k
    end
    h
  end

  def mysql_on?(v)
    %w[on 1 true yes].include?(v.to_s.downcase)
  end

  # ── Redis / Valkey ───────────────────────────────────────────────────────

  # redis.conf: last value of each directive, plus rename-command and user lines.
  def redis_conf(text)
    conf = { 'rename-command' => [], 'user' => [], 'include' => [] }
    text.to_s.each_line do |raw|
      l = raw.strip
      next if l.empty? || l.start_with?('#')

      k, v = l.split(/\s+/, 2)
      k = k.downcase
      if conf[k].is_a?(Array)
        conf[k] << v.to_s
      else
        conf[k] = v.to_s.strip.delete_prefix('"').delete_suffix('"')
      end
    end
    conf
  end

  # `CONFIG GET *` output: alternating names and values, one per line.
  def redis_config_get(out)
    lines = out.to_s.lines.map(&:chomp)
    lines.each_slice(2).to_h { |k, v| [k.to_s, v.to_s] }
  end

  DANGEROUS_REDIS = %w[FLUSHALL FLUSHDB CONFIG DEBUG MODULE SHUTDOWN].freeze

  # Dangerous commands still callable: not renamed to "" nor denied by ACL.
  def redis_dangerous_left(conf, acl_default)
    renamed = conf['rename-command'].map { |v| v.split.first.to_s.upcase }
    acl = acl_default.to_s
    DANGEROUS_REDIS.reject do |c|
      renamed.include?(c) || acl.include?('-@dangerous') || acl.include?("-#{c.downcase}") || acl =~ /\boff\b/
    end
  end

  # Does the file configuration require a password for the default user?
  def redis_conf_requires_auth?(conf)
    return true unless conf['requirepass'].to_s.empty?

    default = conf['user'].reverse.find { |u| u.split.first == 'default' }
    return false unless default

    words = default.split
    words.include?('off') || (!words.include?('nopass') && words.any? { |w| w.start_with?('>', '#') })
  end

  # ── MongoDB ──────────────────────────────────────────────────────────────

  # mongod options from its command line and its YAML config file (the file
  # is read at start; command line options win).
  def mongod_options(args, yaml)
    y = yaml.is_a?(Hash) ? yaml : {}
    o = {
      auth: y.dig('security', 'authorization').to_s == 'enabled',
      bind_ip: y.dig('net', 'bindIp'),
      bind_all: y.dig('net', 'bindIpAll') == true,
      tls_mode: y.dig('net', 'tls', 'mode') || y.dig('net', 'ssl', 'mode'),
      javascript: y.dig('security', 'javascriptEnabled'),
    }
    a = Array(args)
    o[:auth] = true if a.include?('--auth')
    o[:auth] = false if a.include?('--noauth')
    o[:bind_all] = true if a.include?('--bind_ip_all')
    if (i = a.index('--bind_ip'))
      o[:bind_ip] = a[i + 1]
    end
    a.grep(/\A--bind_ip=/).each { |x| o[:bind_ip] = x.split('=', 2).last }
    if (i = a.index('--tlsMode'))
      o[:tls_mode] = a[i + 1]
    end
    o[:javascript] = false if a.include?('--noscripting')
    o[:bind_ip] ||= 'localhost' unless o[:bind_all]
    o
  end

  def mongod_exposed?(o)
    return true if o[:bind_all]

    o[:bind_ip].to_s.split(',').map(&:strip).any? { |h| !loopback?(h) && !h.end_with?('.sock') }
  end

  # ── Memcached ────────────────────────────────────────────────────────────

  def memcached_options(args)
    a = Array(args)
    o = { listen: nil, udp: nil, sasl: false }
    a.each_with_index do |w, i|
      case w
      when '-l', '--listen' then o[:listen] = a[i + 1]
      when /\A--listen=(.+)/ then o[:listen] = Regexp.last_match(1)
      when /\A-l(.+)/ then o[:listen] = Regexp.last_match(1)
      when '-U', '--udp-port' then o[:udp] = a[i + 1]
      when /\A--udp-port=(.+)/ then o[:udp] = Regexp.last_match(1)
      when /\A-U(\d+)\z/ then o[:udp] = Regexp.last_match(1)
      when '-S', '--enable-sasl' then o[:sasl] = true
      end
    end
    o
  end

  # UDP is off when -U 0, and by default since memcached 1.5.6.
  def memcached_udp_on?(o, version)
    return o[:udp].to_s != '0' if o[:udp]

    !version_at_least?(version, '1.5.6')
  end

  def memcached_exposed?(o)
    return true if o[:listen].nil?

    o[:listen].split(',').map { |h| h.sub(/:\d+\z/, '') }.any? { |h| !loopback?(h) }
  end

  # ── TLS endpoints (openssl output) ───────────────────────────────────────

  # `openssl x509 -noout -enddate -text`: notAfter, key algorithm and size.
  def x509_facts(text)
    t = text.to_s
    not_after = t[/notAfter=(.+)$/, 1]
    bits = t[/Public-Key:\s*\((\d+)\s*bit\)/, 1]&.to_i
    algo = t[/Public Key Algorithm:\s*(\S+)/, 1]
    { not_after: not_after&.strip, bits: bits, algorithm: algo }
  end

  # Is a key too weak: RSA/DSA under min_rsa bits, EC under 256.
  def weak_key?(facts, min_rsa)
    return false unless facts[:bits]

    case facts[:algorithm].to_s
    when /rsa/i, /dsa/i then facts[:bits] < min_rsa
    when /ec|id-ecPublicKey/i then facts[:bits] < 256
    else false
    end
  end

  # Response headers of a raw HTTP exchange: { lowercase name => value }.
  def http_headers(raw)
    h = {}
    raw.to_s.each_line do |l|
      break if l.strip.empty? && !h.empty?
      next unless (m = l.match(/\A([A-Za-z0-9-]+):\s*(.*?)\s*\z/))

      h[m[1].downcase] = m[2]
    end
    h
  end

  # HSTS with a max-age of at least min_age seconds.
  def hsts_ok?(value, min_age)
    age = value.to_s[/max-age\s*=\s*"?(\d+)/i, 1]
    age && age.to_i >= min_age
  end

  # ── CPU, firmware, BMC ───────────────────────────────────────────────────

  # Flaws the kernel reports as not mitigated ("Vulnerable...").
  def cpu_vulnerable(vulns)
    vulns.select { |_, s| s.to_s.start_with?('Vulnerable') }.map { |k, s| "#{k}: #{s}" }.sort
  end

  # Flaws whose mitigation is only complete with SMT off.
  def cpu_smt_exposed(vulns)
    vulns.select { |_, s| s.to_s =~ /SMT (vulnerable|Host state unknown)/i }.map { |k, s| "#{k}: #{s}" }.sort
  end

  # Boot parameters that switch CPU flaw mitigations off.
  MITIGATION_OFF = /\A(mitigations=off|nospectre_v1|nospectre_v2|spectre_v2=off|spectre_v2_user=off|nopti|pti=off|
                      nospec_store_bypass_disable|spec_store_bypass_disable=off|mds=off|tsx_async_abort=off|l1tf=off|
                      mmio_stale_data=off|retbleed=off|srbds=off|gather_data_sampling=off|spectre_bhi=off|
                      reg_file_data_sampling=off|spec_rstack_overflow=off|noibrs|noibpb|kvm\.nx_huge_pages=off)\z/x.freeze

  def mitigation_off_params(cmdline)
    cmdline.to_s.split.grep(MITIGATION_OFF)
  end

  def nosmt_at_boot?(cmdline)
    cmdline.to_s.split.any? { |t| t == 'nosmt' || t == 'nosmt=force' || t =~ /\A(mitigations|mds|l1tf|tsx_async_abort|mmio_stale_data)=.*nosmt|\Al1tf=full,force\z/ }
  end

  def iommu_off_params(cmdline)
    cmdline.to_s.split.grep(/\A(intel_iommu=off|amd_iommu=off|iommu=off|iommu=pt|iommu\.passthrough=1)\z/)
  end

  # `ipmitool lan print`: is cipher suite 0 (no authentication) usable?
  # The "Cipher Suite Priv Max" string has one letter per suite; X is unused.
  def ipmi_cipher0_enabled?(lan_print)
    m = lan_print.to_s.match(/^Cipher Suite Priv Max\s*:\s*(\S+)/)
    return nil unless m

    m[1][0] != 'X'
  end

  # `ipmitool lan print`: privilege levels for which the NONE authentication
  # type is enabled ("Auth Type Enable : Callback : NONE MD5 ...").
  def ipmi_none_auth(lan_print)
    lines = lan_print.to_s.lines.drop_while { |l| l !~ /^Auth Type Enable/ }
    lines = lines.take_while.with_index { |l, i| i.zero? || l =~ /^\s+:/ }
    lines.filter_map do |l|
      m = l.match(/:\s*(Callback|User|Operator|Admin|OEM)\s*:(.*)$/)
      m[1] if m && m[2].split.include?('NONE')
    end
  end

  # `fwupdmgr get-updates --json`: [:ok|:pending|:unknown, detail].
  def fwupd_state(exit_status, stdout, stderr)
    text = "#{stdout}\n#{stderr}"
    if exit_status.to_i.zero?
      data = begin
        JSON.parse(stdout.to_s)
      rescue StandardError
        nil
      end
      return [:unknown, text.strip[0, 200]] unless data.is_a?(Hash)

      pending = Array(data['Devices']).flat_map do |d|
        Array(d['Releases']).map { |r| "#{d['Name']}: #{r['Version']}" }
      end
      return pending.empty? ? [:ok, 'no update'] : [:pending, pending]
    end
    return [:ok, 'no updatable device'] if text =~ /No updatable devices|No updates available|No updates/i
    return [:unknown, 'firmware metadata never refreshed (fwupdmgr refresh)'] if text =~ /metadata|refresh/i

    [:unknown, text.strip[0, 200]]
  end

  # ── Shared ───────────────────────────────────────────────────────────────

  def loopback?(host)
    h = host.to_s.delete_prefix('[').delete_suffix(']').downcase
    h == 'localhost' || h.start_with?('127.') || h == '::1' || h == 'ip6-localhost' || h.start_with?('/')
  end

  # Is version a at least b ("1.24.0" vs "1.23.4")? An unknown version is not.
  def version_at_least?(a, b)
    return false if a.to_s.empty?

    x = a.to_s.scan(/\d+/).map(&:to_i)
    y = b.to_s.scan(/\d+/).map(&:to_i)
    n = [x.size, y.size].max
    ((x + [0] * (n - x.size)) <=> (y + [0] * (n - y.size))) >= 0
  end
end
