# frozen_string_literal: true

require 'json'

# Web servers as they resolve their own configuration: `nginx -T`, httpd's
# include tree (DUMP_INCLUDES) and run settings (DUMP_RUN_CFG), the HAProxy
# files the running process was given, `caddy adapt`, `lighttpd -p`, and the
# server.xml of the running Tomcat. A server that is installed but whose
# configuration cannot be read is reported, never skipped (fail-closed).
class ::SdwWeb < Inspec.resource(1)
  name 'sdw_web'
  desc 'Effective configuration of the web servers installed on the target.'
  example "describe sdw_web do\n  its('version_disclosure') { should be_empty }\nend"

  include SdwHelpers

  SERVERS = %w[nginx apache haproxy caddy lighttpd tomcat].freeze

  def installed
    SdwMemo.fetch(:web_installed) { SERVERS.select { |s| send("#{s}?") } }
  end

  def any?
    !installed.empty?
  end

  def installed?(name)
    installed.include?(name)
  end

  def label
    installed.empty? ? 'web servers (none installed)' : "web servers (#{installed.join(', ')})"
  end

  # ── findings (config: what the configuration says) ─────────────────────

  def version_disclosure
    out = []
    out.concat(unreadable(%w[nginx apache lighttpd]))
    out.concat(SdwParse.nginx_server_tokens_on(nginx_tree).map { |f| "nginx: #{f}" }) if nginx_tree
    out.concat(SdwParse.apache_version_disclosure(apache_dirs).map { |f| "Apache: #{f}" }) if apache_dirs
    if lighttpd_conf
      tag = lighttpd_value('server.tag')
      out << "lighttpd: server.tag #{tag.nil? ? 'unset (lighttpd/version)' : tag}" if tag.nil? || tag =~ /\d/
    end
    out
  end

  def directory_listing
    out = []
    out.concat(unreadable(%w[nginx apache lighttpd]))
    out.concat(SdwParse.nginx_autoindex_on(nginx_tree).map { |f| "nginx: #{f}" }) if nginx_tree
    if apache_dirs && apache_module?('autoindex_module')
      out.concat(SdwParse.apache_indexes(apache_dirs).map { |f| "Apache: #{f}" })
    end
    if lighttpd_conf
      %w[server.dir-listing dir-listing.activate].each do |k|
        v = lighttpd_value(k)
        out << "lighttpd: #{k} = #{v}" if v.to_s.casecmp?('enable')
      end
    end
    out
  end

  def legacy_tls_config
    out = []
    out.concat(unreadable(%w[nginx apache haproxy]))
    out.concat(SdwParse.nginx_legacy_tls(nginx_tree, nginx_version, system_tls_min).map { |f| "nginx: #{f}" }) if nginx_tree
    out.concat(SdwParse.apache_legacy_tls(apache_dirs, system_tls_min).map { |f| "Apache: #{f}" }) if apache_dirs && apache_module?('ssl_module')
    out.concat(SdwParse.haproxy_legacy_tls(haproxy_sections, haproxy_version, system_tls_min).map { |f| "HAProxy: #{f}" }) if haproxy_sections
    out
  end

  # Lowest protocol the system OpenSSL configuration allows (nil: no floor).
  def system_tls_min
    SdwMemo.fetch(:system_tls_min) do
      dir = which('openssl') ? cmd_ok('openssl version -d 2>/dev/null').to_s[/"([^"]+)"/, 1] : nil
      files = [dir && "#{dir}/openssl.cnf", '/etc/ssl/openssl.cnf', '/etc/pki/tls/openssl.cnf', '/etc/crypto-policies/back-ends/opensslcnf.config']
      SdwParse.openssl_min_protocol(files.compact.uniq.filter_map { |f| read_file(f) }.join("\n"))
    end
  end

  # Servers configured to serve requests as root.
  def config_root_workers
    out = []
    out.concat(unreadable(%w[nginx apache haproxy lighttpd]))
    out << 'nginx: user root' if nginx_tree && SdwParse.nginx_user(nginx_tree) == 'root'
    if installed?('apache') && apache_run_user
      out << "Apache: User #{apache_run_user[:name]} (uid 0)" if apache_run_user[:id].zero?
    elsif installed?('apache')
      out << 'Apache: the run user could not be resolved (DUMP_RUN_CFG)'
    end
    if haproxy_sections
      g = haproxy_sections.select { |s| s[:kind] == 'global' }.flat_map { |s| s[:lines] }
      u = g.reverse.find { |w| %w[user uid].include?(w.first) }
      out << "HAProxy: #{u.join(' ')}" if u && %w[root 0].include?(u[1])
    end
    if lighttpd_conf
      u = lighttpd_value('server.username')
      out << "lighttpd: server.username #{u}" if u.to_s == 'root'
    end
    out
  end

  # Request-serving processes running as root now.
  def runtime_root_workers
    procs = inspec.sdw_procs
    out = []
    nginx_workers = procs.matching(/\Anginx: worker process/)
    out << "nginx: #{nginx_workers.size} worker process(es) as root" if nginx_workers.any? { |p| p[:uid].zero? }
    apache = procs.named('apache2', 'httpd')
    out << "Apache: every #{apache.first[:comm]} process runs as root" if apache.size > 1 && apache.all? { |p| p[:uid].zero? }
    hap = procs.named('haproxy')
    out << 'HAProxy: every haproxy process runs as root' if !hap.empty? && hap.all? { |p| p[:uid].zero? }
    %w[caddy lighttpd].each do |n|
      ps = procs.named(n)
      out << "#{n}: runs as root (pid #{ps.map { |p| p[:pid] }.join(', ')})" if ps.any? { |p| p[:uid].zero? }
    end
    tomcat_procs.each { |p| out << "Tomcat: java runs as root (pid #{p[:pid]})" if p[:uid].zero? }
    out
  end

  def trace_enabled
    return unreadable(%w[apache]) unless apache_dirs

    SdwParse.apache_trace_enabled(apache_dirs).map { |f| "Apache: #{f}" }
  end

  def open_stats
    return unreadable(%w[haproxy]) unless haproxy_sections

    SdwParse.haproxy_open_stats(haproxy_sections).map { |f| "HAProxy: #{f}" }
  end

  def admin_exposed
    return ["Caddy: the configuration could not be adapted (#{caddy_error})"] unless caddy_json

    a = SdwParse.caddy_admin_exposed(caddy_json)
    a ? ["Caddy: admin API listens on #{a}"] : []
  end

  def shutdown_port_open
    out = []
    tomcat_bases.each do |base|
      xml = read_file("#{base}/conf/server.xml")
      if xml.nil?
        out << "Tomcat #{base}: conf/server.xml unreadable"
        next
      end
      s = SdwParse.tomcat_shutdown(xml)
      out << "Tomcat #{base}: shutdown port #{s[:port]} with the default command SHUTDOWN" if SdwParse.tomcat_shutdown_open?(xml)
    end
    out
  end

  def manager_apps
    tomcat_bases.flat_map do |base|
      %w[manager host-manager].filter_map do |app|
        dir = "#{base}/webapps/#{app}"
        ctx = "#{base}/conf/Catalina/localhost/#{app}.xml"
        next unless inspec.file(dir).directory? || inspec.file(ctx).file?

        "Tomcat #{base}: #{app} application deployed"
      end
    end
  end

  def to_s
    label
  end

  # ── nginx ──────────────────────────────────────────────────────────────

  def nginx?
    !which('nginx').nil?
  end

  def nginx_tree
    return nil unless nginx?

    SdwMemo.fetch(:nginx_tree) do
      r = sh("#{which('nginx')} -T 2>&1")
      r.exit_status.zero? ? SdwParse.nginx_tree(r.stdout) : nil
    end
  end

  def nginx_version
    SdwMemo.fetch(:nginx_version) { sh("#{which('nginx')} -v 2>&1").stdout.to_s[%r{nginx/([\d.]+)}, 1] }
  end

  # ── Apache httpd ───────────────────────────────────────────────────────

  def apache?
    !apache_ctl.nil?
  end

  # apachectl, or an httpd binary that is Apache (BusyBox has an httpd too).
  def apache_ctl
    SdwMemo.fetch(:apache_ctl) do
      %w[apache2ctl apachectl httpd apache2].filter_map { |b| which(b) }.find { |b| sh("#{b} -v 2>&1").stdout.to_s.include?('Apache') }
    end
  end

  def apache_dirs
    return nil unless apache?

    SdwMemo.fetch(:apache_dirs) do
      inc = SdwParse.apache_includes(sh("#{apache_ctl} -t -D DUMP_INCLUDES 2>/dev/null").stdout)
      inc.empty? ? nil : SdwParse.apache_directives(SdwParse.apache_flatten(inc, ->(p) { read_file(p) }))
    end
  end

  def apache_run_user
    SdwMemo.fetch(:apache_run_user) { SdwParse.apache_run_user(sh("#{apache_ctl} -t -D DUMP_RUN_CFG 2>/dev/null").stdout) }
  end

  def apache_module?(mod)
    SdwMemo.fetch(:apache_modules) { sh("#{apache_ctl} -M 2>/dev/null").stdout.to_s }.include?(mod)
  end

  # ── HAProxy ────────────────────────────────────────────────────────────

  def haproxy?
    !which('haproxy').nil?
  end

  def haproxy_sections
    return nil unless haproxy?

    SdwMemo.fetch(:haproxy_sections) do
      files = haproxy_files
      text = files.map { |f| read_file(f) }.compact.join("\n")
      text.empty? ? nil : SdwParse.haproxy_sections(text)
    end
  end

  # The files the running haproxy was started with (-f), else the default.
  def haproxy_files
    args = inspec.sdw_procs.named('haproxy').first&.dig(:args) || []
    paths = args.each_cons(2).select { |a, _| a == '-f' }.map(&:last)
    paths = ['/etc/haproxy/haproxy.cfg'] if paths.empty?
    paths.flat_map { |p| inspec.file(p).directory? ? list_dir(p, '*.cfg') : [p] }
  end

  def haproxy_version
    SdwMemo.fetch(:haproxy_version) { sh("#{which('haproxy')} -v 2>&1").stdout.to_s[/version ([\d.]+)/i, 1] }
  end

  # ── Caddy ──────────────────────────────────────────────────────────────

  def caddy?
    !which('caddy').nil?
  end

  def caddy_json
    return nil unless caddy?

    SdwMemo.fetch(:caddy_json) do
      args = inspec.sdw_procs.named('caddy').first&.dig(:args) || []
      conf = args[args.index('--config') + 1] if args.index('--config')
      adapter = args[args.index('--adapter') + 1] if args.index('--adapter')
      conf ||= '/etc/caddy/Caddyfile'
      adapter ||= 'caddyfile' if conf.end_with?('Caddyfile')
      cmd = "#{which('caddy')} adapt --config #{Shellwords.escape(conf)}#{adapter ? " --adapter #{Shellwords.escape(adapter)}" : ''} 2>/dev/null"
      begin
        JSON.parse(sh(cmd).stdout)
      rescue StandardError
        nil
      end
    end
  end

  def caddy_error
    'caddy adapt failed'
  end

  # ── lighttpd ───────────────────────────────────────────────────────────

  def lighttpd?
    !which('lighttpd').nil?
  end

  def lighttpd_conf
    return nil unless lighttpd?

    SdwMemo.fetch(:lighttpd_conf) do
      args = inspec.sdw_procs.named('lighttpd').first&.dig(:args) || []
      conf = args[args.index('-f') + 1] if args.index('-f')
      conf ||= '/etc/lighttpd/lighttpd.conf'
      r = sh("#{which('lighttpd')} -p -f #{Shellwords.escape(conf)} 2>/dev/null")
      r.exit_status.zero? && !r.stdout.to_s.empty? ? r.stdout : nil
    end
  end

  # Last top-level assignment of key in the preprocessed configuration.
  def lighttpd_value(key)
    v = nil
    lighttpd_conf.to_s.each_line do |l|
      m = l.match(/\A\s*#{Regexp.escape(key)}\s*[+:]?=\s*(.+?)\s*\z/)
      v = m[1].delete_prefix('"').delete_suffix('"') if m
    end
    v
  end

  # ── Tomcat ─────────────────────────────────────────────────────────────

  def tomcat?
    !tomcat_bases.empty?
  end

  def tomcat_procs
    inspec.sdw_procs.matching(/org\.apache\.catalina\.startup\.Bootstrap/)
  end

  # catalina.base of every running Tomcat, else the packaged instances.
  def tomcat_bases
    SdwMemo.fetch(:tomcat_bases) do
      bases = tomcat_procs.filter_map { |p| p[:args].grep(/\A-Dcatalina\.base=/).first&.split('=', 2)&.last }
      bases = (list_dir('/var/lib', 'tomcat*') + list_dir('/usr/share', 'tomcat*')).select { |d| inspec.file("#{d}/conf/server.xml").file? } if bases.empty?
      bases.uniq
    end
  end

  private

  # Installed servers whose configuration could not be read.
  def unreadable(names)
    names.select { |n| installed?(n) }.filter_map do |n|
      ok = case n
           when 'nginx' then nginx_tree
           when 'apache' then apache_dirs
           when 'haproxy' then haproxy_sections
           when 'lighttpd' then lighttpd_conf
           else true
           end
      "#{n}: installed, but its effective configuration could not be read" unless ok
    end
  end
end
