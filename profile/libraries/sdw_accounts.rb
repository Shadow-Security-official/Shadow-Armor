# frozen_string_literal: true

# Local accounts (/etc/passwd, /etc/shadow, /etc/group, login.defs), with
# evidence-friendly queries: each returns the offending entries, so a failure
# names exactly who or what is wrong.
class ::SdwAccounts < Inspec.resource(1)
  name 'sdw_accounts'
  desc 'Local users and groups with security-relevant queries.'
  example "describe sdw_accounts do\n  its('uid0_users') { should eq ['root'] }\nend"

  include SdwHelpers

  NOLOGIN = %r{(/nologin|/false|/sync|/shutdown|/halt)\z}
  STRONG_HASH = /\A\$(6|y|gy|7|2b|2y|2a)\$/

  def users
    SdwMemo.fetch(:passwd) do
      (read_file('/etc/passwd') || '').lines.filter_map do |l|
        next if l.strip.empty? || l.start_with?('#')

        f = l.chomp.split(':', -1)
        { name: f[0], pw: f[1], uid: f[2].to_i, gid: f[3].to_i, home: f[5], shell: f[6].to_s }
      end
    end
  end

  def shadow
    SdwMemo.fetch(:shadow) do
      text = read_file('/etc/shadow')
      raise ::Inspec::Exceptions::ResourceFailed, 'cannot read /etc/shadow (run as root or with --sudo)' if text.nil?

      text.lines.to_h do |l|
        f = l.chomp.split(':', -1)
        [f[0], { hash: f[1].to_s, last: f[2], min: f[3], max: f[4], warn: f[5], inactive: f[6], expire: f[7] }]
      end
    end
  end

  def groups
    SdwMemo.fetch(:group) do
      (read_file('/etc/group') || '').lines.filter_map do |l|
        next if l.strip.empty? || l.start_with?('#')

        f = l.chomp.split(':', -1)
        { name: f[0], gid: f[2].to_i, members: f[3].to_s.split(',').reject(&:empty?) }
      end
    end
  end

  def login_defs
    @login_defs ||= inspec.sdw_kv('/etc/login.defs')
  end

  def uid_min
    (login_defs.value('UID_MIN') || 1000).to_i
  end

  def uid0_users
    users.select { |u| u[:uid].zero? }.map { |u| u[:name] }
  end

  def empty_password_users
    shadow.select { |_, s| s[:hash].empty? }.keys
  end

  def unshadowed_users
    users.reject { |u| u[:pw] == 'x' }.map { |u| u[:name] }
  end

  def legacy_plus_entries
    %w[/etc/passwd /etc/shadow /etc/group].flat_map do |f|
      (read_file(f) || '').lines.select { |l| l.start_with?('+') }.map { |l| "#{f}: #{l.split(':').first}" }
    end
  end

  # System accounts (uid < UID_MIN) that still have a login shell.
  def system_accounts_with_shell
    users.select do |u|
      u[:uid] < uid_min && !%w[root sync shutdown halt].include?(u[:name]) && u[:shell] !~ NOLOGIN && !u[:shell].empty?
    end.map { |u| "#{u[:name]} (#{u[:shell]})" }
  end

  def interactive_users
    users.select { |u| (u[:uid] >= uid_min || u[:uid].zero?) && u[:shell] !~ NOLOGIN && !u[:shell].empty? && u[:name] != 'nobody' }
  end

  def duplicates
    d = []
    users.group_by { |u| u[:uid] }.each { |k, v| d << "uid #{k}: #{v.map { |u| u[:name] }.join(',')}" if v.size > 1 }
    users.group_by { |u| u[:name] }.each { |k, v| d << "user name #{k} x#{v.size}" if v.size > 1 }
    groups.group_by { |g| g[:gid] }.each { |k, v| d << "gid #{k}: #{v.map { |g| g[:name] }.join(',')}" if v.size > 1 }
    groups.group_by { |g| g[:name] }.each { |k, v| d << "group name #{k} x#{v.size}" if v.size > 1 }
    d
  end

  def missing_primary_groups
    gids = groups.map { |g| g[:gid] }
    users.reject { |u| gids.include?(u[:gid]) }.map { |u| "#{u[:name]} (gid #{u[:gid]})" }
  end

  def shadow_group_members
    g = groups.find { |x| x[:name] == 'shadow' }
    return [] unless g

    members = g[:members].dup
    users.each { |u| members << "#{u[:name]} (primary)" if u[:gid] == g[:gid] }
    members
  end

  # Password hashes that are not yescrypt/SHA-512/bcrypt/scrypt.
  def weak_hash_users
    shadow.select do |_, s|
      h = s[:hash].delete_prefix('!').delete_prefix('!')
      next false if h.empty? || h.start_with?('*', '!') || h == 'x'

      h !~ STRONG_HASH
    end.map { |n, s| "#{n} (#{hash_kind(s[:hash])})" }
  end

  def hash_kind(h)
    h = h.delete_prefix('!')
    case h
    when /\A\$1\$/ then 'MD5-crypt'
    when /\A\$5\$/ then 'SHA-256-crypt'
    when /\A\$(3|md5|sha1)\$?/ then 'legacy'
    when /\A[.\/0-9A-Za-z]{13}\z/ then 'DES-crypt'
    else 'unknown scheme'
    end
  end

  # Interactive users with a usable password whose shadow field violates a limit.
  def users_with_password
    names = interactive_users.map { |u| u[:name] }
    shadow.select { |n, s| names.include?(n) && usable?(s[:hash]) }
  end

  def usable?(hash)
    !(hash.empty? || hash.start_with?('!', '*'))
  end

  # Root is exempt from expiry and inactivity: an expired or disabled root
  # account also refuses key-based logins, which is how hosts get locked out.
  def password_max_days_violations(limit)
    users_with_password.reject { |n, _| n == 'root' }.select { |_, s| s[:max].to_s.empty? || s[:max].to_i > limit || s[:max].to_i.negative? }.map { |n, s| "#{n} (max #{s[:max].to_s.empty? ? 'unset' : s[:max]})" }
  end

  def password_min_days_violations(limit)
    users_with_password.select { |_, s| s[:min].to_i < limit }.map { |n, s| "#{n} (min #{s[:min].to_s.empty? ? 'unset' : s[:min]})" }
  end

  def inactive_violations(limit)
    users_with_password.reject { |n, _| n == 'root' }.select { |_, s| s[:inactive].to_s.empty? || s[:inactive].to_i > limit || s[:inactive].to_i.negative? }.map { |n, s| "#{n} (inactive #{s[:inactive].to_s.empty? ? 'unset' : s[:inactive]})" }
  end

  # Home directories of interactive users that are missing, not owned by the
  # user, or accessible by group-write/other.
  def home_problems
    SdwMemo.fetch(:home_problems) do
      probs = []
      interactive_users.reject { |u| u[:uid].zero? }.each do |u|
        f = inspec.file(u[:home])
        unless f.exist? && f.directory?
          probs << "#{u[:name]}: home #{u[:home]} missing"
          next
        end
        probs << "#{u[:name]}: #{u[:home]} owned by #{f.owner}" if f.owner != u[:name]
        probs << "#{u[:name]}: #{u[:home]} mode #{format('%04o', f.mode)}" if (f.mode & 0o027) != 0
      end
      probs
    end
  end

  # Dot files writable by group/other, and risky trust files.
  def dotfile_problems
    SdwMemo.fetch(:dotfile_problems) do
      probs = []
      interactive_users.each do |u|
        next unless u[:home].to_s.start_with?('/') && u[:home] != '/'

        out = cmd_ok("find #{Shellwords.escape(u[:home])} -maxdepth 1 -name '.*' \\( -type f -o -type l \\) -printf '%m\\t%u\\t%f\\n' 2>/dev/null")
        out.to_s.each_line do |l|
          mode, owner, fname = l.chomp.split("\t")
          m = mode.to_i(8)
          probs << "#{u[:home]}/#{fname}: group/world-writable (#{mode})" if (m & 0o022) != 0
          probs << "#{u[:home]}/#{fname}: trust file present" if %w[.rhosts .shosts .equiv].include?(fname)
          probs << "#{u[:home]}/#{fname}: readable by others (#{mode})" if %w[.netrc .pgpass .my.cnf].include?(fname) && (m & 0o077) != 0
          probs << "#{u[:home]}/#{fname}: owned by #{owner}" if owner != u[:name] && !%w[.bash_history].include?(fname) && u[:uid] != 0
        end
      end
      probs
    end
  end

  def to_s
    'local accounts'
  end
end
