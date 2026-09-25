# frozen_string_literal: true

#
# Cookbook:: shadow_armor
# Recipe:: default
#
# Converges the remediation plan produced by `sdw-armor harden`. The plan is a
# list of declarative actions (node['shadow_armor']['actions']), each tagged
# with the control it fixes. This recipe is a small interpreter: every action
# kind maps to native Chef resources, so a why-run shows exactly what would
# change and every edited file is backed up under file_backup_path.
#
# Rules of the house:
#   * prefer drop-in files owned by Shadow-Armor over editing vendor files;
#   * validate before writing (sshd -t, visudo -c);
#   * never restart what is not running, never enable what does not exist.

h = ShadowArmor::Helpers

sa = node['shadow_armor']
family = node['platform_family']
rhel_like = %w[rhel fedora amazon].include?(family)
debian_like = family == 'debian'
systemd = h.systemd?
systemctl = !h.which('systemctl').nil?

applicable = lambda do |a|
  case a['platform']
  when nil, '', 'any' then true
  when 'debian' then debian_like
  when 'rhel' then rhel_like
  else a['platform'] == family
  end
end

actions = Array(sa['actions']).map(&:to_h).select { |a| applicable.call(a) }
by_kind = actions.group_by { |a| a['kind'] }
controls_of = ->(list) { list.map { |a| a['control'] }.compact.uniq }

log 'shadow-armor-plan' do
  message "Shadow-Armor run #{sa['run_id']}: #{actions.size} actions for #{controls_of.call(actions).size} controls on #{node['platform']} #{node['platform_version']}"
  level :info
end

# ---------------------------------------------------------------- packages
if (list = by_kind['packages_absent'])
  pkgs = list.flat_map { |a| Array(a['packages']) }.uniq.select { |p| h.package_installed?(p) }
  pkgs.each do |p|
    package "remove #{p}" do
      package_name p
      action :remove
    end
  end
end

if (list = by_kind['packages_present'])
  pkgs = list.flat_map { |a| a['packages'].is_a?(Hash) ? Array(a['packages'][debian_like ? 'debian' : 'rhel']) : Array(a['packages']) }.uniq
  # A package that cannot be installed (no repository access, unknown name)
  # must not block the rest of the plan: the re-audit reports what is missing.
  apt_update 'shadow-armor' do
    frequency 86_400
    action :periodic
    only_if { debian_like }
    ignore_failure true
  end
  pkgs.each do |p|
    package p do
      # Recommends can drag in a mail server (aide -> mailx -> exim4).
      options '--no-install-recommends' if debian_like
      ignore_failure true
    end
  end
end

# ---------------------------------------------------------------- groups & accounts
(by_kind['group_present'] || []).each do |a|
  group a['group'] do
    action :create
  end
end

(by_kind['group_members_empty'] || []).each do |a|
  group a['group'] do
    members []
    append false
    action :manage
    only_if { ::File.read('/etc/group').match?(/^#{Regexp.escape(a['group'])}:/) }
  end
end

if by_kind['lock_empty_passwords']
  h.shadow_entries.select { |_, s| s[:hash].empty? }.each_key do |user|
    execute "lock account #{user} (empty password)" do
      command ['passwd', '-l', user]
    end
  end
end

if by_kind['system_accounts_nologin']
  crontabs = h.crontab_users
  h.passwd_entries.select do |u|
    u[:uid] < h.uid_min && !%w[root sync shutdown halt].include?(u[:name]) && u[:shell] !~ h::NOLOGIN && !u[:shell].empty?
  end.each do |u|
    if crontabs.include?(u[:name]) || h.authorized_keys?(u[:home])
      log "#{u[:name]} keeps its shell #{u[:shell]}: it owns a crontab or an authorized_keys file, review it by hand" do
        level :warn
      end
      next
    end
    execute "set nologin shell for #{u[:name]}" do
      command ['usermod', '-s', h.nologin_shell, u[:name]]
    end
  end
end

if by_kind['expire_weak_hashes']
  h.shadow_entries.select { |_, s| h.weak_hash?(s[:hash]) }.each_key do |user|
    execute "expire weak password hash of #{user}" do
      command ['chage', '-d', '0', user]
    end
  end
end

(by_kind['account_inactive'] || []).each do |a|
  days = a['days'].to_i
  execute "useradd default INACTIVE=#{days}" do
    command ['useradd', '-D', '-f', days.to_s]
    not_if { ::File.read('/etc/default/useradd').match?(/^INACTIVE=#{days}$/) rescue false }
  end
  names = h.interactive_users.reject { |u| u[:uid].zero? }.map { |u| u[:name] }
  h.shadow_entries.each do |user, s|
    next unless names.include?(user) && h.usable_password?(s[:hash])
    next if !s[:inactive].to_s.empty? && s[:inactive].to_i.between?(0, days)

    max = s[:max].to_s.empty? || s[:max].to_i.negative? ? nil : s[:max].to_i
    if max && max < 99_999 && h.expires_at_once?(s, max, days)
      log "#{user}: its password expired more than #{days} days ago, an inactivity limit would disable it at once; left unchanged" do
        level :warn
      end
      next
    end
    execute "chage --inactive #{days} #{user}" do
      command ['chage', '--inactive', days.to_s, user]
    end
  end
end

(by_kind['password_aging'] || []).each do |a|
  defs = {}
  defs['PASS_MAX_DAYS'] = a['max_days'] if a['max_days']
  defs['PASS_MIN_DAYS'] = a['min_days'] if a['min_days']
  defs['PASS_WARN_AGE'] = a['warn_days'] if a['warn_days']
  by_kind['kv_file'] ||= []
  by_kind['kv_file'] << { 'control' => a['control'], 'kind' => 'kv_file', 'path' => '/etc/login.defs', 'separator' => ' ', 'settings' => defs }
  names = h.interactive_users.map { |u| u[:name] }
  h.shadow_entries.each do |user, s|
    next unless names.include?(user) && h.usable_password?(s[:hash])

    args = []
    want_max = a['max_days'] && user != 'root' && (s[:max].to_s.empty? || s[:max].to_i > a['max_days'].to_i || s[:max].to_i.negative?)
    if want_max && h.expires_at_once?(s, a['max_days'])
      log "#{user}: its password is older than #{a['max_days']} days, a maximum age would expire it at once; left unchanged (ask #{user} to change it, then run again)" do
        level :warn
      end
      want_max = false
    end
    args += ['--maxdays', a['max_days'].to_s] if want_max
    args += ['--mindays', a['min_days'].to_s] if a['min_days'] && s[:min].to_i < a['min_days'].to_i
    args += ['--warndays', a['warn_days'].to_s] if a['warn_days'] && s[:warn].to_i < a['warn_days'].to_i
    next if args.empty?

    execute "chage #{args.join(' ')} #{user}" do
      command ['chage', *args, user]
    end
  end
end

(by_kind['command'] || []).each do |a|
  cmds = a['commands'] || {}
  list = Array(cmds[debian_like ? 'debian' : 'rhel']) + Array(cmds['default'])
  list.each do |c|
    execute "#{a['control']}: #{c}" do
      command c
      ignore_failure true # the re-audit reports the control if this did not work
    end
  end
end

# ---------------------------------------------------------------- files
if (list = by_kind['cron_allow'])
  users = (['root'] + h.crontab_users).uniq
  { '/etc/cron.allow' => nil, '/etc/at.allow' => '/usr/bin/at' }.each do |path, needs|
    next if needs && !::File.exist?(needs)

    file path do
      content "#{users.join("\n")}\n"
      mode '0640'
      owner 'root'
      group 'root'
      action :create_if_missing
    end
  end
end

(by_kind['file_content'] || []).group_by { |a| a['path'] }.each do |path, list|
  a = list.last
  next if a['only_if_exists'] && !::File.exist?(a['only_if_exists'])

  directory ::File.dirname(path) do
    recursive true
    not_if { ::File.directory?(::File.dirname(path)) }
  end
  file path do
    content a['content']
    mode a['mode'] || '0644'
    owner a['owner'] || 'root'
    group a['group'] || 'root'
    action a['create_only'] ? :create_if_missing : :create
  end
end

(by_kind['line_in_file'] || []).group_by { |a| a['path'] }.each do |path, list|
  file path do
    content(lazy do
      list.reduce(h.read(path).to_s) do |txt, a|
        h.line_transform(txt, a['line'], match: a['match'], after: a['after'], first: a['first'])
      end
    end)
    only_if { ::File.exist?(path) }
  end
end

kv_restart = []
(by_kind['kv_file'] || []).group_by { |a| a['path'] }.each do |path, list|
  settings = list.each_with_object({}) { |a, acc| acc.merge!(a['settings'] || {}) }
  sep = list.first['separator'] || ' '
  create = list.any? { |a| a['create'] }
  section = list.first['section']
  kv_restart.concat(list.map { |a| a['notify'] }.compact)
  directory ::File.dirname(path) do
    recursive true
    only_if { create && !::File.directory?(::File.dirname(path)) }
  end
  file path do
    content(lazy do
      base = h.read(path) || (create ? h.header(controls_of.call(list)) : '')
      section ? h.ini_transform(base, section, settings) : h.kv_transform(base, settings, sep)
    end)
    mode lazy { ::File.exist?(path) ? format('%o', ::File.stat(path).mode & 0o7777) : '0644' }
    only_if { create || ::File.exist?(path) }
  end
end

if kv_restart.include?('auditd')
  execute 'reload auditd configuration' do
    command 'service auditd reload || systemctl kill -s HUP auditd'
    only_if { systemd && system('systemctl is-active --quiet auditd') }
    ignore_failure true
  end
end

(by_kind['systemd_dropin'] || []).group_by { |a| a['config'] }.each do |config, list|
  section = list.first['section']
  settings = list.each_with_object({}) { |a, acc| acc.merge!(a['settings'] || {}) }
  dir = "/etc/#{config}.d"
  directory dir do
    recursive true
  end
  dropin = "#{dir}/60-shadow-armor.conf"
  merged = h.merged_ini(dropin, settings)
  file dropin do
    content "#{h.header(controls_of.call(list) + h.managed_controls(dropin))}[#{section}]\n#{merged.map { |k, v| "#{k}=#{v}" }.join("\n")}\n"
    mode '0644'
  end
  restart = list.map { |a| a['restart'] }.compact.first
  next unless restart

  execute "restart #{restart}" do
    command ['systemctl', 'restart', restart]
    only_if { systemd && system("systemctl is-active --quiet #{restart}") }
    ignore_failure true
  end
end

# ---------------------------------------------------------------- kernel
if (list = by_kind['sysctl'])
  settings = list.each_with_object({}) { |a, acc| acc.merge!(a['settings'] || {}) }
  sysctl_file = '/etc/sysctl.d/99-zz-shadow-armor.conf'
  all_settings = h.merged_settings(sysctl_file, settings, sep: '=')
  file sysctl_file do
    content "#{h.header(controls_of.call(list) + h.managed_controls(sysctl_file))}#{all_settings.sort.map { |k, v| "#{k} = #{v}" }.join("\n")}\n"
    mode '0644'
  end
  file '/etc/sysctl.conf' do
    content(lazy { h.sysctl_conf_transform(h.read('/etc/sysctl.conf'), settings) })
    only_if { ::File.exist?('/etc/sysctl.conf') && !::File.symlink?('/etc/sysctl.conf') }
  end
  settings.sort.each do |k, v|
    execute "sysctl -w #{k}=#{v}" do
      command ['sysctl', '-q', '-w', "#{k}=#{v}"]
      not_if { ::File.read("/proc/sys/#{k.tr('.', '/')}").split.join(' ') == v.to_s rescue true }
      ignore_failure :quiet # read-only /proc/sys (containers) or missing key: the boot value still applies
    end
  end
end

if (list = by_kind['modprobe_disable'])
  mods = list.flat_map { |a| Array(a['modules']) }.uniq
  modfile = '/etc/modprobe.d/60-shadow-armor.conf'
  lines = h.merged_lines(modfile, mods.flat_map { |m| ["install #{m} /bin/false", "blacklist #{m}"] })
  file modfile do
    content "#{h.header(controls_of.call(list) + h.managed_controls(modfile))}#{lines.join("\n")}\n"
    mode '0644'
  end
  mods.each do |m|
    execute "unload #{m}" do
      command ['modprobe', '-r', m]
      only_if { ::File.read('/proc/modules').lines.any? { |l| l.split.first == m.tr('-', '_') } rescue false }
      ignore_failure :quiet
    end
  end
end

if (list = by_kind['grub_cmdline'])
  params = list.each_with_object({}) { |a, acc| acc.merge!(a['params'] || {}) }
  if h.which('grubby')
    args = params.map { |k, v| v.to_s.empty? ? k : "#{k}=#{v}" }.join(' ')
    execute "grubby --update-kernel=ALL --args=\"#{args}\"" do
      command ['grubby', '--update-kernel=ALL', "--args=#{args}"]
      not_if { a = `grubby --info=DEFAULT 2>/dev/null`[/^args="?([^"\n]*)/, 1].to_s.split; params.all? { |k, v| a.include?(v.to_s.empty? ? k : "#{k}=#{v}") } }
    end
  elsif ::File.exist?('/etc/default/grub')
    file '/etc/default/grub' do
      content(lazy { h.grub_default_transform(h.read('/etc/default/grub'), params) })
      notifies :run, 'execute[regenerate grub configuration]', :delayed
    end
    execute 'regenerate grub configuration' do
      command 'if command -v update-grub >/dev/null; then update-grub; elif command -v grub2-mkconfig >/dev/null; then grub2-mkconfig -o /boot/grub2/grub.cfg; else grub-mkconfig -o /boot/grub/grub.cfg; fi'
      action :nothing
      ignore_failure true
    end
  else
    log 'grub_cmdline: no grubby and no /etc/default/grub on this host; kernel parameters must be set manually' do
      level :warn
    end
  end
end

(by_kind['mount_options'] || []).each do |a|
  mp = a['mountpoint']
  add = a['add']
  unit = "#{mp.delete_prefix('/').tr('/', '-')}.mount"
  if h.fstab_has?(mp)
    file '/etc/fstab' do
      content(lazy { h.fstab_transform(h.read('/etc/fstab'), mp, add) })
    end
  elsif mp == '/dev/shm'
    file '/etc/fstab' do
      content(lazy { "#{h.read('/etc/fstab').to_s.chomp}\n# #{h::MARK} (#{a['control']})\ntmpfs\t/dev/shm\ttmpfs\tdefaults,#{add.join(',')}\t0\t0\n" })
    end
  elsif systemd && (h.unit_exists?(unit) || ::File.exist?("/usr/share/systemd/#{unit}"))
    execute "provide #{unit}" do
      command ['cp', "/usr/share/systemd/#{unit}", "/etc/systemd/system/#{unit}"]
      only_if { ::File.exist?("/usr/share/systemd/#{unit}") && !h.unit_exists?(unit) }
    end
    directory "/etc/systemd/system/#{unit}.d"
    file "/etc/systemd/system/#{unit}.d/60-shadow-armor.conf" do
      content "#{h.header([a['control']])}[Mount]\nOptions=mode=1777,strictatime,#{add.join(',')}\n"
      mode '0644'
      notifies :run, 'execute[systemctl daemon-reload]', :immediately
    end
    execute "enable #{unit}" do
      command ['systemctl', 'enable', unit]
      not_if { `systemctl is-enabled #{unit} 2>/dev/null`.strip =~ /enabled|static/ }
    end
    log "#{mp} becomes a separate tmpfs mount at the next reboot (#{unit})" do
      level :warn
      not_if { h.mounted?(mp) }
    end
  else
    log "#{mp} is not a separate mount on this host: create a partition or volume for it (manual)" do
      level :warn
    end
    next
  end
  execute "remount #{mp} with #{add.join(',')}" do
    command ['mount', '-o', "remount,#{add.join(',')}", mp]
    only_if { h.mounted?(mp) && !(add - h.current_mount_options(mp)).empty? }
    ignore_failure :quiet
  end
end

execute 'systemctl daemon-reload' do
  action :nothing
  only_if { systemd }
end

# ---------------------------------------------------------------- sshd
if (list = by_kind['sshd_config'])
  raw = list.each_with_object({}) { |a, acc| acc.merge!(a['settings'] || {}) }
  settings = {}
  raw.each do |k, v|
    if v.is_a?(Hash)
      algos = h.ssh_supported(v['supported'], Array(v['prefer']))
      if algos.empty?
        log("#{k}: none of the recommended algorithms is supported by this OpenSSH; left unchanged") { level :warn }
        next
      end
      settings[k] = algos.join(',')
    else
      settings[k] = v.to_s
    end
  end
  sshd_dropin = '/etc/ssh/sshd_config.d/00-shadow-armor.conf'
  if settings.key?('PermitRootLogin')
    earlier = h.merged_settings(sshd_dropin, {}, sep: ' ', casefold: true).find { |k, _| k.casecmp?('PermitRootLogin') }&.last
    asked = list.filter_map { |a| (a['settings'] || {})['PermitRootLogin'] }
    settings['PermitRootLogin'] = (asked + [earlier]).compact.reduce { |x, y| h.stricter_root_login(x, y) }
  end
  settings = h.merged_settings(sshd_dropin, settings, sep: ' ', casefold: true)
  body = "#{h.header(controls_of.call(list) + h.managed_controls(sshd_dropin))}#{settings.sort.map { |k, v| "#{k} #{v}" }.join("\n")}\n"
  major, minor = h.openssh_version
  dropin = major > 8 || (major == 8 && minor >= 2)
  privsep = lambda do
    out = `sshd -t 2>&1`
    dir = out[/Missing privilege separation directory: (\S+)/, 1]
    FileUtils.mkdir_p(dir, mode: 0o755) if dir
  end

  if dropin
    directory '/etc/ssh/sshd_config.d' do
      mode '0755'
    end
    file '/etc/ssh/sshd_config.d/00-shadow-armor.conf' do
      content body
      mode '0600'
      owner 'root'
      group 'root'
      # Validate the whole configuration with the new drop-in read first.
      verify do |path|
        privsep.call
        main = "Include #{path}\n#{h.read('/etc/ssh/sshd_config')}"
        tmp = ::File.join(::File.dirname(path), "sdw-armor-sshd-verify-#{Process.pid}")
        ::File.write(tmp, main)
        ok = system('sshd', '-t', '-f', tmp, out: ::File::NULL, err: $stderr)
        ::File.delete(tmp)
        ok
      end
      notifies :run, 'execute[reload sshd]', :delayed
    end
    # First value wins in sshd: our drop-in must be read before anything else.
    file '/etc/ssh/sshd_config' do
      content(lazy do
        text = h.read('/etc/ssh/sshd_config').to_s
        first = text.lines.map(&:strip).find { |l| !l.empty? && !l.start_with?('#') }.to_s
        if first =~ %r{\AInclude\s+/etc/ssh/sshd_config\.d/\*\.conf\z}i
          text
        else
          h.line_transform(text, 'Include /etc/ssh/sshd_config.d/00-shadow-armor.conf', first: true)
        end
      end)
      mode lazy { format('%o', ::File.stat('/etc/ssh/sshd_config').mode & 0o7777) }
      only_if { ::File.exist?('/etc/ssh/sshd_config') }
      notifies :run, 'execute[reload sshd]', :delayed
    end
  else
    file '/etc/ssh/sshd_config' do
      content(lazy do
        text = h.read('/etc/ssh/sshd_config').to_s.sub(/# BEGIN Shadow-Armor.*?# END Shadow-Armor\n/m, '')
        "# BEGIN Shadow-Armor managed block (OpenSSH < 8.2 has no Include): first value wins\n#{body}# END Shadow-Armor\n#{text}"
      end)
      verify 'sshd -t -f %{path}'
      notifies :run, 'execute[reload sshd]', :delayed
    end
  end
  execute 'reload sshd' do
    command 'systemctl reload ssh 2>/dev/null || systemctl reload sshd'
    action :nothing
    ignore_failure true
    only_if { systemd && (system('systemctl is-active --quiet ssh') || system('systemctl is-active --quiet sshd')) }
  end
end

# ---------------------------------------------------------------- sudo
if (list = by_kind['sudoers_defaults'])
  sudo_file = '/etc/sudoers.d/zz-shadow-armor'
  lines = h.merged_lines(sudo_file, list.flat_map { |a| Array(a['defaults']) }.map { |d| "Defaults #{d}" })
  file sudo_file do
    content "#{h.header(controls_of.call(list) + h.managed_controls(sudo_file))}#{lines.join("\n")}\n"
    mode '0440'
    owner 'root'
    group 'root'
    verify 'visudo -c -q -f %{path}'
    only_if { ::File.directory?('/etc/sudoers.d') }
  end
end

# ---------------------------------------------------------------- audit
if (list = by_kind['audit_rules'])
  x86 = node['kernel']['machine'] == 'x86_64'
  rules = list.flat_map { |a| Array(a['rules']) }.uniq.reject { |r| r.include?('arch=b32') && !x86 }
  directory '/etc/audit/rules.d' do
    recursive true
  end
  unless rules.empty?
    rules_file = '/etc/audit/rules.d/60-shadow-armor.rules'
    all_rules = h.merged_lines(rules_file, rules)
    file rules_file do
      content "#{h.header(controls_of.call(list) + h.managed_controls(rules_file))}#{all_rules.join("\n")}\n"
      mode '0640'
      notifies :run, 'execute[load audit rules]', :delayed
    end
  end
  if list.any? { |a| a['immutable'] }
    file '/etc/audit/rules.d/99-zz-shadow-armor-finalize.rules' do
      content "#{h.header(controls_of.call(list))}# Lock the audit configuration until reboot (must be the last rule).\n-e 2\n"
      mode '0640'
      notifies :run, 'execute[load audit rules]', :delayed
    end
  end
  execute 'load audit rules' do
    command 'augenrules --load'
    action :nothing
    only_if { !h.which('augenrules').nil? }
    ignore_failure :quiet # immutable (-e 2) configurations only reload at reboot
  end
end

# ---------------------------------------------------------------- PAM
(by_kind['pam_feature'] || []).each do |a|
  feature = a['feature']
  settings = a['settings'] || {}
  if rhel_like && h.which('authselect')
    authselect_feature = { 'faillock' => 'with-faillock', 'pwhistory' => 'with-pwhistory', 'without-nullok' => 'without-nullok' }[feature]
    if authselect_feature
      execute "authselect enable-feature #{authselect_feature}" do
        command ['authselect', 'enable-feature', authselect_feature]
        only_if { system('authselect current >/dev/null 2>&1') }
        not_if { `authselect current 2>/dev/null`.include?(authselect_feature) }
      end
    end
    package('libpwquality') { ignore_failure true } if feature == 'pwquality'
  elsif debian_like
    case feature
    when 'pwquality'
      package('libpam-pwquality') { ignore_failure true }
    when 'faillock'
      file '/usr/share/pam-configs/sdw-faillock' do
        content <<~PAM
          Name: Shadow-Armor account lockout (pam_faillock)
          Default: yes
          Priority: 0
          Auth-Type: Primary
          Auth:
          	[default=die] pam_faillock.so authfail
        PAM
        mode '0644'
      end
      file '/usr/share/pam-configs/sdw-faillock-notify' do
        content <<~PAM
          Name: Shadow-Armor failed login accounting (pam_faillock preauth)
          Default: yes
          Priority: 1024
          Auth-Type: Primary
          Auth:
          	requisite pam_faillock.so preauth
          Account-Type: Primary
          Account:
          	required pam_faillock.so
        PAM
        mode '0644'
      end
      execute 'pam-auth-update --enable sdw-faillock sdw-faillock-notify' do
        command %w[pam-auth-update --package --enable sdw-faillock sdw-faillock-notify]
        not_if { ::File.read('/etc/pam.d/common-auth').include?('pam_faillock.so') rescue false }
      end
    when 'pwhistory'
      remember = settings['remember'] || 5
      file '/usr/share/pam-configs/sdw-pwhistory' do
        content <<~PAM
          Name: Shadow-Armor password history (pam_pwhistory)
          Default: yes
          Priority: 1000
          Password-Type: Primary
          Password:
          	requisite pam_pwhistory.so remember=#{remember} enforce_for_root try_first_pass use_authtok
        PAM
        mode '0644'
      end
      execute 'pam-auth-update --enable sdw-pwhistory' do
        command %w[pam-auth-update --package --enable sdw-pwhistory]
        not_if { ::File.read('/etc/pam.d/common-password').include?("pam_pwhistory.so remember=#{remember}") rescue false }
      end
    when 'without-nullok'
      log 'pam_unix nullok: remove it from /usr/share/pam-configs/unix (and run pam-auth-update) manually on Debian/Ubuntu' do
        level :warn
      end
    end
  else
    log "PAM feature #{feature}: no authselect/pam-auth-update on this platform, configure it manually" do
      level :warn
    end
  end
  next unless feature == 'pwhistory' && settings['remember']

  file '/etc/security/pwhistory.conf' do
    content(lazy { h.kv_transform(h.read('/etc/security/pwhistory.conf'), { 'remember' => settings['remember'] }, ' = ') })
    only_if { ::File.exist?('/etc/security/pwhistory.conf') }
  end
end

# ---------------------------------------------------------------- permissions
(by_kind['file_mode'] || []).each do |a|
  max = a['max'].to_i(8)
  Array(a['paths']).flat_map { |g| g.include?('*') ? Dir.glob(g) : [g] }.uniq.each do |fpath|
    next unless ::File.exist?(fpath) && !::File.symlink?(fpath)

    newmode = ::File.stat(fpath).mode & 0o7777 & max
    res = ::File.directory?(fpath) ? :directory : :file
    send(res, "#{a['control']} #{fpath}") do
      path fpath
      mode format('%04o', newmode)
      owner a['owner'] if a['owner']
      group a['group'] if a['group']
    end
  end
end

if by_kind['home_permissions']
  h.interactive_users.reject { |u| u[:uid].zero? }.each do |u|
    next unless ::File.directory?(u[:home]) && u[:home] != '/'

    mode = ::File.stat(u[:home]).mode & 0o7777 & ~0o027
    directory "home of #{u[:name]}" do
      path u[:home]
      mode format('%04o', mode)
      owner u[:name]
    end
  end
end

if by_kind['dotfile_permissions']
  h.interactive_users.each do |u|
    next unless ::File.directory?(u[:home]) && u[:home] != '/'

    Dir.glob(::File.join(u[:home], '.*')).each do |f|
      next unless ::File.file?(f) && !::File.symlink?(f)

      if %w[.rhosts .shosts].include?(::File.basename(f))
        file(f) { action :delete }
        next
      end
      m = ::File.stat(f).mode & 0o7777
      next if (m & 0o022).zero?

      file f do
        mode format('%04o', m & ~0o022)
      end
    end
  end
end

if by_kind['user_secret_permissions']
  secrets = %w[.pgpass .my.cnf .netrc .git-credentials .aws/credentials .kube/config .docker/config.json .vault-token]
  h.interactive_users.each do |u|
    home = u[:home]
    next unless ::File.directory?(home) && home != '/'

    ssh = ::File.join(home, '.ssh')
    if ::File.directory?(ssh) && (::File.stat(ssh).mode & 0o077) != 0
      directory ssh do
        mode '0700'
      end
    end
    Dir.glob(::File.join(ssh, '*')).each do |f|
      next unless ::File.file?(f) && !::File.symlink?(f)

      b = ::File.basename(f)
      next if b.end_with?('.pub') || b.start_with?('known_hosts')

      m = ::File.stat(f).mode & 0o7777
      want = %w[authorized_keys authorized_keys2 config].include?(b) ? m & ~0o022 : m & ~0o077
      next if want == m

      file(f) { mode format('%04o', want) }
    end
    secrets.map { |s| ::File.join(home, s) }.each do |f|
      next unless ::File.file?(f) && !::File.symlink?(f)

      m = ::File.stat(f).mode & 0o7777
      next if (m & 0o077).zero?

      file(f) { mode format('%04o', m & ~0o077) }
    end
  end
end

if by_kind['private_key_permissions']
  %w[/etc/ssl/private /etc/pki/tls/private /etc/letsencrypt/archive /etc/letsencrypt/keys].each do |d|
    next unless ::File.directory?(d)

    m = ::File.stat(d).mode & 0o7777
    next if (m & 0o007).zero?

    directory(d) { mode format('%04o', m & ~0o007) }
  end
  `find /etc -xdev -type f \\( -name '*.key' -o -name '*.pem' \\) -perm -004 -exec grep -l 'PRIVATE KEY' {} + 2>/dev/null`.lines.map(&:chomp).each do |f|
    file(f) { mode format('%04o', ::File.stat(f).mode & 0o7777 & ~0o007) }
  end
end

if by_kind['mfa_secret_permissions']
  targets = []
  targets << ['/etc/users.oath', 'root'] if ::File.exist?('/etc/users.oath')
  h.interactive_users.each do |u|
    %w[.google_authenticator .config/Yubico/u2f_keys].each do |rel|
      f = ::File.join(u[:home], rel)
      targets << [f, u[:name]] if ::File.file?(f)
    end
  end
  targets.each do |f, owner_name|
    file f do
      mode format('%04o', ::File.stat(f).mode & 0o700)
      owner owner_name
    end
  end
end

if by_kind['strip_world_writable']
  paths = h.find_paths('-type f -perm -0002')
  ruby_block "remove o+w from #{paths.size} world-writable files" do
    block { paths.each { |p| ::File.chmod(::File.stat(p).mode & 0o7775, p) if ::File.exist?(p) } }
    not_if { paths.empty? }
  end
end

if by_kind['sticky_world_writable_dirs']
  paths = h.find_paths('-type d -perm -0002 ! -perm -1000')
  ruby_block "add the sticky bit to #{paths.size} world-writable directories" do
    block { paths.each { |p| ::File.chmod((::File.stat(p).mode & 0o7777) | 0o1000, p) if ::File.directory?(p) } }
    not_if { paths.empty? }
  end
end

# ---------------------------------------------------------------- services
if !systemctl && (by_kind['services_disabled'] || by_kind['services_enabled'])
  log 'no systemctl on this host: service enablement is left unchanged (non-systemd init)' do
    level :warn
  end
  by_kind.delete('services_disabled')
  by_kind.delete('services_enabled')
end
(by_kind['services_disabled'] || []).flat_map { |a| Array(a['units']) }.uniq.each do |unit|
  next unless h.unit_exists?(unit)

  execute "stop #{unit}" do
    command ['systemctl', 'stop', unit]
    only_if { systemd && system("systemctl is-active --quiet #{unit}") }
  end
  execute "mask #{unit}" do
    command "systemctl disable #{unit} >/dev/null 2>&1; systemctl mask #{unit}"
    not_if { `systemctl is-enabled #{unit} 2>/dev/null`.strip.start_with?('masked') }
  end
end

(by_kind['services_enabled'] || []).each do |a|
  unit = Array(a['units']).find { |u| h.unit_exists?(u) }
  unless unit
    log "#{a['control']}: none of #{Array(a['units']).join(', ')} is installed" do
      level :warn
    end
    next
  end
  execute "unmask #{unit}" do
    command ['systemctl', 'unmask', unit]
    only_if { `systemctl is-enabled #{unit} 2>/dev/null`.strip.start_with?('masked') }
  end
  execute "enable #{unit}" do
    command ['systemctl', 'enable', unit]
    not_if { `systemctl is-enabled #{unit} 2>/dev/null`.strip =~ /\A(enabled|static|alias)/ }
  end
  execute "start #{unit}" do
    command ['systemctl', 'start', unit]
    only_if { systemd }
    not_if { system("systemctl is-active --quiet #{unit}") }
    ignore_failure true # enabled for the next boot anyway; the re-audit reports it as pending
  end
end

# ---------------------------------------------------------------- firewall
(by_kind['firewall'] || []).each do |a|
  # Default deny for what nothing serves now; everything listening now, the
  # sshd ports and the allowed list stay open, so no working service is cut.
  ssh_ports = `sshd -T 2>/dev/null`.lines.grep(/^port /).map { |l| "#{l.split.last.to_i}/tcp" }
  rules = (Array(a['allow_tcp']).map { |p| "#{p.to_i}/tcp" } + ssh_ports + ['22/tcp'] + h.listening_ports)
          .select { |r| r =~ %r{\A[1-9]\d*/(tcp|udp)\z} }.uniq.sort_by(&:to_i)
  log "firewall: ports kept open: #{rules.join(', ')}" do
    level :warn
  end
  if debian_like
    package('ufw') do
      options '--no-install-recommends'
      ignore_failure true
    end
    rules.each do |r|
      execute "ufw allow #{r}" do
        command ['ufw', 'allow', r]
        not_if { `ufw show added 2>/dev/null`.include?("ufw allow #{r}") }
      end
    end
    execute 'ufw default deny incoming' do
      command %w[ufw default deny incoming]
    end
    execute 'ufw default allow outgoing' do
      command %w[ufw default allow outgoing]
    end
    execute 'ufw enable' do
      command %w[ufw --force enable]
      not_if { `ufw status 2>/dev/null`.include?('Status: active') }
      ignore_failure true # e.g. no netfilter access; the re-audit tells
    end
  elsif rhel_like
    package('firewalld') { ignore_failure true }
    execute 'enable firewalld' do
      command %w[systemctl enable --now firewalld]
      not_if { system('systemctl is-active --quiet firewalld') }
      ignore_failure true
    end
    rules.each do |r|
      execute "firewall-cmd --permanent --add-port=#{r}" do
        command ['firewall-cmd', '--permanent', "--add-port=#{r}"]
        not_if { `firewall-cmd --list-ports 2>/dev/null`.split.include?(r) || (r == '22/tcp' && `firewall-cmd --list-services 2>/dev/null`.split.include?('ssh')) }
      end
    end
    execute 'firewall-cmd --reload' do
      command %w[firewall-cmd --reload]
      ignore_failure true
    end
  else
    log('firewall: unsupported platform, configure a default-deny inbound policy manually') { level :warn }
  end
end

# ---------------------------------------------------------------- integrity & updates
if by_kind['aide_init']
  execute 'initialise the AIDE database' do
    command(debian_like ? 'aideinit -y -f' : 'aide --init && mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz')
    timeout 3600
    not_if { %w[/var/lib/aide/aide.db /var/lib/aide/aide.db.gz].any? { |f| ::File.exist?(f) } }
    only_if { !h.which('aide').nil? }
    ignore_failure true
  end
end

if by_kind['automatic_updates']
  if debian_like
    package('unattended-upgrades') { ignore_failure true }
    file '/etc/apt/apt.conf.d/20auto-upgrades' do
      content "// #{h::MARK} (SA-10.03)\nAPT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"
      mode '0644'
    end
  elsif rhel_like
    package('dnf-automatic') { ignore_failure true }
    file '/etc/dnf/automatic.conf' do
      content(lazy { h.ini_transform(h.read('/etc/dnf/automatic.conf'), 'commands', { 'upgrade_type' => 'security', 'apply_updates' => 'yes' }) })
      only_if { ::File.exist?('/etc/dnf/automatic.conf') }
    end
    execute 'enable dnf-automatic.timer' do
      command %w[systemctl enable --now dnf-automatic.timer]
      not_if { `systemctl is-enabled dnf-automatic.timer 2>/dev/null`.strip == 'enabled' }
    end
  end
end

if by_kind['security_updates']
  execute 'apply pending security updates' do
    command(if debian_like
              'apt-get update -q && if command -v unattended-upgrade >/dev/null; then unattended-upgrade -v; else apt-get -s dist-upgrade | awk \'/^Inst .*security/ {print $2}\' | xargs -r apt-get install -y --only-upgrade; fi'
            else
              'dnf -y upgrade --security'
            end)
    environment('DEBIAN_FRONTEND' => 'noninteractive')
    timeout 7200
    ignore_failure true
  end
end

# ---------------------------------------------------------------- journal
journal = sa['journal_dir'] || '/var/lib/shadow-armor'
directory "#{journal}/journal" do
  recursive true
  mode '0700'
end
file "#{journal}/journal/#{sa['run_id'] || 'run'}.json" do
  content(lazy { JSON.pretty_generate('run_id' => sa['run_id'], 'finished_at' => Time.now.utc.iso8601, 'controls' => controls_of.call(actions), 'actions' => actions) })
  mode '0600'
  sensitive true # keep the plan out of the Chef diff output
end
