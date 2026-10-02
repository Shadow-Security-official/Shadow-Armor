# frozen_string_literal: true

# Pillar 6 - Renforcez la sécurité et la configuration des accès SSH
# Every check reads `sshd -T`: the configuration sshd resolves itself, after
# Include files, drop-ins (first value wins) and compiled-in defaults. The
# evidence names the file that set each value.

max_tries = input('sdw_ssh_max_auth_tries', value: sdw_catalog.default('sdw_ssh_max_auth_tries'))
grace_max = input('sdw_ssh_login_grace_time', value: sdw_catalog.default('sdw_ssh_login_grace_time'))
idle_max = input('sdw_ssh_idle_timeout_max', value: sdw_catalog.default('sdw_ssh_idle_timeout_max'))
sessions_max = input('sdw_ssh_max_sessions', value: sdw_catalog.default('sdw_ssh_max_sessions'))

sshd = sdw_sshd
sshd_missing = 'OpenSSH server (sshd) is not installed'

# Shorthand: one effective keyword must have one of the accepted values.
opt = lambda do |keyword, accepted|
  describe sshd.option(keyword) do
    its('value') { should be_in Array(accepted) }
  end
end

# sshd -T prints times in seconds; tolerate "1m" style just in case.
seconds = lambda do |v|
  s = v.to_s
  return s.to_i unless s =~ /[smhdw]/i

  s.scan(/(\d+)([smhdw]?)/i).sum { |n, u| n.to_i * { '' => 1, 's' => 1, 'm' => 60, 'h' => 3600, 'd' => 86_400, 'w' => 604_800 }[u.downcase] }
end

control 'SA-06.01' do
  sdw_catalog.apply(self, 'SA-06.01')
  only_if(sshd_missing) { sshd.installed? }
  # prohibit-password keeps key-based root logins: only passwords are refused.
  instance_exec('PermitRootLogin', %w[no prohibit-password forced-commands-only], &opt)
end

control 'SA-06.02' do
  sdw_catalog.apply(self, 'SA-06.02')
  only_if(sshd_missing) { sshd.installed? }
  methods = sshd.value('authenticationmethods').to_s
  lists = methods.split(/\s+/)
  publickey_everywhere = !methods.empty? && methods != 'any' && lists.all? { |l| l.split(',').map { |m| m.split(':').first }.include?('publickey') }
  if publickey_everywhere
    describe sshd.option('AuthenticationMethods') do
      its('value') { should match(/publickey/) }
    end
  else
    instance_exec('PasswordAuthentication', 'no', &opt)
    if sshd.value('kbdinteractiveauthentication') == 'yes'
      # keyboard-interactive is a password prompt unless PAM adds a second factor.
      describe SdwFindings.new('second-factor PAM modules in the sshd auth stack (keyboard-interactive is enabled)', sdw_mfa.second_factor_modules('sshd')) do
        its('items') { should_not be_empty }
      end
    end
  end
end

control 'SA-06.03' do
  sdw_catalog.apply(self, 'SA-06.03')
  only_if(sshd_missing) { sshd.installed? }
  instance_exec('PermitEmptyPasswords', 'no', &opt)
end

control 'SA-06.04' do
  sdw_catalog.apply(self, 'SA-06.04')
  only_if(sshd_missing) { sshd.installed? }
  describe sshd.option('MaxAuthTries') do
    its('value') { should cmp <= max_tries }
  end
end

control 'SA-06.05' do
  sdw_catalog.apply(self, 'SA-06.05')
  only_if(sshd_missing) { sshd.installed? }
  v = seconds.call(sshd.value('logingracetime'))
  describe SdwValue.new("#{sshd.option('LoginGraceTime')} in seconds", v) do
    its('value') { should be_between(1, grace_max.to_i) }
  end
end

control 'SA-06.06' do
  sdw_catalog.apply(self, 'SA-06.06')
  only_if(sshd_missing) { sshd.installed? }
  interval = seconds.call(sshd.value('clientaliveinterval'))
  count = sshd.value('clientalivecountmax').to_i
  describe sshd.option('ClientAliveInterval') do
    its('value') { should cmp > 0 }
  end
  describe SdwValue.new("seconds before sshd drops a client that stopped answering (ClientAliveInterval #{interval}s x ClientAliveCountMax #{count})", interval * [count, 1].max) do
    its('value') { should cmp <= idle_max.to_i }
  end
end

control 'SA-06.07' do
  sdw_catalog.apply(self, 'SA-06.07')
  only_if(sshd_missing) { sshd.installed? }
  instance_exec('X11Forwarding', 'no', &opt)
end

control 'SA-06.08' do
  sdw_catalog.apply(self, 'SA-06.08')
  only_if(sshd_missing) { sshd.installed? }
  if sshd.value('disableforwarding') == 'yes'
    instance_exec('DisableForwarding', 'yes', &opt)
  else
    instance_exec('AllowTcpForwarding', 'no', &opt)
  end
end

control 'SA-06.09' do
  sdw_catalog.apply(self, 'SA-06.09')
  only_if(sshd_missing) { sshd.installed? }
  instance_exec('HostbasedAuthentication', 'no', &opt)
  instance_exec('IgnoreRhosts', 'yes', &opt)
end

control 'SA-06.10' do
  sdw_catalog.apply(self, 'SA-06.10')
  only_if(sshd_missing) { sshd.installed? }
  instance_exec('PermitUserEnvironment', 'no', &opt)
end

control 'SA-06.11' do
  sdw_catalog.apply(self, 'SA-06.11')
  only_if(sshd_missing) { sshd.installed? }
  instance_exec('LogLevel', %w[INFO VERBOSE], &opt)
end

control 'SA-06.12' do
  sdw_catalog.apply(self, 'SA-06.12')
  only_if(sshd_missing) { sshd.installed? }
  set = %w[allowusers allowgroups denyusers denygroups].select { |k| !sshd.values(k).reject(&:empty?).empty? }
  describe SdwFindings.new('sshd -T access lists (AllowUsers, AllowGroups, DenyUsers, DenyGroups) that are set', set) do
    its('items') { should_not be_empty }
  end
end

control 'SA-06.13' do
  sdw_catalog.apply(self, 'SA-06.13')
  only_if(sshd_missing) { sshd.installed? }
  banner = sshd.value('banner').to_s
  describe sshd.option('Banner') do
    its('value') { should_not be_in ['none', ''] }
  end
  if banner.start_with?('/')
    describe file(banner) do
      it { should exist }
      its('content') { should_not match(/\\[mrsv]/) }
    end
  end
end

control 'SA-06.14' do
  sdw_catalog.apply(self, 'SA-06.14')
  only_if(sshd_missing) { sshd.installed? }
  instance_exec('UsePAM', 'yes', &opt)
end

control 'SA-06.15' do
  sdw_catalog.apply(self, 'SA-06.15')
  only_if(sshd_missing) { sshd.installed? }
  start, rate, full = sshd.value('maxstartups').to_s.split(':').map(&:to_i)
  describe SdwValue.new("#{sshd.option('MaxStartups')} = #{sshd.value('maxstartups')}", [start.to_i <= 10, rate.to_i >= 30 || rate.to_i.zero?, full.to_i <= 60].all?) do
    its('value') { should cmp true }
  end
  describe sshd.option('MaxSessions') do
    its('value') { should cmp <= sessions_max }
  end
end

control 'SA-06.16' do
  sdw_catalog.apply(self, 'SA-06.16')
  only_if(sshd_missing) { sshd.installed? }
  instance_exec('GSSAPIAuthentication', 'no', &opt)
end

control 'SA-06.17' do
  sdw_catalog.apply(self, 'SA-06.17')
  only_if(sshd_missing) { sshd.installed? }
  relaxed = {
    'permitrootlogin' => ->(v) { v.to_s.downcase == 'yes' },
    'passwordauthentication' => ->(v) { v.to_s.downcase == 'yes' },
    'permitemptypasswords' => ->(v) { v.to_s.downcase == 'yes' },
    'permituserenvironment' => ->(v) { v.to_s.downcase != 'no' },
    'hostbasedauthentication' => ->(v) { v.to_s.downcase == 'yes' },
    'authenticationmethods' => ->(v) { v.to_s.downcase == 'any' },
  }
  found = sshd.match_blocks.flat_map do |m|
    m[:settings].select { |k, v| relaxed.key?(k) && relaxed[k].call(v) }.map { |k, v| "#{m[:file]}:#{m[:line]} Match #{m[:condition]} -> #{k} #{v}" }
  end
  describe SdwFindings.new("Match blocks that relax a hardened keyword (#{sshd.match_blocks.size} Match blocks examined)", found) do
    its('items') { should be_empty }
  end
end

control 'SA-06.18' do
  sdw_catalog.apply(self, 'SA-06.18')
  only_if(sshd_missing) { sshd.installed? }
  %w[/etc/ssh/sshd_config /etc/ssh/sshd_config.d/*].each do |g|
    describe sdw_perms(g, max: '0600', owner: 'root') do
      its('violations') { should be_empty }
    end
  end
end

control 'SA-06.19' do
  sdw_catalog.apply(self, 'SA-06.19')
  only_if(sshd_missing) { sshd.installed? }
  describe sdw_perms('/etc/ssh/ssh_host_*_key', max: '0640', owner: 'root', groups: %w[root ssh_keys]) do
    its('violations') { should be_empty }
  end
end

control 'SA-06.20' do
  sdw_catalog.apply(self, 'SA-06.20')
  only_if(sshd_missing) { sshd.installed? }
  instance_exec('StrictModes', 'yes', &opt)
end

control 'SA-06.21' do
  sdw_catalog.apply(self, 'SA-06.21')
  only_if(sshd_missing) { sshd.installed? }
  instance_exec('PermitRootLogin', 'no', &opt)
  reopened = sshd.match_blocks.select { |m| m[:settings].key?('permitrootlogin') && m[:settings]['permitrootlogin'].downcase != 'no' }
  describe SdwFindings.new("Match blocks that let root log in again (#{sshd.match_blocks.size} Match blocks examined)",
                           reopened.map { |m| "#{m[:file]}:#{m[:line]} Match #{m[:condition]} -> permitrootlogin #{m[:settings]['permitrootlogin']}" }) do
    its('items') { should be_empty }
  end
end
