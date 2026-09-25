# frozen_string_literal: true

# Pillar 8 - Contrôlez la configuration des utilisateurs et groupes locaux
# Local users & groups.

inactive_max = input('sdw_inactive_days_max', value: sdw_catalog.default('sdw_inactive_days_max')).to_i
umask_req = input('sdw_umask', value: sdw_catalog.default('sdw_umask')).to_s
tmout_max = input('sdw_shell_timeout_max', value: sdw_catalog.default('sdw_shell_timeout_max')).to_i

acc = sdw_accounts

findings = lambda do |label, items|
  describe SdwFindings.new(label, items) do
    its('items') { should be_empty }
  end
end

control 'SA-08.01' do
  sdw_catalog.apply(self, 'SA-08.01')
  describe SdwValue.new('accounts with UID 0 in /etc/passwd', acc.uid0_users) do
    its('value') { should eq ['root'] }
  end
end

control 'SA-08.02' do
  sdw_catalog.apply(self, 'SA-08.02')
  instance_exec('accounts with an empty password field in /etc/shadow', acc.empty_password_users, &findings)
end

control 'SA-08.03' do
  sdw_catalog.apply(self, 'SA-08.03')
  instance_exec("accounts whose /etc/passwd password field is not 'x'", acc.unshadowed_users, &findings)
end

control 'SA-08.04' do
  sdw_catalog.apply(self, 'SA-08.04')
  instance_exec("legacy '+' entries", acc.legacy_plus_entries, &findings)
end

control 'SA-08.05' do
  sdw_catalog.apply(self, 'SA-08.05')
  instance_exec("system accounts (UID < #{acc.uid_min}) with a login shell", acc.system_accounts_with_shell, &findings)
end

control 'SA-08.06' do
  sdw_catalog.apply(self, 'SA-08.06')
  instance_exec('duplicate UIDs, GIDs, user or group names', acc.duplicates, &findings)
end

control 'SA-08.07' do
  sdw_catalog.apply(self, 'SA-08.07')
  instance_exec('accounts whose primary GID has no group', acc.missing_primary_groups, &findings)
end

control 'SA-08.08' do
  sdw_catalog.apply(self, 'SA-08.08')
  instance_exec('members of the shadow group', acc.shadow_group_members, &findings)
end

control 'SA-08.09' do
  sdw_catalog.apply(self, 'SA-08.09')
  instance_exec('interactive home directory problems', acc.home_problems, &findings)
end

control 'SA-08.10' do
  sdw_catalog.apply(self, 'SA-08.10')
  instance_exec('unsafe dot files in interactive homes', acc.dotfile_problems, &findings)
end

control 'SA-08.11' do
  sdw_catalog.apply(self, 'SA-08.11')
  kv = sdw_kv('/etc/default/useradd', sep: '=')
  inactive = (kv.value('INACTIVE') || -1).to_i
  describe SdwValue.new("useradd default #{kv.setting('INACTIVE')} (-1 = never)", inactive) do
    its('value') { should be_between(0, inactive_max) }
  end
  instance_exec("interactive accounts (root excepted) without an inactivity limit <= #{inactive_max} days", acc.inactive_violations(inactive_max), &findings)
end

control 'SA-08.12' do
  sdw_catalog.apply(self, 'SA-08.12')
  req = umask_req.to_i(8)
  # A umask is compliant when it masks at least every bit the required one masks.
  weak = ->(v) { v.nil? || (v.to_s.to_i(8) & req) != req }
  describe sdw_kv('/etc/login.defs').setting('UMASK') do
    its('value') { should satisfy("mask at least #{umask_req}") { |v| !weak.call(v) } }
  end
  files = %w[/etc/profile /etc/bash.bashrc /etc/bashrc /etc/login.defs] + sdw_sh('ls -1 /etc/profile.d/*.sh 2>/dev/null').stdout.lines.map(&:strip)
  loose = files.flat_map do |f|
    next [] unless file(f).exist?

    file(f).content.to_s.lines.each_with_index.filter_map do |l, i|
      m = l.match(/^\s*umask\s+(\d{3,4})/)
      "#{f}:#{i + 1} umask #{m[1]}" if m && weak.call(m[1])
    end
  end
  instance_exec("shell profiles setting a umask looser than #{umask_req}", loose, &findings)
end

control 'SA-08.13' do
  sdw_catalog.apply(self, 'SA-08.13')
  files = %w[/etc/profile /etc/bash.bashrc /etc/bashrc] + sdw_sh('ls -1 /etc/profile.d/*.sh 2>/dev/null').stdout.lines.map(&:strip)
  text = files.select { |f| file(f).exist? }.map { |f| file(f).content.to_s }.join("\n")
  values = text.scan(/^\s*(?:export\s+|readonly\s+|declare\s+-[rx]+\s+|typeset\s+-[rx]+\s+)*TMOUT=(\d+)/).flatten.map(&:to_i)
  describe SdwValue.new("TMOUT set in system shell profiles (#{values.empty? ? 'not set' : values.join(', ')})", values.max || 0) do
    its('value') { should be_between(1, tmout_max) }
  end
  describe SdwValue.new('TMOUT is readonly in a system shell profile', text.match?(/^\s*(readonly\s+TMOUT|readonly\s+TMOUT=|declare\s+-[a-z]*r[a-z]*\s+TMOUT|typeset\s+-[a-z]*r[a-z]*\s+TMOUT)/)) do
    its('value') { should cmp true }
  end
end

control 'SA-08.14' do
  sdw_catalog.apply(self, 'SA-08.14')
  root = acc.users.find { |u| u[:name] == 'root' }
  describe SdwValue.new('primary GID of root', root && root[:gid]) do
    its('value') { should cmp 0 }
  end
end
