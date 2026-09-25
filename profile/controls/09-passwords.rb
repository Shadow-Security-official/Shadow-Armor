# frozen_string_literal: true

# Pillar 9 - Appliquez une politique de sécurité des mots de passe utilisateurs locaux
# Checked where PAM enforces it (effective stacks, module arguments over
# config files), and on the hashes actually stored in /etc/shadow.

min_len = input('sdw_password_min_length', value: sdw_catalog.default('sdw_password_min_length')).to_i
min_classes = input('sdw_password_min_classes', value: sdw_catalog.default('sdw_password_min_classes')).to_i
history = input('sdw_password_history', value: sdw_catalog.default('sdw_password_history')).to_i
max_days = input('sdw_password_max_days', value: sdw_catalog.default('sdw_password_max_days')).to_i
min_days = input('sdw_password_min_days', value: sdw_catalog.default('sdw_password_min_days')).to_i
warn_days = input('sdw_password_warn_days', value: sdw_catalog.default('sdw_password_warn_days')).to_i
deny_max = input('sdw_lockout_deny_max', value: sdw_catalog.default('sdw_lockout_deny_max')).to_i
unlock_min = input('sdw_lockout_unlock_min', value: sdw_catalog.default('sdw_lockout_unlock_min')).to_i

pwq = sdw_pwquality
acc = sdw_accounts
login_defs = sdw_kv('/etc/login.defs')

# The PAM service that holds the shared auth/password stacks.
shared = %w[common-auth system-auth].find { |s| file("/etc/pam.d/#{s}").exist? }
shared_pw = %w[common-password system-auth].find { |s| file("/etc/pam.d/#{s}").exist? }
no_pam = 'no shared PAM configuration found (/etc/pam.d/common-* or system-auth)'

control 'SA-09.01' do
  sdw_catalog.apply(self, 'SA-09.01')
  only_if(no_pam) { !shared_pw.nil? }
  describe pwq do
    its('enabled') { should cmp true }
  end
end

control 'SA-09.02' do
  sdw_catalog.apply(self, 'SA-09.02')
  only_if(no_pam) { !shared_pw.nil? }
  describe pwq do
    its('minlen') { should cmp >= min_len }
  end
end

control 'SA-09.03' do
  sdw_catalog.apply(self, 'SA-09.03')
  only_if(no_pam) { !shared_pw.nil? }
  describe pwq do
    its('classes_required') { should cmp >= min_classes }
  end
end

control 'SA-09.04' do
  sdw_catalog.apply(self, 'SA-09.04')
  only_if(no_pam) { !shared_pw.nil? }
  describe pwq do
    its('maxrepeat') { should cmp >= 1 }
    its('maxrepeat') { should cmp <= 3 }
    its('maxsequence') { should cmp >= 1 }
    its('maxsequence') { should cmp <= 3 }
    its('dictcheck') { should_not cmp 0 }
  end
end

control 'SA-09.05' do
  sdw_catalog.apply(self, 'SA-09.05')
  only_if(no_pam) { !shared_pw.nil? }
  describe pwq do
    its('enforce_for_root') { should cmp true }
  end
end

control 'SA-09.06' do
  sdw_catalog.apply(self, 'SA-09.06')
  only_if(no_pam) { !shared_pw.nil? }
  stack = sdw_pam(shared_pw).stack('password')
  remember = if stack.include?('pam_pwhistory.so')
               a = stack.args('pam_pwhistory.so')
               (a['remember'] || sdw_kv('/etc/security/pwhistory.conf', sep: '=').value('remember') || 10).to_i
             else
               stack.args('pam_unix.so')['remember'].to_i
             end
  describe SdwValue.new("password history depth (#{stack.include?('pam_pwhistory.so') ? 'pam_pwhistory' : 'pam_unix remember'})", remember) do
    its('value') { should cmp >= history }
  end
end

control 'SA-09.07' do
  sdw_catalog.apply(self, 'SA-09.07')
  describe login_defs.setting('ENCRYPT_METHOD') do
    its('value') { should be_in %w[YESCRYPT SHA512] }
  end
  if shared_pw
    args = sdw_pam(shared_pw).stack('password').args('pam_unix.so')
    describe SdwFindings.new('weak hashing options on pam_unix.so in the password stack', %w[md5 bigcrypt blowfish].select { |o| args.key?(o) }) do
      its('items') { should be_empty }
    end
  end
end

control 'SA-09.08' do
  sdw_catalog.apply(self, 'SA-09.08')
  describe SdwFindings.new('accounts whose stored hash is not yescrypt/SHA-512/bcrypt/scrypt', acc.weak_hash_users) do
    its('items') { should be_empty }
  end
end

control 'SA-09.09' do
  sdw_catalog.apply(self, 'SA-09.09')
  only_if(no_pam) { !shared.nil? }
  stack = sdw_pam(shared).stack('auth')
  mod = %w[pam_faillock.so pam_tally2.so].find { |m| stack.include?(m) }
  describe SdwValue.new("lockout module in the #{shared} auth stack", mod) do
    its('value') { should_not be_nil }
  end
  if mod
    args = stack.entries.select { |e| e[:module] == mod }.map { |e| e[:args] }.flatten.to_h { |x| k, v = x.split('=', 2); [k, v] }
    conf = sdw_kv('/etc/security/faillock.conf', sep: '=')
    deny = (args['deny'] || conf.value('deny') || 3).to_i
    unlock = (args['unlock_time'] || conf.value('unlock_time') || 600).to_i
    describe SdwValue.new("#{mod} deny (effective: module arguments, then faillock.conf, then default)", deny) do
      its('value') { should be_between(1, deny_max) }
    end
    describe SdwValue.new("#{mod} unlock_time in seconds (0 = administrator unlock)", unlock) do
      its('value') { should satisfy("be 0 or >= #{unlock_min}") { |v| v.zero? || v >= unlock_min } }
    end
  end
end

control 'SA-09.10' do
  sdw_catalog.apply(self, 'SA-09.10')
  describe login_defs.setting('PASS_MAX_DAYS') do
    its('value') { should cmp <= max_days }
  end
  describe SdwFindings.new("interactive accounts (root excepted) whose maximum password age exceeds #{max_days} days", acc.password_max_days_violations(max_days)) do
    its('items') { should be_empty }
  end
end

control 'SA-09.11' do
  sdw_catalog.apply(self, 'SA-09.11')
  describe login_defs.setting('PASS_MIN_DAYS') do
    its('value') { should cmp >= min_days }
  end
  describe login_defs.setting('PASS_WARN_AGE') do
    its('value') { should cmp >= warn_days }
  end
  describe SdwFindings.new("interactive accounts with a minimum password age below #{min_days} day(s)", acc.password_min_days_violations(min_days)) do
    its('items') { should be_empty }
  end
end

control 'SA-09.12' do
  sdw_catalog.apply(self, 'SA-09.12')
  services = %w[login sshd su sudo passwd common-auth common-password system-auth password-auth].select { |s| file("/etc/pam.d/#{s}").exist? }
  only_if(no_pam) { !services.empty? }
  found = services.flat_map do |svc|
    sdw_pam(svc).entries.select { |e| e[:module] == 'pam_unix.so' && e[:args].include?('nullok') }.map { |e| "#{e[:file]} (#{e[:type]})" }
  end.uniq
  describe SdwFindings.new('pam_unix.so lines accepting empty passwords (nullok)', found) do
    its('items') { should be_empty }
  end
end
