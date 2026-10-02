# frozen_string_literal: true

# Pillar 7 - Contrôlez l'escalade de privilèges
# Privilege escalation: sudo (effective policy across every included file),
# su, setuid binaries.

fs_scan = input('sdw_fs_scan', value: sdw_catalog.default('sdw_fs_scan'))
suid_allow = Array(input('sdw_suid_allowlist', value: sdw_catalog.default('sdw_suid_allowlist')))

sudo = sdw_sudoers
sudo_missing = 'sudo is not installed'

control 'SA-07.01' do
  sdw_catalog.apply(self, 'SA-07.01')
  only_if(sudo_missing) { sudo.installed? }
  describe SdwValue.new('sudoers Defaults use_pty (effective, all includes)', sudo.default('use_pty')) do
    its('value') { should cmp true }
  end
end

control 'SA-07.02' do
  sdw_catalog.apply(self, 'SA-07.02')
  only_if(sudo_missing) { sudo.installed? }
  describe SdwValue.new('sudoers Defaults logfile (effective, all includes)', sudo.default('logfile')) do
    its('value') { should_not be_nil }
    its('value') { should_not cmp false }
  end
end

control 'SA-07.03' do
  sdw_catalog.apply(self, 'SA-07.03')
  only_if(sudo_missing) { sudo.installed? }
  describe SdwFindings.new("sudoers entries that skip authentication (#{sudo.files.size} files parsed)", sudo.nopasswd_rules) do
    its('items') { should be_empty }
  end
end

control 'SA-07.04' do
  sdw_catalog.apply(self, 'SA-07.04')
  only_if(sudo_missing) { sudo.installed? }
  t = sudo.default('timestamp_timeout')
  minutes = t.nil? ? 5.0 : t.to_s.to_f
  describe SdwValue.new("sudoers timestamp_timeout (effective: #{t.nil? ? 'unset, sudo default 5' : t})", minutes) do
    its('value') { should be_between(0, 15) }
  end
end

control 'SA-07.05' do
  sdw_catalog.apply(self, 'SA-07.05')
  pam = sdw_pam('su')
  only_if('su has no PAM configuration') { pam.exists? }
  stack = pam.stack('auth')
  describe stack do
    its('modules') { should include 'pam_wheel.so' }
  end
  if stack.include?('pam_wheel.so')
    describe SdwValue.new('pam_wheel.so arguments in the su auth stack', stack.args('pam_wheel.so').keys) do
      its('value') { should include 'use_uid' }
    end
  end
end

control 'SA-07.06' do
  sdw_catalog.apply(self, 'SA-07.06')
  only_if(sudo_missing) { sudo.installed? }
  sudo.files.each do |f|
    describe sdw_perms(f, max: '0440', owner: 'root') do
      its('violations') { should be_empty }
    end
  end
end

control 'SA-07.07' do
  sdw_catalog.apply(self, 'SA-07.07')
  only_if(sudo_missing) { sudo.installed? }
  describe SdwFindings.new('sudo rules granting commands through negation', sudo.negated_command_rules) do
    its('items') { should be_empty }
  end
end

control 'SA-07.08' do
  sdw_catalog.apply(self, 'SA-07.08')
  only_if(sudo_missing) { sudo.installed? }
  describe SdwValue.new('sudoers env_reset (effective; unset means the sudo default: on)', sudo.default('env_reset')) do
    its('value') { should_not cmp false }
  end
  describe SdwValue.new('sudoers secure_path (effective)', sudo.default('secure_path')) do
    its('value') { should_not be_nil }
  end
end

control 'SA-07.09' do
  sdw_catalog.apply(self, 'SA-07.09')
  only_if('filesystem scan disabled (sdw_fs_scan: false)') { fs_scan }
  describe SdwFindings.new('setuid/setgid files outside sdw_suid_allowlist', sdw_fs_scan.setid_not_in(suid_allow)) do
    its('items') { should be_empty }
  end
end
